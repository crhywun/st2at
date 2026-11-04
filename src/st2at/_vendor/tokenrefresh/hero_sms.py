"""HeroSMS 手机 SMS（SMS-Activate 兼容协议）。

文档: https://hero-sms.com/cn/api
迁移说明: 将 SMS-Activate host 换成 https://hero-sms.com 即可。

Base（实测）:
  https://hero-sms.com/stubs/handler_api.php?api_key=KEY&action=...

查询:
  getBalance / getCountries / getServicesList / getPrices / getTopCountriesByService

租号/收码:
  getNumber / getNumberV2 / getStatus / setStatus

与 GetatextProvider 对齐接口: rent / poll / complete / cancel
（session 参数忽略，始终直连，不走 ChatGPT 代理）
"""
from __future__ import annotations

import json
import os
import random
import re
import threading
import time
from typing import Any, Callable

import requests

DEFAULT_API_BASE = "https://hero-sms.com/stubs/handler_api.php"
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))

# setStatus（SMS-Activate 兼容）
STATUS_READY = "1"  # 告知已发送短信 / 等待码
STATUS_RETRY = "3"  # 请求重发
STATUS_DONE = "6"  # 成功完成
STATUS_CANCEL = "8"  # 取消

# OpenAI / ChatGPT 服务码（与 sms-activate / smsbower 同族）
DEFAULT_SERVICE = "dr"
# 默认国家：英国 16（可改；也可用 HERO_SMS_COUNTRIES 多国随机）
DEFAULT_COUNTRY = "16"
DEFAULT_COUNTRY_FALLBACK = "12,0,43,78,117"  # us, ru, de, fr, pt — 可按库存调整
DEFAULT_MAX_PRICE = 0.5


def _direct_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.trust_env = False
    s.proxies = {"http": None, "https": None}
    return s


def _strip_env_quotes(s: str) -> str:
    try:
        from .sms_common import clean_api_key

        return clean_api_key(s)
    except Exception:
        v = (s or "").strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1].strip()
        if len(v) >= 2 and v[0] in ("'", '"') and v[-1] not in ("'", '"'):
            v = v[1:].strip()
        if len(v) >= 2 and v[-1] in ("'", '"') and v[0] not in ("'", '"'):
            v = v[:-1].strip()
        return v


def _env(name: str, default: str = "") -> str:
    return _strip_env_quotes(os.environ.get(name) or default)


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _normalize_phone(number: str, country: str | int = "") -> str:
    """E.164 when possible; fallback +digits."""
    raw = str(number or "").strip()
    if not raw:
        return ""
    try:
        from .sms_e164 import normalize_e164

        # country may be numeric id — e164 helper expects ISO2; pass empty if digit id
        c = str(country or "").strip()
        if c.isdigit():
            c = ""
        return normalize_e164(raw, country=c)
    except Exception:
        digits = re.sub(r"\D", "", raw)
        return f"+{digits}" if digits else ""


def _load_sms_config_file() -> dict[str, Any]:
    paths: list[str] = []
    env_cfg = _env("TOKENREFRESH_SMS_CONFIG")
    if env_cfg:
        paths.append(env_cfg)
    paths.extend(
        [
            os.path.join(os.getcwd(), "sms_config.json"),
            os.path.join(os.getcwd(), "tokenrefresh_sms_config.json"),
            os.path.join(PACKAGE_DIR, "sms_config.json"),
            os.path.join(PACKAGE_DIR, "tokenrefresh_sms_config.json"),
        ]
    )
    for path in paths:
        try:
            with open(os.path.normpath(path), "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                continue
            for key in ("hero_sms", "herosms", "hero"):
                sub = data.get(key)
                if isinstance(sub, dict):
                    return dict(sub)
            if (data.get("provider") or "").lower() in (
                "hero",
                "hero-sms",
                "herosms",
                "hero_sms",
            ):
                return data
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return {}


class HeroSmsClient:
    """Low-level HeroSMS handler_api client (SMS-Activate compatible)."""

    def __init__(
        self,
        api_key: str,
        *,
        api_base: str | None = None,
        log_fn: Callable[[str], None] | None = None,
        timeout: float = 30.0,
    ):
        self.api_key = _strip_env_quotes(api_key or "")
        self.api_base = (
            api_base
            or _env("HERO_SMS_API_BASE")
            or _env("HEROSMS_API_BASE")
            or DEFAULT_API_BASE
        ).rstrip()
        self.log = log_fn or (lambda _: None)
        self.timeout = timeout
        self._http = _direct_session()
        try:
            conc = int(_env("HERO_SMS_HTTP_CONCURRENCY") or "12")
        except ValueError:
            conc = 12
        self._sem = threading.Semaphore(max(2, min(conc, 32)))
        self._pace_lock = threading.Lock()
        self._last_req_at = 0.0
        try:
            self._min_interval = float(_env("HERO_SMS_HTTP_MIN_INTERVAL") or "0.05")
        except ValueError:
            self._min_interval = 0.05

    def close(self) -> None:
        try:
            self._http.close()
        except Exception:
            pass

    def _pace(self) -> None:
        with self._pace_lock:
            wait = self._min_interval - (time.time() - self._last_req_at)
            if wait > 0:
                time.sleep(wait)
            self._last_req_at = time.time()

    def request(self, action: str, params: dict[str, Any] | None = None) -> str | dict | None:
        if not self.api_key:
            raise RuntimeError("HeroSMS api_key missing")
        q: dict[str, Any] = {"api_key": self.api_key, "action": action}
        for k, v in (params or {}).items():
            if v is None or v == "":
                continue
            q[k] = v
        with self._sem:
            self._pace()
            try:
                r = self._http.get(
                    self.api_base,
                    params=q,
                    headers={
                        "accept": "application/json,text/plain,*/*",
                        "user-agent": "tokenrefresh-hero-sms/1.0",
                    },
                    timeout=self.timeout,
                )
                text = (r.text or "").strip()
            except Exception as e:
                self.log(f"HeroSMS request error action={action}: {e}")
                return None
        if not text:
            return None
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except Exception:
                return text
        return text

    def get_balance(self) -> dict[str, Any]:
        raw = self.request("getBalance")
        if isinstance(raw, str) and "ACCESS_BALANCE" in raw:
            try:
                bal = float(raw.split(":", 1)[1])
                return {"ok": True, "balance": bal, "raw": raw}
            except Exception:
                return {"ok": True, "raw": raw}
        if isinstance(raw, dict) and "balance" in raw:
            return {"ok": True, "balance": raw.get("balance"), "raw": raw}
        return {"ok": False, "raw": raw}

    def get_number(
        self,
        service: str,
        country: str | int,
        *,
        max_price: float | None = None,
        operator: str = "",
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "service": service,
            "country": country,
        }
        if max_price is not None and float(max_price) > 0:
            params["maxPrice"] = f"{float(max_price):.4f}".rstrip("0").rstrip(".")
        if operator and operator.lower() not in ("any", "auto", "0", "all"):
            params["operator"] = operator
        raw = self.request("getNumber", params)
        # ACCESS_NUMBER:id:phone
        if isinstance(raw, str) and raw.startswith("ACCESS_NUMBER:"):
            parts = raw.split(":")
            if len(parts) >= 3:
                aid = parts[1].strip()
                phone = _normalize_phone(parts[2], country=country)
                return {
                    "ok": True,
                    "activation_id": aid,
                    "phone": phone,
                    "raw": raw,
                    "country": str(country),
                }
        return {"ok": False, "error": str(raw), "raw": raw}

    def get_number_v2(
        self,
        service: str,
        country: str | int,
        *,
        max_price: float | None = None,
        operator: str = "",
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "service": service,
            "country": country,
        }
        if max_price is not None and float(max_price) > 0:
            params["maxPrice"] = f"{float(max_price):.4f}".rstrip("0").rstrip(".")
        if operator and operator.lower() not in ("any", "auto", "0", "all"):
            params["operator"] = operator
        raw = self.request("getNumberV2", params)
        if isinstance(raw, dict) and (raw.get("activationId") or raw.get("phoneNumber")):
            return {
                "ok": True,
                "activation_id": str(raw.get("activationId") or ""),
                "phone": _normalize_phone(
                    str(raw.get("phoneNumber") or ""), country=country
                ),
                "cost": raw.get("activationCost"),
                "country_code": raw.get("countryCode"),
                "operator": raw.get("activationOperator"),
                "raw": raw,
                "country": str(country),
            }
        return {"ok": False, "error": str(raw), "raw": raw}

    def get_status(self, activation_id: str) -> dict[str, Any]:
        raw = self.request("getStatus", {"id": activation_id})
        if not isinstance(raw, str):
            # some gateways return JSON
            if isinstance(raw, dict):
                code = raw.get("code") or raw.get("smsCode") or raw.get("sms")
                if code:
                    return {"ok": True, "state": "ok", "code": str(code).strip(), "raw": raw}
            return {"ok": False, "state": "unknown", "raw": raw}
        if raw.startswith("STATUS_OK:"):
            code = raw.split(":", 1)[1].strip()
            m = re.search(r"\b(\d{4,8})\b", code)
            if m:
                code = m.group(1)
            return {"ok": True, "state": "ok", "code": code, "raw": raw}
        if raw.startswith("STATUS_WAIT"):
            return {"ok": True, "state": "wait", "raw": raw}
        if "CANCEL" in raw:
            return {"ok": True, "state": "cancel", "raw": raw}
        if raw == "NO_ACTIVATION":
            return {"ok": False, "state": "no_activation", "raw": raw}
        return {"ok": True, "state": "other", "raw": raw}

    def set_status(self, activation_id: str, status: str) -> dict[str, Any]:
        raw = self.request("setStatus", {"id": activation_id, "status": status})
        if raw is None:
            return {"ok": False, "raw": raw}
        if isinstance(raw, str) and (
            raw.startswith("ACCESS_")
            or raw in ("ACCESS_READY", "ACCESS_ACTIVATION", "ACCESS_CANCEL")
            or "ACCESS" in raw
        ):
            return {"ok": True, "raw": raw}
        # some deployments return plain OK / empty success
        if isinstance(raw, str) and raw.upper() in ("OK", "1", "TRUE"):
            return {"ok": True, "raw": raw}
        if isinstance(raw, dict) and not raw.get("error"):
            return {"ok": True, "raw": raw}
        # treat non-error text as ok if not clearly BAD_*
        if isinstance(raw, str) and not raw.upper().startswith("BAD_") and "ERROR" not in raw.upper():
            return {"ok": True, "raw": raw}
        return {"ok": False, "error": str(raw), "raw": raw}


class HeroSmsProvider:
    """Phone SMS provider with Getatext-compatible rent/poll/complete/cancel."""

    def __init__(
        self,
        api_key: str,
        *,
        service: str = DEFAULT_SERVICE,
        country: str | int = DEFAULT_COUNTRY,
        country_fallback: str = DEFAULT_COUNTRY_FALLBACK,
        max_price: float = DEFAULT_MAX_PRICE,
        operator: str = "",
        use_v2: bool = True,
        country_shuffle: bool = True,
        sms_timeout_s: float = 30.0,
        sms_poll_interval: float = 2.0,
        api_base: str | None = None,
        log_fn: Callable[[str], None] | None = None,
    ):
        self.service = str(service or DEFAULT_SERVICE).strip() or DEFAULT_SERVICE
        self.country = country
        self.country_fallback = (country_fallback or "").strip()
        self.max_price = float(max_price) if float(max_price) > 0 else DEFAULT_MAX_PRICE
        self.operator = (operator or "").strip()
        self.use_v2 = use_v2
        self.country_shuffle = country_shuffle
        self.sms_timeout_s = max(5.0, min(float(sms_timeout_s), 90.0))
        self.sms_poll_interval = max(0.5, float(sms_poll_interval))
        self.log = log_fn or (lambda _: None)
        self.last_rent_error = ""
        self.client = HeroSmsClient(api_key, api_base=api_base, log_fn=self.log)

    def close(self) -> None:
        self.client.close()

    def _country_try_list(self) -> list[str]:
        multi = _env("HERO_SMS_COUNTRIES") or _env("HEROSMS_COUNTRIES")
        out: list[str] = []
        if multi:
            for part in re.split(r"[,;\s]+", multi):
                p = part.strip()
                if p and p not in out:
                    out.append(p)
        else:
            c0 = str(self.country or "").strip()
            if c0:
                out.append(c0)
            for part in re.split(r"[,;\s]+", self.country_fallback or ""):
                p = part.strip()
                if p and p not in out:
                    out.append(p)
        if not out:
            out = [DEFAULT_COUNTRY]
        if self.country_shuffle and len(out) > 1:
            out = list(out)
            random.shuffle(out)
        return out

    def _rent_once(self, country: str | int) -> dict[str, Any]:
        if self.use_v2:
            res = self.client.get_number_v2(
                self.service,
                country,
                max_price=self.max_price,
                operator=self.operator,
            )
            if res.get("ok"):
                return res
            err = str(res.get("error") or res.get("raw") or "")
            # V2 不可用 / 无号时再试 V1
            if "NO_NUMBERS" in err or "NO_NUMBER" in err:
                return res
            if "BAD_ACTION" in err or "METHOD" in err.upper():
                pass  # fall through to v1
            else:
                # 其它业务错误也可再试 v1 一次
                pass
            return self.client.get_number(
                self.service,
                country,
                max_price=self.max_price,
                operator=self.operator,
            )
        return self.client.get_number(
            self.service,
            country,
            max_price=self.max_price,
            operator=self.operator,
        )

    def rent(self, session: Any = None) -> dict | None:
        _ = session
        self.last_rent_error = ""
        last_err = ""
        countries = self._country_try_list()
        self.log(
            f"HeroSMS rent try countries={','.join(str(c) for c in countries)} "
            f"service={self.service} maxPrice={self.max_price}"
        )
        for c in countries:
            res = self._rent_once(c)
            if res.get("ok"):
                aid = str(res.get("activation_id") or "").strip()
                phone = str(res.get("phone") or "").strip()
                if not aid or not phone:
                    last_err = "empty_tel_or_id"
                    continue
                if not phone.startswith("+"):
                    phone = _normalize_phone(phone, country=c)
                self.log(
                    f"HeroSMS rent ok id={aid[:12]}... country={c} e164={phone} "
                    f"maxPrice={self.max_price}"
                    + (
                        f" cost={res.get('cost')}"
                        if res.get("cost") is not None
                        else ""
                    )
                )
                try:
                    self.client.set_status(aid, STATUS_READY)
                except Exception:
                    pass
                self.last_rent_error = ""
                return {
                    "activation_id": aid,
                    "phone": phone,
                    "country": str(c),
                    "country_used": str(c),
                    "raw": res.get("raw"),
                    "provider": "hero",
                    "max_price": self.max_price,
                    "price": res.get("cost"),
                }
            last_err = str(res.get("error") or res.get("raw") or "rent_fail")
            self.log(f"HeroSMS rent fail country={c}: {last_err[:100]}")
            low = last_err.upper()
            # 致命错误：别空扫国家
            if any(x in low for x in ("BAD_KEY", "BANNED", "WRONG_TOKEN", "NO_BALANCE", "ERROR_SQL")):
                break
        self.last_rent_error = last_err or "rent_failed"
        self.log(f"HeroSMS rent fail: {self.last_rent_error[:120]}")
        return None

    def poll(
        self,
        session: Any,
        activation_id: str,
        timeout_s: float | None = None,
    ) -> str | None:
        """先查码再 sleep（与 Getatext/VAK 一致）。"""
        _ = session
        limit = float(timeout_s) if timeout_s is not None else self.sms_timeout_s
        limit = max(5.0, min(limit, 120.0))
        deadline = time.time() + limit
        interval = self.sms_poll_interval
        while time.time() < deadline:
            st = self.client.get_status(activation_id)
            if st.get("state") == "ok" and st.get("code"):
                self.log(f"HeroSMS code: {st['code']}")
                return str(st["code"])
            if st.get("state") in ("cancel", "no_activation"):
                return None
            remaining = deadline - time.time()
            if remaining <= 0.2:
                break
            time.sleep(min(interval, remaining))
        self.log(f"HeroSMS timeout after {limit:.0f}s")
        return None

    def complete(self, session: Any, activation_id: str) -> None:
        _ = session
        aid = str(activation_id or "").strip()
        if not aid:
            return
        last_err = ""
        for try_i in range(1, 4):
            r = self.client.set_status(aid, STATUS_DONE)
            if r.get("ok"):
                self.log(f"HeroSMS complete id={aid[:12]}... try={try_i}")
                return
            last_err = str(r.get("error") or r.get("raw") or "complete_failed")
            time.sleep(0.3 * try_i)
        raise RuntimeError(f"HeroSMS complete failed id={aid[:12]}: {last_err[:160]}")

    def cancel(self, session: Any, activation_id: str) -> None:
        _ = session
        aid = str(activation_id or "").strip()
        if not aid:
            return
        last_err = ""
        for try_i in range(1, 4):
            r = self.client.set_status(aid, STATUS_CANCEL)
            if r.get("ok"):
                self.log(f"HeroSMS cancel id={aid[:12]}... try={try_i}")
                return
            last_err = str(r.get("error") or r.get("raw") or "cancel_failed")
            time.sleep(0.3 * try_i)
        raise RuntimeError(f"HeroSMS cancel failed id={aid[:12]}: {last_err[:160]}")


def build_hero_sms_provider(
    sms_config: dict | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> HeroSmsProvider | None:
    """Build from env / sms_config.json."""
    cfg = _load_sms_config_file()
    if isinstance(sms_config, dict):
        if isinstance(sms_config.get("hero_sms"), dict):
            cfg.update(sms_config["hero_sms"])
        elif isinstance(sms_config.get("herosms"), dict):
            cfg.update(sms_config["herosms"])
        elif isinstance(sms_config.get("hero"), dict):
            cfg.update(sms_config["hero"])
        else:
            if any(k in sms_config for k in ("service", "country", "api_key", "key")):
                cfg.update(sms_config)

    api_key = _strip_env_quotes(
        _env("HERO_SMS_API_KEY")
        or _env("HEROSMS_API_KEY")
        or _env("HERO_API_KEY")
        or _env("hero")
        or _env("herosms")
        or str(cfg.get("api_key") or cfg.get("key") or "").strip()
    )
    if isinstance(cfg.get("api_keys"), list) and cfg["api_keys"] and not api_key:
        api_key = _strip_env_quotes(str(cfg["api_keys"][0]))
    if not api_key:
        return None

    service = _strip_env_quotes(
        _env("HERO_SMS_SERVICE")
        or str(cfg.get("service") or cfg.get("service_code") or DEFAULT_SERVICE)
    ) or DEFAULT_SERVICE

    countries_blob = (
        _env("HERO_SMS_COUNTRIES")
        or str(cfg.get("countries") or cfg.get("country_list") or "")
    ).strip()
    if countries_blob:
        parts = [p.strip() for p in re.split(r"[,;\s]+", countries_blob) if p.strip()]
        country: str | int = parts[0] if parts else DEFAULT_COUNTRY
        country_fallback = ",".join(parts[1:]) if len(parts) > 1 else ""
    else:
        country = _env("HERO_SMS_COUNTRY") or str(
            cfg.get("country") or DEFAULT_COUNTRY
        )
        country_fallback = (
            _env("HERO_SMS_COUNTRY_FALLBACK")
            if "HERO_SMS_COUNTRY_FALLBACK" in os.environ
            else str(
                cfg.get("country_fallback")
                if cfg.get("country_fallback") is not None
                else DEFAULT_COUNTRY_FALLBACK
            )
        )
    try:
        if str(country).isdigit():
            country = int(country)
    except Exception:
        pass

    max_price = _env_float(
        "HERO_SMS_MAX_PRICE",
        float(cfg.get("max_price") or cfg.get("maxPrice") or DEFAULT_MAX_PRICE),
    )
    timeout = _env_float(
        "HERO_SMS_TIMEOUT",
        float(
            cfg.get("sms_timeout")
            or cfg.get("timeout")
            or _env("K12_PHONE_OTP_TIMEOUT_S")
            or 30.0
        ),
    )
    poll_iv = _env_float(
        "HERO_SMS_POLL_INTERVAL",
        float(cfg.get("poll_interval") or 2.0),
    )
    operator = _env("HERO_SMS_OPERATOR") or str(cfg.get("operator") or "")
    use_v2 = _env("HERO_SMS_USE_V2", "1").lower() not in ("0", "false", "no", "off")
    shuffle = _env("HERO_SMS_COUNTRY_SHUFFLE", "1").lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    api_base = _env("HERO_SMS_API_BASE") or cfg.get("api_base") or cfg.get("handler_api")

    return HeroSmsProvider(
        api_key,
        service=service,
        country=country,
        country_fallback=country_fallback,
        max_price=max_price,
        operator=operator,
        use_v2=use_v2,
        country_shuffle=shuffle,
        sms_timeout_s=timeout,
        sms_poll_interval=poll_iv,
        api_base=str(api_base) if api_base else None,
        log_fn=log_fn,
    )
