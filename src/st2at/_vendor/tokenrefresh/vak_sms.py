"""VAK-SMS 接码（https://vak-sms.com）— Codex add_phone 绑机。

实测 API（GET + apiKey query）:
  /api/getBalance/          → {"balance": float}
  /api/getCountNumber/      → {"dr": N}  需 service + country
  /api/getNumber/           → {"tel": 4477…, "idNum": "21050137"}
  /api/getSmsCode/          → {"smsCode": null|str}  需 idNum
  /api/setStatus/           → status=end 取消退款  需 idNum

国家用 ISO2 小写: us/gb/ca/br/de/id …
OpenAI/ChatGPT 服务码: dr（与 sms-activate 同族）
"""
from __future__ import annotations

import json
import os
import random
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable

import requests

DEFAULT_API_BASE = "https://vak-sms.com/api"
# OpenAI / ChatGPT
DEFAULT_SERVICE = "dr"
# 多国试号（排除 us/usv 虚拟、id、au）；租号默认随机打乱顺序
# 查价 2026-07：it/gb/at/pl/fr/pt/si ≈0.01；ph≈0.024；ca≈0.029；cl≈0.03
DEFAULT_COUNTRY = "it"
DEFAULT_COUNTRY_FALLBACK = "gb,at,pl,fr,pt,si,ph,ca,cl"
# 最高单价（美元）；贵了不租。API 参数 maxPrice
DEFAULT_MAX_PRICE = 0.03


def _strip_env_quotes(s: str) -> str:
    """Strip accidental surrounding quotes from env values (shared helper)."""
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
    try:
        return float(_env(name) or default)
    except ValueError:
        return default


def _normalize_phone(phone: str | int, country: str = "") -> str:
    """E.164 — same rules as Getatext (sms_e164)."""
    from .sms_e164 import normalize_e164

    return normalize_e164(str(phone or ""), country=country)


def _load_sms_config_file() -> dict[str, Any]:
    roots = [
        Path.cwd(),
        Path(__file__).resolve().parent,
        Path(__file__).resolve().parent.parent.parent,  # project root if vendor/tokenrefresh
    ]
    for root in roots:
        for name in ("sms_config.json", "tokenrefresh_sms_config.json"):
            p = root / name
            if not p.is_file():
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            if isinstance(data.get("vak_sms"), dict):
                return dict(data["vak_sms"])
            if isinstance(data.get("vak"), dict):
                return dict(data["vak"])
            if (data.get("provider") or "").lower() in ("vak", "vak-sms", "vaksms"):
                return data
    return {}


class VakSmsClient:
    """Thin GET client for vak-sms.com/api/*."""

    def __init__(
        self,
        api_key: str,
        api_base: str | None = None,
        timeout: float = 25.0,
        log_fn: Callable[[str], None] | None = None,
    ):
        self.api_key = (api_key or "").strip()
        self.api_base = (api_base or _env("VAK_SMS_API_BASE") or DEFAULT_API_BASE).rstrip(
            "/"
        )
        self.timeout = timeout
        self.log = log_fn or (lambda _: None)
        self._http = requests.Session()
        self._http.verify = False
        try:
            conc = int(_env("VAK_SMS_HTTP_CONCURRENCY") or "8")
        except ValueError:
            conc = 8
        self._sem = threading.Semaphore(max(2, min(conc, 32)))
        self._pace_lock = threading.Lock()
        self._last_req_at = 0.0
        try:
            self._min_interval = float(_env("VAK_SMS_HTTP_MIN_INTERVAL") or "0.08")
        except ValueError:
            self._min_interval = 0.08

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

    def request(self, path: str, params: dict[str, Any] | None = None) -> Any:
        if not self.api_key:
            raise RuntimeError("VAK SMS api_key missing")
        p = path if path.startswith("/") else f"/{path}"
        if not p.endswith("/"):
            p = p + "/"
        q: dict[str, Any] = {"apiKey": self.api_key}
        for k, v in (params or {}).items():
            if v is None or v == "":
                continue
            q[k] = v
        url = f"{self.api_base}{p}"
        with self._sem:
            self._pace()
            try:
                r = self._http.get(
                    url,
                    params=q,
                    headers={
                        "accept": "application/json,text/plain,*/*",
                        "user-agent": "tokenrefresh-vak-sms/1.0",
                    },
                    timeout=self.timeout,
                )
                text = (r.text or "").strip()
            except Exception as e:
                self.log(f"VAK SMS request error path={p}: {e}")
                return {"error": str(e)}
        if not text:
            return {"error": "empty_response"}
        try:
            return json.loads(text)
        except Exception:
            return {"error": "bad_json", "raw": text[:200]}

    def get_balance(self) -> dict[str, Any]:
        data = self.request("getBalance")
        if isinstance(data, dict) and "balance" in data:
            return {"ok": True, "balance": data.get("balance"), "raw": data}
        return {"ok": False, "raw": data}

    def get_count(self, service: str, country: str) -> dict[str, Any]:
        data = self.request(
            "getCountNumber", {"service": service, "country": country}
        )
        if not isinstance(data, dict):
            return {"ok": False, "count": 0, "raw": data}
        if data.get("error"):
            return {"ok": False, "count": 0, "error": data.get("error"), "raw": data}
        # {"dr": 1129}
        cnt = data.get(service)
        if cnt is None and data:
            # first numeric value
            for v in data.values():
                if isinstance(v, (int, float)):
                    cnt = v
                    break
        try:
            n = int(cnt or 0)
        except Exception:
            n = 0
        return {"ok": True, "count": n, "raw": data}

    def get_number(
        self,
        service: str,
        country: str,
        *,
        operator: str = "",
        max_price: float | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"service": service, "country": country}
        if operator and operator.lower() not in ("any", "auto", "0", "all"):
            params["operator"] = operator
        # 贵了不要：maxPrice 限制（实测 gb 支持）
        if max_price is not None and float(max_price) > 0:
            params["maxPrice"] = f"{float(max_price):.4f}".rstrip("0").rstrip(".")
        data = self.request("getNumber", params)
        if not isinstance(data, dict):
            return {"ok": False, "error": "bad_response", "raw": data}
        if data.get("error"):
            return {"ok": False, "error": str(data.get("error")), "raw": data}
        tel = data.get("tel") or data.get("number") or data.get("phone")
        aid = data.get("idNum") or data.get("id") or data.get("activationId")
        if tel is None or aid is None:
            return {"ok": False, "error": "empty_tel_or_id", "raw": data}
        # 若响应带 price 且超限 → 立刻 end 退号
        price_val = data.get("price") or data.get("cost") or data.get("servicePrice")
        try:
            if max_price is not None and price_val is not None and float(price_val) > float(max_price) + 1e-9:
                self.set_status(str(aid).strip(), "end")
                return {
                    "ok": False,
                    "error": f"price_too_high:{price_val}>{max_price}",
                    "raw": data,
                }
        except Exception:
            pass
        # country 来自 getNumber 请求参数；tel 多为国际数字（4477…）
        ctry = str(params.get("country") or "").strip()
        phone_e164 = _normalize_phone(tel, country=ctry)
        return {
            "ok": True,
            "phone": phone_e164,
            "activation_id": str(aid).strip(),
            "price": price_val,
            "country": ctry,
            "raw_number": str(tel),
            "raw": data,
        }

    def get_sms_code(self, activation_id: str) -> dict[str, Any]:
        data = self.request("getSmsCode", {"idNum": activation_id})
        if not isinstance(data, dict):
            return {"ok": False, "raw": data}
        if data.get("error"):
            return {"ok": False, "error": str(data.get("error")), "raw": data}
        code = data.get("smsCode")
        if code is None or str(code).strip() in ("", "null", "None"):
            return {"ok": True, "code": None, "raw": data}
        return {"ok": True, "code": str(code).strip(), "raw": data}

    def set_status(self, activation_id: str, status: str) -> dict[str, Any]:
        data = self.request(
            "setStatus", {"idNum": activation_id, "status": status}
        )
        if not isinstance(data, dict):
            return {"ok": False, "raw": data}
        if data.get("error"):
            return {"ok": False, "error": str(data.get("error")), "raw": data}
        return {"ok": True, "raw": data}


class VakSmsProvider:
    """Provider interface matching Getatext/Smsbower: rent / poll / complete / cancel."""

    def __init__(
        self,
        api_key: str,
        *,
        service: str = DEFAULT_SERVICE,
        country: str = DEFAULT_COUNTRY,
        country_fallback: str = DEFAULT_COUNTRY_FALLBACK,
        operator: str = "",
        max_price: float = DEFAULT_MAX_PRICE,
        sms_timeout_s: float = 120.0,
        sms_poll_interval: float = 2.0,
        api_base: str | None = None,
        log_fn: Callable[[str], None] | None = None,
    ):
        self.service = (service or DEFAULT_SERVICE).strip()
        self.country = (country or DEFAULT_COUNTRY).strip().lower()
        self.country_fallback = (country_fallback or "").strip()
        self.operator = (operator or "").strip()
        try:
            self.max_price = float(max_price)
        except Exception:
            self.max_price = DEFAULT_MAX_PRICE
        if self.max_price <= 0:
            self.max_price = DEFAULT_MAX_PRICE
        # 与 Getatext 对齐：等码默认 ~30s，超时立刻 cancel，禁止长占号
        self.sms_timeout_s = max(8.0, min(float(sms_timeout_s), 90.0))
        self.sms_poll_interval = max(0.8, float(sms_poll_interval))
        self.log = log_fn or (lambda _: None)
        self.last_rent_error = ""
        self.client = VakSmsClient(api_key, api_base=api_base, log_fn=self.log)

    def close(self) -> None:
        self.client.close()

    def _country_try_list(self, *, shuffle: bool | None = None) -> list[str]:
        """主国 + fallback 列表。默认每次租号随机打乱（VAK_SMS_COUNTRY_SHUFFLE=1）。"""
        out: list[str] = []
        # 也可 VAK_SMS_COUNTRIES=it,gb,at,... 一表覆盖主+fallback
        multi = (_env("VAK_SMS_COUNTRIES") or "").strip()
        if multi:
            for part in re.split(r"[,;\s]+", multi):
                p = part.strip().lower()
                if p and p not in out:
                    out.append(p)
        else:
            if self.country:
                out.append(self.country.lower())
            for part in re.split(r"[,;\s]+", self.country_fallback or ""):
                p = part.strip().lower()
                if p and p not in out:
                    out.append(p)
        if not out:
            out = [DEFAULT_COUNTRY]
        if shuffle is None:
            shuffle = (_env("VAK_SMS_COUNTRY_SHUFFLE") or "1").strip().lower() not in (
                "0",
                "false",
                "no",
                "off",
            )
        if shuffle and len(out) > 1:
            out = list(out)
            random.shuffle(out)
        return out

    def rent(self, session: Any = None) -> dict | None:
        _ = session
        self.last_rent_error = ""
        last_err = ""
        countries = self._country_try_list(shuffle=True)
        self.log(
            f"VAK SMS rent try countries(random)={','.join(countries)} "
            f"maxPrice={self.max_price}"
        )
        for c in countries:
            # optional stock peek (not required)
            try:
                st = self.client.get_count(self.service, c)
                if st.get("ok") and int(st.get("count") or 0) <= 0:
                    self.log(f"VAK SMS stock=0 country={c} service={self.service}")
                    last_err = f"no stock country={c}"
                    continue
            except Exception:
                pass
            res = self.client.get_number(
                self.service,
                c,
                operator=self.operator,
                max_price=self.max_price,
            )
            if res.get("ok"):
                phone = str(res.get("phone") or "")
                aid = str(res.get("activation_id") or "")
                price = res.get("price")
                # 再走一遍 E.164，与 Getatext rent 日志字段对齐
                phone = _normalize_phone(phone, country=c)
                self.log(
                    f"VAK SMS rent ok id={aid[:12]}... raw={res.get('raw_number') or '-'} "
                    f"country={c} e164={phone} maxPrice={self.max_price}"
                    + (f" price={price}" if price is not None else "")
                )
                self.last_rent_error = ""
                return {
                    "activation_id": aid,
                    "phone": phone,
                    "country": c,
                    "raw_number": str(res.get("raw_number") or ""),
                    "raw": res.get("raw"),
                    "provider": "vak",
                    "country_used": c,
                    "max_price": self.max_price,
                    "price": price,
                }
            last_err = str(res.get("error") or res.get("raw") or "rent_fail")
            self.log(f"VAK SMS rent fail country={c}: {last_err[:100]}")
            # noNumber / badService → try next country
            low = last_err.lower()
            if "bad" in low and "service" in low:
                break
        self.last_rent_error = last_err or "rent_failed"
        self.log(f"VAK SMS rent fail: {self.last_rent_error[:120]}")
        return None

    def poll(
        self,
        session: Any,
        activation_id: str,
        timeout_s: float | None = None,
    ) -> str | None:
        """先查码再 sleep（与 Getatext 一致），禁止先睡白烧等码窗口。"""
        _ = session
        limit = float(timeout_s) if timeout_s is not None else self.sms_timeout_s
        # 与 Getatext 对齐硬顶 90s；实际由 K12_PHONE_OTP_TIMEOUT_S / VAK_SMS_TIMEOUT 控制
        limit = max(8.0, min(limit, 90.0))
        deadline = time.time() + limit
        interval = self.sms_poll_interval
        i = 0
        while time.time() < deadline:
            st = self.client.get_sms_code(activation_id)
            if st.get("ok") and st.get("code"):
                code = str(st["code"]).strip()
                # 正文里抽 4–8 位（与 Getatext 一致）
                if code and not code.isdigit():
                    m = re.search(r"\b(\d{4,8})\b", code)
                    if m:
                        code = m.group(1)
                self.log(f"VAK SMS code: {code}")
                return code
            if st.get("error") in ("noNumber", "no_activation", "cancel"):
                self.log(f"VAK SMS poll end: {st.get('error')}")
                return None
            remaining = deadline - time.time()
            if remaining <= 0.2:
                break
            # 前几轮密扫（对齐 Getatext）
            if i < 8:
                wait = min(0.8, interval)
            elif i < 20:
                wait = interval
            else:
                wait = min(2.5, interval * 1.2)
            time.sleep(min(wait, remaining))
            i += 1
        self.log(
            f"VAK SMS timeout after {limit:.0f}s id={str(activation_id)[:12]}... "
            f"— caller must cancel immediately"
        )
        return None

    def complete(self, session: Any, activation_id: str) -> None:
        """收码后必须 complete，否则号占 active 槽（与 Getatext complete 同语义）。

        VAK：setStatus status=ok/ready/6；end=取消。
        """
        _ = session
        aid = str(activation_id or "").strip()
        if not aid:
            return
        last_err = ""
        for try_i in range(1, 5):
            for st in ("ok", "ready", "6"):
                r = self.client.set_status(aid, st)
                if r.get("ok"):
                    self.log(
                        f"VAK SMS complete status={st} id={aid[:12]}... try={try_i}"
                    )
                    return
                err = str(r.get("error") or r.get("raw") or "")
                low = err.lower()
                if any(
                    k in low
                    for k in (
                        "already",
                        "completed",
                        "finish",
                        "status ok",
                        "not found",
                        "no activation",
                    )
                ):
                    self.log(
                        f"VAK SMS complete already-done id={aid[:12]}... {err[:80]}"
                    )
                    return
                last_err = err or "complete_failed"
            time.sleep(0.35 * try_i)
        raise RuntimeError(f"VAK complete failed id={aid[:12]}: {last_err[:160]}")

    def cancel(self, session: Any, activation_id: str) -> None:
        _ = session
        # 实测 status=end 可取消退款；失败抛出供 _safe_cancel 重试（立刻 cancel，无 60s 等待）
        aid = str(activation_id or "").strip()
        if not aid:
            return
        last_err = ""
        for try_i in range(1, 4):
            r = self.client.set_status(aid, "end")
            if r.get("ok"):
                self.log(f"VAK SMS cancel end id={aid[:12]}... try={try_i}")
                return
            err = str(r.get("error") or r.get("raw") or "cancel_failed")
            low = err.lower()
            if any(
                k in low
                for k in ("already", "cancel", "not found", "no activation", "end")
            ):
                self.log(f"VAK SMS cancel already-done id={aid[:12]}... {err[:80]}")
                return
            last_err = err
            time.sleep(0.35 * try_i)
        raise RuntimeError(f"VAK cancel failed: {last_err[:160]}")


def build_vak_sms_provider(
    sms_config: dict | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> VakSmsProvider | None:
    cfg = _load_sms_config_file()
    if isinstance(sms_config, dict):
        if isinstance(sms_config.get("vak_sms"), dict):
            cfg.update(sms_config["vak_sms"])
        elif isinstance(sms_config.get("vak"), dict):
            cfg.update(sms_config["vak"])
        else:
            # only merge if looks like vak config
            if any(k in sms_config for k in ("service", "country", "api_key", "key")):
                cfg.update(sms_config)

    api_key = _strip_env_quotes(
        _env("VAK_SMS_API_KEY")
        or _env("VAK_API_KEY")
        or _env("vak")  # project .env shorthand
        or _env("VAKSMS_API_KEY")
        or str(cfg.get("api_key") or cfg.get("key") or "").strip()
    )
    if isinstance(cfg.get("api_keys"), list) and cfg["api_keys"] and not api_key:
        api_key = _strip_env_quotes(str(cfg["api_keys"][0]))
    if not api_key:
        return None

    service = _strip_env_quotes(
        _env("VAK_SMS_SERVICE")
        or str(cfg.get("service") or cfg.get("service_code") or DEFAULT_SERVICE)
    ) or DEFAULT_SERVICE
    # 多国表优先：VAK_SMS_COUNTRIES / cfg.countries
    countries_blob = (
        _env("VAK_SMS_COUNTRIES")
        or str(cfg.get("countries") or cfg.get("country_list") or "")
    ).strip()
    if countries_blob:
        parts = [p.strip().lower() for p in re.split(r"[,;\s]+", countries_blob) if p.strip()]
        country = parts[0] if parts else DEFAULT_COUNTRY
        country_fallback = ",".join(parts[1:]) if len(parts) > 1 else ""
    else:
        country = (
            _env("VAK_SMS_COUNTRY")
            or str(cfg.get("country") or DEFAULT_COUNTRY)
        ).strip().lower() or DEFAULT_COUNTRY
        country_fallback = (
            _env("VAK_SMS_COUNTRY_FALLBACK")
            if "VAK_SMS_COUNTRY_FALLBACK" in os.environ
            else str(
                cfg.get("country_fallback")
                if cfg.get("country_fallback") is not None
                else DEFAULT_COUNTRY_FALLBACK
            )
        )
    operator = _env("VAK_SMS_OPERATOR") or str(cfg.get("operator") or "")
    max_price = _env_float(
        "VAK_SMS_MAX_PRICE",
        float(cfg.get("max_price") or cfg.get("maxPrice") or DEFAULT_MAX_PRICE),
    )
    # 与 Getatext 对齐：默认 30s 等码（K12_PHONE_OTP_TIMEOUT_S / VAK_SMS_TIMEOUT）
    timeout = _env_float(
        "VAK_SMS_TIMEOUT",
        float(
            cfg.get("sms_timeout")
            or cfg.get("timeout")
            or _env("K12_PHONE_OTP_TIMEOUT_S")
            or 30.0
        ),
    )
    poll_iv = _env_float(
        "VAK_SMS_POLL_INTERVAL",
        float(cfg.get("poll_interval") or 1.0),
    )
    api_base = _env("VAK_SMS_API_BASE") or cfg.get("api_base")

    return VakSmsProvider(
        api_key,
        service=service,
        country=country,
        country_fallback=country_fallback,
        operator=operator,
        max_price=max_price,
        sms_timeout_s=timeout,
        sms_poll_interval=poll_iv,
        api_base=str(api_base) if api_base else None,
        log_fn=log_fn,
    )
