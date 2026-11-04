"""SMSBower 手机 SMS 客户端 API（handler_api.php · SMS-Activate 兼容协议）。

文档: https://smsbower.app/cn/api?page=client

Base:
  https://smsbower.page/stubs/handler_api.php?api_key=KEY&action=...

查询:
  getBalance / getServicesList / getCountries / getPrices / getPricesV2 / getPricesV3
  getTopCountriesByService

租号/收码:
  getNumber / getNumberV2 / getStatus / setStatus

与 GetatextProvider 对齐接口: rent / poll / complete / cancel
（session 参数忽略，始终直连，不走 ChatGPT 代理）
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any, Callable

import requests

DEFAULT_API_BASE = "https://smsbower.page/stubs/handler_api.php"
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))

# setStatus（SMS-Activate 兼容）
STATUS_READY = "1"  # 告知已发送短信 / 等待码
STATUS_RETRY = "3"  # 请求重发
STATUS_DONE = "6"  # 成功完成
STATUS_CANCEL = "8"  # 取消


def _direct_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.trust_env = False
    s.proxies = {"http": None, "https": None}
    return s


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _normalize_phone(number: str) -> str:
    digits = re.sub(r"\D", "", str(number or ""))
    return f"+{digits}" if digits else ""


def _load_sms_config_file() -> dict[str, Any]:
    """Load sms_config.json → smsbower / smsbower_sms section."""
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
            for key in ("smsbower_sms", "smsbower_phone", "smsbower"):
                sub = data.get(key)
                if isinstance(sub, dict) and (
                    sub.get("api_key")
                    or sub.get("api_keys")
                    or key != "smsbower"
                    or sub.get("sms_service")
                    or sub.get("service_code")
                ):
                    # mail 段也可能叫 smsbower；优先带 sms 字段的
                    if key == "smsbower" and not any(
                        sub.get(k)
                        for k in (
                            "sms_service",
                            "service_code",
                            "phone_service",
                            "handler_api",
                        )
                    ):
                        # 可能是 mail-only 配置，仍可作为 key 来源
                        pass
                    return dict(sub)
            # top-level keys
            if data.get("api_key") and data.get("service"):
                return data
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return {}


class SmsbowerSmsClient:
    """Low-level SMSBower handler_api client."""

    def __init__(
        self,
        api_key: str,
        *,
        api_base: str | None = None,
        log_fn: Callable[[str], None] | None = None,
        timeout: float = 30.0,
    ):
        self.api_key = (api_key or "").strip()
        self.api_base = (
            api_base
            or _env("SMSBOWER_SMS_API_BASE")
            or _env("SMSBOWER_HANDLER_API")
            or DEFAULT_API_BASE
        ).rstrip()
        self.log = log_fn or (lambda _: None)
        self.timeout = timeout
        self._http = _direct_session()
        # 全互斥会把 60 路 export 串成一条队；改成有限并发 + 轻量节流
        try:
            conc = int(_env("SMSBOWER_SMS_HTTP_CONCURRENCY") or "12")
        except ValueError:
            conc = 12
        self._sem = threading.Semaphore(max(2, min(conc, 32)))
        self._pace_lock = threading.Lock()
        self._last_req_at = 0.0
        try:
            self._min_interval = float(_env("SMSBOWER_SMS_HTTP_MIN_INTERVAL") or "0.05")
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
        """Call handler_api. Returns raw text or parsed JSON when possible."""
        if not self.api_key:
            raise RuntimeError("SMSBower SMS api_key missing")
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
                        "user-agent": "tokenrefresh-smsbower-sms/1.0",
                    },
                    timeout=self.timeout,
                )
                text = (r.text or "").strip()
            except Exception as e:
                self.log(f"Smsbower SMS request error action={action}: {e}")
                return None
        if not text:
            return None
        # JSON responses (getServicesList / getCountries / getNumberV2 / prices)
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except Exception:
                return text
        return text

    # ── 查询 ─────────────────────────────────────────────

    def get_balance(self) -> dict[str, Any]:
        raw = self.request("getBalance")
        # ACCESS_BALANCE:123.45
        if isinstance(raw, str) and "ACCESS_BALANCE" in raw:
            try:
                bal = float(raw.split(":", 1)[1])
                return {"ok": True, "balance": bal, "raw": raw}
            except Exception:
                return {"ok": True, "raw": raw}
        return {"ok": False, "raw": raw}

    def get_services_list(self) -> dict[str, Any]:
        raw = self.request("getServicesList")
        if isinstance(raw, dict):
            services = raw.get("services") or raw.get("data") or []
            return {"ok": True, "services": services, "raw": raw}
        return {"ok": False, "raw": raw}

    def get_countries(self) -> dict[str, Any]:
        raw = self.request("getCountries")
        if isinstance(raw, (dict, list)):
            # normalize list of {id, eng, chn, rus}
            items = raw if isinstance(raw, list) else (
                raw.get("countries") or raw.get("data") or list(raw.values())
            )
            return {"ok": True, "countries": items, "raw": raw}
        return {"ok": False, "raw": raw}

    def get_prices(
        self,
        service: str = "",
        country: str | int = "",
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if service:
            params["service"] = service
        if country != "" and country is not None:
            params["country"] = country
        raw = self.request("getPrices", params)
        return {"ok": isinstance(raw, dict), "prices": raw if isinstance(raw, dict) else {}, "raw": raw}

    def get_prices_v2(
        self,
        service: str = "",
        country: str | int = "",
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if service:
            params["service"] = service
        if country != "" and country is not None:
            params["country"] = country
        raw = self.request("getPricesV2", params)
        return {"ok": isinstance(raw, dict), "prices": raw if isinstance(raw, dict) else {}, "raw": raw}

    def get_prices_v3(
        self,
        service: str = "",
        country: str | int = "",
    ) -> dict[str, Any]:
        """Per-provider price/count."""
        params: dict[str, Any] = {}
        if service:
            params["service"] = service
        if country != "" and country is not None:
            params["country"] = country
        raw = self.request("getPricesV3", params)
        return {"ok": isinstance(raw, dict), "prices": raw if isinstance(raw, dict) else {}, "raw": raw}

    def get_top_countries_by_service(self, service: str) -> dict[str, Any]:
        raw = self.request("getTopCountriesByService", {"service": service})
        return {"ok": raw is not None, "raw": raw}

    # ── 租号 / 状态 ─────────────────────────────────────

    def get_number(
        self,
        service: str,
        country: str | int,
        *,
        max_price: float | None = None,
        provider_ids: str = "",
        except_provider_ids: str = "",
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "service": service,
            "country": country,
        }
        if max_price is not None:
            params["maxPrice"] = max_price
        if provider_ids:
            params["providerIds"] = provider_ids
        if except_provider_ids:
            params["exceptProviderIds"] = except_provider_ids
        raw = self.request("getNumber", params)
        # ACCESS_NUMBER:id:phone
        if isinstance(raw, str) and raw.startswith("ACCESS_NUMBER:"):
            parts = raw.split(":")
            if len(parts) >= 3:
                aid = parts[1].strip()
                phone = _normalize_phone(parts[2])
                return {
                    "ok": True,
                    "activation_id": aid,
                    "phone": phone,
                    "raw": raw,
                }
        return {"ok": False, "error": str(raw), "raw": raw}

    def get_number_v2(
        self,
        service: str,
        country: str | int,
        *,
        max_price: float | None = None,
        provider_ids: str = "",
        except_provider_ids: str = "",
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "service": service,
            "country": country,
        }
        if max_price is not None:
            params["maxPrice"] = max_price
        if provider_ids:
            params["providerIds"] = provider_ids
        if except_provider_ids:
            params["exceptProviderIds"] = except_provider_ids
        raw = self.request("getNumberV2", params)
        if isinstance(raw, dict) and (raw.get("activationId") or raw.get("phoneNumber")):
            return {
                "ok": True,
                "activation_id": str(raw.get("activationId") or ""),
                "phone": _normalize_phone(str(raw.get("phoneNumber") or "")),
                "cost": raw.get("activationCost"),
                "country_code": raw.get("countryCode"),
                "operator": raw.get("activationOperator"),
                "raw": raw,
            }
        return {"ok": False, "error": str(raw), "raw": raw}

    def get_status(self, activation_id: str) -> dict[str, Any]:
        raw = self.request("getStatus", {"id": activation_id})
        if not isinstance(raw, str):
            return {"ok": False, "state": "unknown", "raw": raw}
        if raw.startswith("STATUS_OK:"):
            code = raw.split(":", 1)[1].strip()
            # sometimes full SMS text after code
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
        return {"ok": bool(raw), "raw": raw}


class SmsbowerSmsProvider:
    """Phone SMS provider with Getatext-compatible rent/poll/complete/cancel."""

    def __init__(
        self,
        api_key: str,
        *,
        service: str = "dr",
        country: str | int = "12",
        max_price: float = 2.0,
        provider_ids: str = "",
        except_provider_ids: str = "",
        provider_fallback: str = "",
        use_v2: bool = True,
        sms_timeout_s: float = 12.0,
        sms_poll_interval: float = 1.5,
        api_base: str | None = None,
        log_fn: Callable[[str], None] | None = None,
    ):
        self.service = str(service or "dr").strip()
        self.country = country
        self.max_price = float(max_price)
        self.provider_ids = (provider_ids or "").strip()
        self.except_provider_ids = (except_provider_ids or "").strip()
        # 主供应商无号时依次尝试（逗号分隔）；最后可再试「不限供应商」
        self.provider_fallback = (provider_fallback or "").strip()
        self.use_v2 = use_v2
        self.sms_timeout_s = max(5.0, min(float(sms_timeout_s), 60.0))
        self.sms_poll_interval = max(0.5, float(sms_poll_interval))
        self.log = log_fn or (lambda _: None)
        self.client = SmsbowerSmsClient(api_key, api_base=api_base, log_fn=self.log)

    def close(self) -> None:
        self.client.close()

    def _provider_try_list(self) -> list[str]:
        """Ordered providerId sets to try ('' = any provider)."""
        out: list[str] = []
        if self.provider_ids:
            out.append(self.provider_ids)
        for part in re.split(r"[,;\s]+", self.provider_fallback):
            p = part.strip()
            if p and p not in out:
                out.append(p)
        # 最后兜底：不限供应商（仍受 max_price/country/service 约束）
        if "" not in out:
            out.append("")
        return out or [""]

    def _rent_once(self, provider_ids: str) -> dict[str, Any]:
        if self.use_v2:
            res = self.client.get_number_v2(
                self.service,
                self.country,
                max_price=self.max_price,
                provider_ids=provider_ids,
                except_provider_ids=self.except_provider_ids,
            )
            if res.get("ok"):
                return res
            # 仅当 V2 非业务失败时再试 V1（避免 NO_NUMBERS 双打）
            err = str(res.get("error") or res.get("raw") or "")
            if "NO_NUMBERS" in err or "NO_NUMBER" in err:
                return res
            return self.client.get_number(
                self.service,
                self.country,
                max_price=self.max_price,
                provider_ids=provider_ids,
                except_provider_ids=self.except_provider_ids,
            )
        return self.client.get_number(
            self.service,
            self.country,
            max_price=self.max_price,
            provider_ids=provider_ids,
            except_provider_ids=self.except_provider_ids,
        )

    def rent(self, session: Any = None) -> dict | None:
        _ = session
        last_err = ""
        for pids in self._provider_try_list():
            label = pids or "any"
            res = self._rent_once(pids)
            if res.get("ok"):
                aid = str(res.get("activation_id") or "").strip()
                phone = str(res.get("phone") or "").strip()
                if not aid or not phone:
                    continue
                self.log(f"Smsbower SMS rent ok id={aid[:12]}... provider={label}")
                try:
                    self.client.set_status(aid, STATUS_READY)
                except Exception:
                    pass
                return {
                    "activation_id": aid,
                    "phone": phone if phone.startswith("+") else _normalize_phone(phone),
                    "raw": res.get("raw"),
                    "provider": "smsbower",
                    "provider_ids_used": label,
                }
            last_err = str(res.get("error") or res.get("raw") or "")
            self.log(f"Smsbower SMS rent fail provider={label}: {last_err[:80]}")
            if "NO_NUMBERS" not in last_err and "NO_NUMBER" not in last_err:
                # 非无号错误不必扫完所有 fallback
                break
        self.log(f"Smsbower SMS rent fail: {last_err or 'unknown'}")
        return None

    def poll(
        self,
        session: Any,
        activation_id: str,
        timeout_s: float | None = None,
    ) -> str | None:
        _ = session
        limit = float(timeout_s) if timeout_s is not None else self.sms_timeout_s
        limit = max(5.0, min(limit, 120.0))
        deadline = time.time() + limit
        interval = self.sms_poll_interval
        while time.time() < deadline:
            st = self.client.get_status(activation_id)
            if st.get("state") == "ok" and st.get("code"):
                self.log(f"Smsbower SMS code: {st['code']}")
                return str(st["code"])
            if st.get("state") in ("cancel", "no_activation"):
                return None
            remaining = deadline - time.time()
            if remaining <= 0.2:
                break
            time.sleep(min(interval, remaining))
        self.log(f"Smsbower SMS timeout after {limit:.0f}s")
        return None

    def complete(self, session: Any, activation_id: str) -> None:
        """收码后 complete（与 Getatext/VAK 同流程：释放 active 槽）。"""
        _ = session
        aid = str(activation_id or "").strip()
        if not aid:
            return
        last_err = ""
        for try_i in range(1, 4):
            r = self.client.set_status(aid, STATUS_DONE)
            if r.get("ok"):
                self.log(f"Smsbower SMS complete id={aid[:12]}... try={try_i}")
                return
            last_err = str(r.get("error") or r.get("raw") or "complete_failed")
            time.sleep(0.3 * try_i)
        raise RuntimeError(f"Smsbower complete failed id={aid[:12]}: {last_err[:160]}")

    def cancel(self, session: Any, activation_id: str) -> None:
        _ = session
        aid = str(activation_id or "").strip()
        if not aid:
            return
        last_err = ""
        for try_i in range(1, 4):
            r = self.client.set_status(aid, STATUS_CANCEL)
            if r.get("ok"):
                self.log(f"Smsbower SMS cancel id={aid[:12]}... try={try_i}")
                return
            last_err = str(r.get("error") or r.get("raw") or "cancel_failed")
            time.sleep(0.3 * try_i)
        raise RuntimeError(f"Smsbower cancel failed id={aid[:12]}: {last_err[:160]}")


def build_smsbower_sms_provider(
    sms_config: dict | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> SmsbowerSmsProvider | None:
    """Build from env / sms_config.json."""
    cfg = _load_sms_config_file()
    if isinstance(sms_config, dict):
        # allow nested
        if isinstance(sms_config.get("smsbower_sms"), dict):
            cfg.update(sms_config["smsbower_sms"])
        elif isinstance(sms_config.get("smsbower"), dict):
            cfg.update(sms_config["smsbower"])
        else:
            cfg.update(sms_config)

    api_key = (
        _env("SMSBOWER_SMS_API_KEY")
        or _env("SMSBOWER_API_KEY")
        or _env("TOKENREFRESH_SMSBOWER_API_KEY")
        or _env("smsbower2")  # 第二把 key（绑机优先可注入到 SMSBOWER_SMS_API_KEY）
        or _env("smsbower")  # project .env shorthand
        or str(cfg.get("api_key") or cfg.get("key") or "").strip()
    )
    if isinstance(cfg.get("api_keys"), list) and cfg["api_keys"] and not api_key:
        api_key = str(cfg["api_keys"][0]).strip()
    if not api_key:
        return None

    service = (
        _env("SMSBOWER_SMS_SERVICE")
        or str(cfg.get("sms_service") or cfg.get("service_code") or cfg.get("service") or "dr")
    ).strip()
    # if config is mail-only service name like long domain, fall back
    if service in ("openai", "gmail.com") or "." in service:
        service = _env("SMSBOWER_SMS_SERVICE") or "dr"

    country: str | int = _env("SMSBOWER_SMS_COUNTRY") or cfg.get("country") or "12"
    try:
        if str(country).isdigit():
            country = int(country)
    except Exception:
        pass

    max_price = _env_float(
        "SMSBOWER_SMS_MAX_PRICE",
        float(cfg.get("max_price") or cfg.get("maxPrice") or 2.0),
    )
    timeout = _env_float(
        "SMSBOWER_SMS_TIMEOUT",
        float(cfg.get("sms_timeout") or cfg.get("timeout") or 18.0),
    )
    poll_iv = _env_float(
        "SMSBOWER_SMS_POLL_INTERVAL",
        float(cfg.get("poll_interval") or 2.0),
    )
    provider_ids = _env("SMSBOWER_SMS_PROVIDER_IDS") or str(
        cfg.get("provider_ids") or cfg.get("providerIds") or ""
    )
    provider_fallback = _env("SMSBOWER_SMS_PROVIDER_FALLBACK") or str(
        cfg.get("provider_fallback") or cfg.get("fallback_providers") or ""
    )
    except_ids = _env("SMSBOWER_SMS_EXCEPT_PROVIDER_IDS") or str(
        cfg.get("except_provider_ids") or ""
    )
    use_v2 = _env("SMSBOWER_SMS_USE_V2", "1").lower() not in ("0", "false", "no")
    api_base = _env("SMSBOWER_SMS_API_BASE") or cfg.get("api_base") or cfg.get("handler_api")
    # 默认更快：12s 等码（换号循环在 phone.py）
    if not _env("SMSBOWER_SMS_TIMEOUT") and not cfg.get("sms_timeout"):
        timeout = 12.0

    return SmsbowerSmsProvider(
        api_key,
        service=service,
        country=country,
        max_price=max_price,
        provider_ids=provider_ids,
        except_provider_ids=except_ids,
        provider_fallback=provider_fallback,
        use_v2=use_v2,
        sms_timeout_s=timeout,
        sms_poll_interval=poll_iv,
        api_base=str(api_base) if api_base else None,
        log_fn=log_fn,
    )


def build_sms_provider(
    sms_config: dict | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> Any:
    """Unified phone SMS provider: prefer K12_SMS_PROVIDER / SMS_PROVIDER.

    - vak | vak-sms | vaksms → VakSmsProvider
    - hero | herosms | hero-sms → HeroSmsProvider
    - smsbower | smsbower_sms → SmsbowerSmsProvider
    - getatext → GetatextProvider
    - auto: 仅按已配置 key 探测；不改变 K12 标准流默认 geta（由 env 显式指定）
    """
    pref = (
        _env("K12_SMS_PROVIDER")
        or _env("SMS_PROVIDER")
        or _env("TOKENREFRESH_SMS_PROVIDER")
        or "auto"
    ).lower()

    if pref in ("vak", "vak-sms", "vak_sms", "vaksms", "vak-sms.com"):
        from .vak_sms import build_vak_sms_provider

        p = build_vak_sms_provider(sms_config, log_fn=log_fn)
        if p is None:
            raise RuntimeError(
                "SMS provider=vak but no API key "
                "(VAK_SMS_API_KEY / VAK_API_KEY / vak= in .env)"
            )
        return p

    if pref in ("hero", "herosms", "hero-sms", "hero_sms", "h"):
        from .hero_sms import build_hero_sms_provider

        p = build_hero_sms_provider(sms_config, log_fn=log_fn)
        if p is None:
            raise RuntimeError(
                "SMS provider=hero but no API key "
                "(HERO_SMS_API_KEY / HEROSMS_API_KEY / hero= in .env)"
            )
        return p

    if pref in ("smsbower", "smsbower_sms", "smsbower-phone", "bower"):
        p = build_smsbower_sms_provider(sms_config, log_fn=log_fn)
        if p is None:
            raise RuntimeError(
                "SMS provider=smsbower but no API key "
                "(SMSBOWER_SMS_API_KEY / SMSBOWER_API_KEY / sms_config)"
            )
        return p

    if pref in ("getatext", "gt"):
        from .getatext import build_getatext_provider

        return build_getatext_provider(sms_config, log_fn=log_fn)

    # auto
    if pref in ("auto", "", "any"):
        from .vak_sms import build_vak_sms_provider
        from .hero_sms import build_hero_sms_provider

        if (
            _env("VAK_SMS_API_KEY")
            or _env("VAK_API_KEY")
            or _env("vak")
            or (
                isinstance(sms_config, dict)
                and (sms_config.get("vak_sms") or sms_config.get("vak"))
            )
        ):
            p = build_vak_sms_provider(sms_config, log_fn=log_fn)
            if p is not None:
                return p
        if (
            _env("HERO_SMS_API_KEY")
            or _env("HEROSMS_API_KEY")
            or _env("hero")
            or _env("herosms")
            or (
                isinstance(sms_config, dict)
                and (sms_config.get("hero_sms") or sms_config.get("herosms"))
            )
        ):
            p = build_hero_sms_provider(sms_config, log_fn=log_fn)
            if p is not None:
                return p
        # explicit smsbower key → prefer smsbower
        if (
            _env("SMSBOWER_SMS_API_KEY")
            or _env("SMSBOWER_API_KEY")
            or (isinstance(sms_config, dict) and (
                sms_config.get("smsbower_sms")
                or (sms_config.get("provider") or "").lower() == "smsbower"
            ))
        ):
            p = build_smsbower_sms_provider(sms_config, log_fn=log_fn)
            if p is not None:
                return p
        from .getatext import build_getatext_provider

        p = build_getatext_provider(sms_config, log_fn=log_fn)
        if p is not None:
            return p
        p = build_vak_sms_provider(sms_config, log_fn=log_fn)
        if p is not None:
            return p
        p = build_hero_sms_provider(sms_config, log_fn=log_fn)
        if p is not None:
            return p
        return build_smsbower_sms_provider(sms_config, log_fn=log_fn)

    # unknown → try vak / hero / getatext / smsbower
    from .getatext import build_getatext_provider
    from .hero_sms import build_hero_sms_provider
    from .vak_sms import build_vak_sms_provider

    return (
        build_vak_sms_provider(sms_config, log_fn=log_fn)
        or build_hero_sms_provider(sms_config, log_fn=log_fn)
        or build_getatext_provider(sms_config, log_fn=log_fn)
        or build_smsbower_sms_provider(sms_config, log_fn=log_fn)
    )
