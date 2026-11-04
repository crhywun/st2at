"""Getatext SMS provider."""
from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Callable

from .sms_e164 import normalize_e164

GETATEXT_API_BASE = "https://getatext.com/api/v1"
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))


class GetatextProvider:
    """Short-lived Getatext phone rental provider."""

    # 全进程共享：限制同时 /rent 数，避免全串行，也避免打爆 API
    _rent_sem: threading.Semaphore | None = None
    _rent_sem_n: int = 0
    _rent_sem_lock = threading.Lock()

    def __init__(self, api_keys: list[str], max_price: float = 3.0,
                 country: str = "", operator: str = "",
                 service: str = "chatgpt",
                 poll_attempts: int = 30,
                 sms_poll_interval: float = 4.0,
                 sms_timeout_s: float | None = None,
                 rent_concurrency: int | None = None,
                 log_fn: Callable | None = None):
        self._keys = [k.strip() for k in api_keys if k and k.strip()]
        self._key_idx = 0
        self.max_price = max_price
        self.country = country
        self.operator = operator
        self.service = service
        self.poll_attempts = max(5, poll_attempts)
        self.sms_poll_interval = max(0.8, float(sms_poll_interval))
        # 总轮询预算（秒）；优先于「次数×间隔」硬顶，避免占死 export 槽
        if sms_timeout_s is None:
            try:
                sms_timeout_s = float(os.environ.get("GETATEXT_SMS_TIMEOUT") or "0") or None
            except ValueError:
                sms_timeout_s = None
        self.sms_timeout_s = float(sms_timeout_s) if sms_timeout_s and sms_timeout_s > 0 else None
        self.log = log_fn or (lambda _: None)
        self._last_status_at = 0.0
        self._throttle_lock = threading.Lock()
        # 最近一次 rent 失败原因（phone.py 可读，用于 max-rentals 退避）
        self.last_rent_error = ""
        # 全进程额度满时统一拉长等待，避免 60 路空转
        self._quota_lock = threading.Lock()
        self._quota_blocked_until = 0.0
        # 每实例本地租号串行取消；改用进程级 semaphore（见 _acquire_rent）
        if rent_concurrency is None:
            try:
                # 默认 24：配合高 workers；仍受平台 active 上限约束
                rent_concurrency = int(os.environ.get("GETATEXT_RENT_CONCURRENCY") or "24")
            except ValueError:
                rent_concurrency = 24
        self._ensure_rent_sem(max(1, min(48, int(rent_concurrency))))

    @classmethod
    def _ensure_rent_sem(cls, n: int) -> None:
        with cls._rent_sem_lock:
            if cls._rent_sem is None or cls._rent_sem_n != n:
                cls._rent_sem = threading.Semaphore(n)
                cls._rent_sem_n = n

    def _next_key(self) -> str | None:
        if not self._keys:
            return None
        key = self._keys[self._key_idx % len(self._keys)]
        self._key_idx += 1
        return key

    def _throttle(self, min_interval: float) -> None:
        with self._throttle_lock:
            wait = min_interval - (time.time() - self._last_status_at)
            if wait > 0:
                time.sleep(wait)
            self._last_status_at = time.time()

    def _call(self, session, path: str, payload: dict,
              api_key: str = "", timeout: int = 30,
              *, throttle: float | None = None) -> tuple[int, dict]:
        if api_key:
            headers = {"Auth": api_key, "Content-Type": "application/json"}
        else:
            key = self._next_key()
            if not key:
                return 0, {"error": "no_api_key"}
            headers = {"Auth": key, "Content-Type": "application/json"}

        if throttle is not None and throttle > 0:
            self._throttle(throttle)
        elif "/rental-status" in path:
            # poll() 自己 sleep；这里只做轻量防抖，避免双重 4s
            self._throttle(min(0.6, self.sms_poll_interval * 0.25))
        elif any(p in path for p in ("/rent", "/re-rent")):
            self._throttle(0.8)

        try:
            resp = session.post(
                f"{GETATEXT_API_BASE}{path}",
                headers=headers,
                json=payload,
                timeout=timeout,
                verify=False,
            )
        except Exception as e:
            # 让 cancel/rent 调用方能重试；旧逻辑吞掉异常会假装成功
            if "cancel" in path:
                raise
            return 0, {"errors": f"network: {e}"[:300]}
        try:
            data = resp.json()
            return resp.status_code, data if isinstance(data, dict) else {}
        except Exception:
            return resp.status_code, {"errors": str(getattr(resp, "text", "") or "")[:300]}

    @staticmethod
    def _err_text(data: dict | None, status: int = 0) -> str:
        if not isinstance(data, dict):
            return f"HTTP {status}"
        for k in ("errors", "error", "message", "detail"):
            v = data.get(k)
            if v is not None and str(v).strip():
                return str(v).strip()[:240]
        try:
            return json.dumps(data, ensure_ascii=False)[:240]
        except Exception:
            return f"HTTP {status}"

    @staticmethod
    def _is_max_rentals_err(err: str) -> bool:
        low = (err or "").lower()
        return (
            "maximum number of active rentals" in low
            or "max" in low and "active rental" in low
            or "too many active" in low
        )

    @staticmethod
    def _is_rate_limit_err(err: str, status: int = 0) -> bool:
        """HTTP 429 / rate limit / too many requests — 勿无限重试。"""
        if int(status or 0) == 429:
            return True
        low = (err or "").lower()
        return (
            "http 429" in low
            or low.strip().startswith("429")
            or "rate limit" in low
            or "rate-limit" in low
            or "too many requests" in low
            or "too many request" in low
        )

    def rent(self, session) -> dict | None:
        """Rent one phone number（并发上限 GETATEXT_RENT_CONCURRENCY）。

        额度满时：写 last_rent_error、进程级 cooldown，有限次退避重试，避免空转打爆。
        **HTTP 429**：立刻记 last_rent_error、短冷却后返回 None（上层 soft abort，
        不在此层空转 max_tries）。
        """
        try:
            max_tries = max(1, int(os.environ.get("GETATEXT_RENT_MAX_TRIES") or "3"))
        except ValueError:
            max_tries = 3
        try:
            cool_s = max(1.0, float(os.environ.get("GETATEXT_QUOTA_COOLDOWN_S") or "4"))
        except ValueError:
            cool_s = 4.0
        try:
            cool_429 = max(
                2.0, float(os.environ.get("GETATEXT_RENT_429_COOLDOWN_S") or "8")
            )
        except ValueError:
            cool_429 = 8.0

        sem = self._rent_sem or threading.Semaphore(1)
        self.last_rent_error = ""
        last_err = ""

        for try_i in range(1, max_tries + 1):
            # 额度满/429 全局冷却：多路 export 一起等，别每人打 6 次
            with self._quota_lock:
                wait_q = self._quota_blocked_until - time.time()
            if wait_q > 0:
                self.log(f"Getatext rent wait quota cooldown {wait_q:.1f}s")
                time.sleep(min(wait_q, cool_s * 2))

            with sem:
                got = None
                hit_429 = False
                for _ in range(len(self._keys) or 1):
                    api_key = self._next_key()
                    if not api_key:
                        last_err = "no_api_key"
                        break
                    payload = {
                        "service": self.service,
                        "max_price": float(self.max_price or 3.0),
                    }
                    if self.country:
                        payload["area_codes"] = self.country
                    if self.operator and self.operator.lower() not in (
                        "any",
                        "auto",
                        "0",
                    ):
                        payload["carrier"] = self.operator

                    status, data = self._call(
                        session,
                        "/rent-a-number",
                        payload,
                        api_key=api_key,
                        throttle=0.8,
                    )
                    if status in (200, 201) and isinstance(data, dict):
                        rid = str(data.get("id") or "").strip()
                        num = str(data.get("number") or "").strip()
                        ctry = str(
                            data.get("country")
                            or data.get("country_code")
                            or data.get("iso")
                            or self.country
                            or ""
                        ).strip()
                        if rid and num:
                            self.last_rent_error = ""
                            with self._quota_lock:
                                self._quota_blocked_until = 0.0
                            phone_e164 = self._normalize(num, country=ctry)
                            self.log(
                                f"Getatext rent: HTTP {status} id={rid[:10]}... "
                                f"raw={num} country={ctry or '-'} e164={phone_e164}"
                            )
                            got = {
                                "activation_id": rid,
                                "phone": phone_e164,
                                "country": ctry,
                                "raw_number": num,
                            }
                            break
                        last_err = "rent ok but empty id/number"
                        self.log(f"Getatext rent fail: {last_err}")
                    else:
                        last_err = self._err_text(data, status)
                        # 统一带 HTTP 码，phone.py 可识别 429 soft abort
                        if status and "http" not in last_err.lower():
                            last_err = f"HTTP {status}: {last_err}"
                        self.log(f"Getatext rent: HTTP {status} fail: {last_err[:120]}")
                        if self._is_rate_limit_err(last_err, status):
                            hit_429 = True
                            last_err = f"HTTP 429 rate-limit: {last_err[:160]}"
                            break  # 换 key 也打爆，立刻出
                        if self._is_max_rentals_err(last_err):
                            break  # 换 key 也没用，出内层
                if got:
                    return got

            self.last_rent_error = last_err or "rent_failed"
            # ★ 429：进程级短冷却 + 立即返回（禁止 max_tries 空转）
            if hit_429 or self._is_rate_limit_err(last_err):
                with self._quota_lock:
                    self._quota_blocked_until = time.time() + cool_429
                self.last_rent_error = last_err or "HTTP 429 rate-limit"
                self.log(
                    f"Getatext rent HTTP 429 → soft abort (cooldown {cool_429:.0f}s) "
                    f"no more rent tries this call"
                )
                return None
            if self._is_max_rentals_err(last_err):
                with self._quota_lock:
                    self._quota_blocked_until = time.time() + cool_s
                if try_i < max_tries:
                    sleep_s = cool_s * try_i
                    self.log(
                        f"Getatext max active rentals — backoff {sleep_s:.1f}s "
                        f"try={try_i}/{max_tries}"
                    )
                    time.sleep(sleep_s)
                    continue
            elif try_i < max_tries:
                time.sleep(min(1.5, 0.4 * try_i))
                continue
            break

        self.last_rent_error = last_err or self.last_rent_error or "rent_failed"
        return None

    def poll(
        self, session, activation_id: str, timeout_s: float | None = None
    ) -> str | None:
        """Poll until SMS code or timeout.

        - ``timeout_s`` 优先（phone.py 传入的短硬顶）
        - 否则 ``sms_timeout_s`` / ``GETATEXT_SMS_TIMEOUT``
        - 前期短间隔快扫；超时由调用方 cancel 释放队列
        """
        budget = None
        if timeout_s is not None and float(timeout_s) > 0:
            budget = float(timeout_s)
        elif self.sms_timeout_s:
            budget = float(self.sms_timeout_s)
        deadline = time.time() + budget if budget else None
        max_rounds = self.poll_attempts
        if budget is not None:
            max_rounds = min(80, max(self.poll_attempts, int(budget / 1.0) + 3))

        # 关键：必须先查码再 sleep。旧逻辑先 sleep 再查，等于从「租号后」白烧时间，
        # 还叠并发买号 → 所有号都等不到码 + 队列顶满。
        for i in range(max_rounds):
            if deadline is not None and time.time() >= deadline:
                self.log(f"Getatext SMS timeout after {budget:.0f}s")
                return None
            try:
                # 官方 API 用 id，不是 rental_id（rental_id 会 404 假成功）
                rid = activation_id
                try:
                    rid = int(str(activation_id).strip())
                except Exception:
                    pass
                status, data = self._call(
                    session,
                    "/rental-status",
                    {"id": rid},
                    throttle=0.0,
                    timeout=15,
                )
            except Exception as e:
                self.log(f"Getatext rental-status err: {e}")
                status, data = 0, {}
            if status == 200 and isinstance(data, dict):
                code = str(
                    data.get("code") or data.get("sms") or data.get("text") or ""
                ).strip()
                if code:
                    m = re.search(r"\b(\d{4,8})\b", code)
                    if m and not code.isdigit():
                        code = m.group(1)
                    self.log(f"Getatext SMS code: {code}")
                    return code
                if str(data.get("status") or "").lower() in (
                    "cancelled",
                    "expired",
                    "failed",
                ):
                    return None
            # 无码再等：前几轮密扫
            if i < 8:
                wait = min(0.8, self.sms_poll_interval)
            elif i < 20:
                wait = self.sms_poll_interval
            else:
                wait = min(2.5, self.sms_poll_interval * 1.2)
            if deadline is not None:
                wait = min(wait, max(0.1, deadline - time.time()))
            if wait > 0:
                time.sleep(wait)
        return None

    def complete(self, session, activation_id: str) -> None:
        """收码后必须 complete，否则后台一直「等待中」占 active 槽。

        官方路径（实机）：``POST /api/v1/rental-status/{id}/completed``
        （旧路径 ``/complete-rental`` 会 404 HTML，假失败仍占槽！）
        未收码时会 403 ``Cant complete this rental`` → 仅应在 poll 到码之后调用。
        """
        aid = str(activation_id or "").strip()
        if not aid:
            return
        rid: str | int = aid
        try:
            rid = int(aid)
        except Exception:
            pass
        # 路径带 id；body 可空或带 id（兼容）
        paths = [
            f"/rental-status/{rid}/completed",
            f"/rental-status/{aid}/completed",
        ]
        payloads: list[dict] = [{}, {"id": rid}]
        last_err = ""
        for try_i in range(1, 5):
            for path in paths:
                for payload in payloads:
                    try:
                        status, data = self._call(
                            session,
                            path,
                            payload,
                            timeout=20,
                            throttle=0.0,
                        )
                    except Exception as e:
                        last_err = f"network: {e}"
                        continue
                    st = ""
                    if isinstance(data, dict):
                        st = str(
                            data.get("status") or data.get("message") or ""
                        ).strip()
                    err = self._err_text(data, int(status or 0))
                    low = f"{st} {err}".lower()
                    if status and int(status) < 400:
                        self.log(
                            f"Getatext complete HTTP {status} status={st or '-'} "
                            f"path={path} id={aid[:12]}... try={try_i}"
                        )
                        return
                    if any(
                        k in low
                        for k in (
                            "already completed",
                            "already complete",
                            "completed",
                            "already finished",
                            "already cancelled",
                            "already canceled",
                            "not found",
                        )
                    ):
                        self.log(
                            f"Getatext complete already-done id={aid[:12]}... "
                            f"HTTP {status} {st or err}"
                        )
                        return
                    # 未收码：明确失败，上层不应在 poll 前 complete
                    if "cant complete" in low or "can't complete" in low:
                        last_err = f"HTTP {status}: {err}"
                        raise RuntimeError(
                            f"getatext complete too-early (no SMS yet): {err}"
                        )
                    last_err = f"HTTP {status}: {err}"
            time.sleep(0.35 * try_i)
        raise RuntimeError(
            f"getatext complete failed id={aid[:12]}: {last_err}"
        )

    def cancel(self, session, activation_id: str) -> None:
        """取消租约。

        官方文档 POST /api/v1/cancel-rental body: ``{"id": 1234}``
        （错误地用 rental_id 会 404 Rental not found，旧代码还把 not found
        当成功 → 日志 cancel ok 但后台号仍「等待中」占队列！）

        实机：租号后几秒即可 cancel，**不要**先睡 60s。
        若 API 偶发 too-early，由上层短退避重试。
        """
        aid = str(activation_id or "").strip()
        if not aid:
            return
        rid: str | int = aid
        try:
            rid = int(aid)
        except Exception:
            pass
        # 只认官方字段 id；可附带 int/string 各试一次
        payloads: list[dict] = [{"id": rid}]
        if not isinstance(rid, int):
            try:
                payloads.append({"id": int(str(rid))})
            except Exception:
                pass
        else:
            payloads.append({"id": str(rid)})

        last_err = ""
        for payload in payloads:
            try:
                status, data = self._call(
                    session,
                    "/cancel-rental",
                    payload,
                    timeout=20,
                    throttle=0.0,
                )
            except Exception as e:
                last_err = f"network: {e}"
                continue
            if status and int(status) < 400:
                st = ""
                if isinstance(data, dict):
                    st = str(data.get("status") or "")
                self.log(
                    f"Getatext cancel HTTP {status} status={st or '-'} "
                    f"id={aid[:12]}... (body uses id= NOT rental_id)"
                )
                # 2xx + cancelled/success/空 status 算成功
                if st and st.lower() not in (
                    "cancelled",
                    "canceled",
                    "success",
                    "ok",
                    "",
                ):
                    # waiting 仍出现在 cancel 响应 → 当失败重试
                    if st.lower() in ("waiting", "active", "pending", "rented"):
                        last_err = f"cancel returned still-active status={st}"
                        continue
                    last_err = f"unexpected status={st}"
                    continue
                return
            err = self._err_text(data, int(status or 0))
            low = (err or "").lower()
            # 仅「真的已取消」算成功
            if any(
                k in low
                for k in (
                    "already cancelled",
                    "already canceled",
                    "already cancel",
                )
            ):
                self.log(f"Getatext cancel already-cancelled id={aid[:12]}...")
                return
            # not found：可能已过期/已取消 — 当成功释放本地跟踪
            if "not found" in low or "rental not found" in low:
                self.log(
                    f"Getatext cancel not-found → treat released id={aid[:12]}..."
                )
                return
            # wait 1 min rule
            if "1 min" in low or "one minute" in low or (
                "wait" in low and "min" in low
            ):
                last_err = err
                raise RuntimeError(f"getatext cancel too-early: {err}")
            last_err = f"HTTP {status}: {err}"
        raise RuntimeError(f"getatext cancel failed id={aid[:12]}: {last_err}")

    @classmethod
    def _normalize(cls, number: str, country: str = "") -> str:
        """E.164 — shared with VAK/Smsbower via sms_e164.normalize_e164."""
        return normalize_e164(number, country=country)


def _load_config_file() -> dict:
    search_paths: list[str] = []
    env_config = os.environ.get("TOKENREFRESH_SMS_CONFIG", "").strip()
    if env_config:
        search_paths.append(env_config)
    search_paths.extend([
        os.path.join(os.getcwd(), "tokenrefresh_sms_config.json"),
        os.path.join(os.getcwd(), "sms_config.json"),
        os.path.join(PACKAGE_DIR, "tokenrefresh_sms_config.json"),
        os.path.join(PACKAGE_DIR, "sms_config.json"),
    ])
    for path in search_paths:
        try:
            with open(os.path.normpath(path), "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data.get("getatext", data) if isinstance(data.get("getatext", data), dict) else {}
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return {}


def _split_env_keys(raw: str) -> list[str]:
    return [k.strip() for k in str(raw or "").replace(";", ",").split(",") if k.strip()]


def build_getatext_provider(sms_config: dict | None = None,
                            log_fn: Callable | None = None) -> GetatextProvider | None:
    """Build a provider from args, env vars, or local tokenrefresh config files."""
    cfg = dict(_load_config_file())
    cfg.update(sms_config or {})

    api_keys: list[str] = []
    api_keys.extend(_split_env_keys(os.environ.get("GETATEXT_API_KEYS", "")))
    env_key = os.environ.get("GETATEXT_API_KEY", "").strip()
    if env_key:
        api_keys.insert(0, env_key)

    for key_name in ("api_key", "key", "token"):
        value = str(cfg.get(key_name) or "").strip()
        if value:
            api_keys.insert(0, value)
            break
    if isinstance(cfg.get("keys"), list):
        api_keys.extend(str(k).strip() for k in cfg["keys"] if str(k).strip())
    if isinstance(cfg.get("api_keys"), list):
        api_keys.extend(str(k).strip() for k in cfg["api_keys"] if str(k).strip())

    deduped_keys = []
    for key in api_keys:
        if key and key not in deduped_keys:
            deduped_keys.append(key)
    if not deduped_keys:
        return None

    # env 覆盖（文档里的 GETATEXT_SMS_TIMEOUT 以前未接入，现生效）
    try:
        poll_interval = float(
            os.environ.get("GETATEXT_POLL_INTERVAL")
            or cfg.get("poll_interval")
            or 2.0
        )
    except (TypeError, ValueError):
        poll_interval = 2.0
    try:
        poll_attempts = int(
            os.environ.get("GETATEXT_POLL_ATTEMPTS")
            or cfg.get("poll_attempts")
            or 24
        )
    except (TypeError, ValueError):
        poll_attempts = 24
    try:
        sms_timeout = float(
            os.environ.get("GETATEXT_SMS_TIMEOUT")
            or cfg.get("sms_timeout")
            or cfg.get("timeout")
            or 18
        )
    except (TypeError, ValueError):
        sms_timeout = 18.0
    try:
        rent_conc = int(os.environ.get("GETATEXT_RENT_CONCURRENCY") or cfg.get("rent_concurrency") or 6)
    except (TypeError, ValueError):
        rent_conc = 6

    return GetatextProvider(
        api_keys=deduped_keys,
        max_price=float(cfg.get("max_price", 3.0)),
        country=str(cfg.get("country", "")),
        operator=str(cfg.get("operator", "")),
        service=str(cfg.get("service", "chatgpt")),
        poll_attempts=poll_attempts,
        sms_poll_interval=poll_interval,
        sms_timeout_s=sms_timeout,
        rent_concurrency=rent_conc,
        log_fn=log_fn,
    )
