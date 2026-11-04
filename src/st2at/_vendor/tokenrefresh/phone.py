"""手机绑定 — Getatext / VAK-SMS / HeroSMS / SMSBower（Codex add_phone）。

硬规则：
  - add-phone HTTP 400 / suspicious behavior = **手机号风控**，与账号无关
  - 立刻 cancel 当前号 → 换号重试，不因该 400 判账号失败
"""
from __future__ import annotations

import os
import re
import threading
import time
from typing import Any

import requests

from . import constants as C
from .utils import request_with_retry, response_json, save_debug
from .getatext import GetatextProvider, build_getatext_provider
from .smsbower_sms import SmsbowerSmsProvider, build_sms_provider


def _phone_switch_max() -> int:
    # 默认 1：绑机失败本轮 soft 跳过，不换号空转；整池先跑完再迭代
    # 需要换号时显式 K12_PHONE_SWITCH_MAX=2+
    try:
        return max(
            1,
            int(
                os.environ.get("K12_PHONE_SWITCH_MAX")
                or os.environ.get("PHONE_NUMBER_SWITCH_MAX")
                or "1"
            ),
        )
    except ValueError:
        return 1


def _phone_no_retry_this_round() -> bool:
    """绑机任一步失败 → 立刻 soft abort，禁止本号再 rent/换号。默认开。"""
    return (os.environ.get("K12_PHONE_NO_RETRY") or "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _soft_skip_bind(msg: str) -> RuntimeError:
    return RuntimeError(
        f"phone bind soft: {msg} — skip this round (no retry, process next account)"
    )


def _phone_risk_pause_s() -> float:
    try:
        return max(0.0, float(os.environ.get("K12_PHONE_RISK_PAUSE_S") or "0.25"))
    except ValueError:
        return 0.25


def _is_phone_risk_error(status_code: int, err_msg: str) -> bool:
    """OpenAI 拒号：换号，不换号就失败账号。"""
    # 会话死了不是号问题 — 换号无意义
    if _is_session_dead_error(status_code, err_msg):
        return False
    if status_code in (400, 403, 429):
        low = (err_msg or "").lower()
        keys = (
            "suspicious",
            "detected",
            "not valid",
            "invalid phone",
            "phone number",
            "unable to send",
            "try a different",
            "different number",
            "banned",
            "blocked",
            "risk",
            "disallowed",
        )
        if any(k in low for k in keys):
            return True
        # 裸 400 在 add-phone 场景多数也是号问题
        if status_code == 400:
            return True
    return False


def _is_session_dead_error(status_code: int, err_msg: str) -> bool:
    """登录态失效：禁止继续租号换绑，立刻 abort（否则 4 次 409 白烧槽位）。

    典型：HTTP 409 Your sign-in session is no longer valid. Please start over.
    """
    low = (err_msg or "").lower()
    if any(
        k in low
        for k in (
            "no longer valid",
            "sign-in session",
            "signin session",
            "session is no longer",
            "start over to continue",
            "please start over",
            "not authenticated",
            "login required",
            "unauthorized",
            "authentication required",
        )
    ):
        return True
    # add-phone 场景 401/409 几乎全是会话问题（不是号码质量）
    if int(status_code or 0) in (401, 409):
        return True
    return False


def _sms_provider_kind(sms_provider: Any) -> str:
    name = type(sms_provider).__name__.lower()
    if isinstance(sms_provider, GetatextProvider) or "getatext" in name:
        return "getatext"
    if "vak" in name:
        return "vak"
    if "hero" in name:
        return "hero"
    if "smsbower" in name:
        return "smsbower"
    return "other"


def _phone_otp_timeout_s(sms_provider: Any) -> float:
    """等验证码硬顶（秒）。**Getatext / VAK 同一套标准**。

    优先级：
      1) K12_PHONE_OTP_TIMEOUT_S / PHONE_OTP_TIMEOUT_S（平台无关）
      2) 平台 env：GETATEXT_SMS_TIMEOUT / VAK_SMS_TIMEOUT / HERO_SMS_TIMEOUT / SMSBOWER_SMS_TIMEOUT
      3) provider.sms_timeout_s
      4) 默认 30s（收码后 complete，超时立刻 cancel）
    """
    for key in ("K12_PHONE_OTP_TIMEOUT_S", "PHONE_OTP_TIMEOUT_S"):
        raw = (os.environ.get(key) or "").strip()
        if raw:
            try:
                return max(8.0, min(float(raw), 90.0))
            except ValueError:
                pass
    kind = _sms_provider_kind(sms_provider)
    env_keys = {
        "getatext": "GETATEXT_SMS_TIMEOUT",
        "vak": "VAK_SMS_TIMEOUT",
        "hero": "HERO_SMS_TIMEOUT",
        "smsbower": "SMSBOWER_SMS_TIMEOUT",
    }
    ek = env_keys.get(kind)
    if ek:
        raw = (os.environ.get(ek) or "").strip()
        if raw:
            try:
                return max(8.0, min(float(raw), 90.0))
            except ValueError:
                pass
    try:
        v = getattr(sms_provider, "sms_timeout_s", None)
        if v is not None and float(v) > 0:
            return max(8.0, min(float(v), 90.0))
    except Exception:
        pass
    return 30.0  # Getatext / VAK 统一默认


# 进程内 cancel 失败的 id：下次额度满时再冲一次，避免坏号永远占坑
_pending_cancel_ids: list[tuple[Any, str]] = []
_pending_cancel_lock = threading.Lock()

# 全进程 live 租约表：无码/风控/异常/进程退出时必须 cancel（Getatext 不 cancel 会一直「等待中」）
# key=activation_id → (provider, rented_at, reason_tag)
_live_rentals: dict[str, tuple[Any, float, str]] = {}
_live_rentals_lock = threading.Lock()
_cancel_watchdog_started = False

# 全进程同时「持号」上限：Getatext 额度极紧，禁止 24 路一起 rent 把队列买爆
_phone_hold_sem: threading.Semaphore | None = None
_phone_hold_sem_n = 0
_phone_hold_lock = threading.Lock()


def _track_live_rental(sms_provider: Any, activation_id: str, *, tag: str = "") -> None:
    aid = str(activation_id or "").strip()
    if not aid or sms_provider is None:
        return
    with _live_rentals_lock:
        _live_rentals[aid] = (sms_provider, time.time(), tag or "held")
    _ensure_cancel_watchdog()


def _untrack_live_rental(activation_id: str) -> None:
    aid = str(activation_id or "").strip()
    if not aid:
        return
    with _live_rentals_lock:
        _live_rentals.pop(aid, None)


def _cancel_all_live_rentals(reason: str = "shutdown") -> int:
    """进程退出/紧急：取消所有仍持有的 Getatext/SMS 租约。"""
    with _live_rentals_lock:
        items = list(_live_rentals.items())
        _live_rentals.clear()
    n = 0
    for aid, (prov, rented_at, tag) in items:
        try:
            if _safe_cancel(
                prov,
                None,
                aid,
                log_fn=None,
                reason=f"{reason}:{tag}",
                rented_at=rented_at,
            ):
                n += 1
            else:
                _remember_cancel_fail(prov, aid)
        except Exception:
            try:
                _remember_cancel_fail(prov, aid)
            except Exception:
                pass
    return n


def _ensure_cancel_watchdog() -> None:
    """后台：超时未 complete 的租约强制 cancel（防无码/卡死占 active）。"""
    global _cancel_watchdog_started
    with _live_rentals_lock:
        if _cancel_watchdog_started:
            return
        _cancel_watchdog_started = True

    def _loop() -> None:
        try:
            max_hold = float(os.environ.get("K12_PHONE_MAX_HOLD_S") or "90")
        except ValueError:
            max_hold = 90.0
        max_hold = max(35.0, min(180.0, max_hold))
        while True:
            time.sleep(8.0)
            now = time.time()
            stale: list[tuple[str, Any, float, str]] = []
            with _live_rentals_lock:
                for aid, (prov, t0, tag) in list(_live_rentals.items()):
                    if now - float(t0) >= max_hold:
                        stale.append((aid, prov, float(t0), tag))
                        _live_rentals.pop(aid, None)
            for aid, prov, t0, tag in stale:
                try:
                    _safe_cancel(
                        prov,
                        None,
                        aid,
                        log_fn=lambda m: None,
                        reason=f"watchdog-stale-{tag}",
                        rented_at=t0,
                    )
                except Exception:
                    try:
                        _remember_cancel_fail(prov, aid)
                    except Exception:
                        pass
            # 顺带冲刷 pending cancel
            try:
                flush_pending_cancels(log_fn=None)
            except Exception:
                pass

    th = threading.Thread(target=_loop, name="sms-cancel-watchdog", daemon=True)
    th.start()
    try:
        import atexit

        atexit.register(lambda: _cancel_all_live_rentals("atexit"))
    except Exception:
        pass


def _phone_hold_limit(sms_provider: Any) -> int:
    """同时持号/绑机上限。

    Getatext 过高会打满 active rentals；过低（旧默认 3、硬顶 8）会把多 worker 串行化。
    默认 16，硬顶 48；可用 SMS_RENT_CONCURRENCY / GETATEXT_RENT_CONCURRENCY 覆盖。
    """
    try:
        shared = (
            os.environ.get("SMS_RENT_CONCURRENCY")
            or os.environ.get("K12_SMS_RENT_CONCURRENCY")
            or ""
        ).strip()
        if shared:
            return max(1, min(48, int(shared)))
        kind = _sms_provider_kind(sms_provider)
        if kind == "getatext":
            return max(
                1,
                min(48, int(os.environ.get("GETATEXT_RENT_CONCURRENCY") or "16")),
            )
        if kind == "vak":
            return max(
                1,
                min(
                    32,
                    int(
                        os.environ.get("VAK_SMS_RENT_CONCURRENCY")
                        or os.environ.get("VAK_SMS_HTTP_CONCURRENCY")
                        or "12"
                    ),
                ),
            )
        if kind == "hero":
            return max(
                1,
                min(
                    12,
                    int(
                        os.environ.get("HERO_SMS_RENT_CONCURRENCY")
                        or os.environ.get("HERO_SMS_HTTP_CONCURRENCY")
                        or "6"
                    ),
                ),
            )
        if kind == "smsbower":
            return max(
                1,
                min(
                    8,
                    int(os.environ.get("SMSBOWER_SMS_HTTP_CONCURRENCY") or "4"),
                ),
            )
        return 3
    except ValueError:
        return 3


def _safe_complete(
    sms_provider: Any,
    sms_session: Any,
    activation_id: str,
    *,
    log_fn: Any = None,
    reason: str = "",
) -> bool:
    """收码后立刻 complete，释放接码平台「等待中/active」占位（Getatext/VAK 同流程）。"""
    if not activation_id or sms_provider is None:
        return True
    log = log_fn or (lambda _m: None)
    if not hasattr(sms_provider, "complete"):
        return False
    last_err = ""
    for i in range(1, 5):
        try:
            sess = sms_session
            fresh = None
            if i >= 2 or sess is None:
                fresh = requests.Session()
                fresh.verify = False
                sess = fresh
            try:
                sms_provider.complete(sess, activation_id)
            finally:
                if fresh is not None:
                    try:
                        fresh.close()
                    except Exception:
                        pass
            log(
                f"[sms] complete ok id={str(activation_id)[:12]}... "
                f"try={i}/4 reason={reason or '-'}"
            )
            return True
        except Exception as e:
            last_err = str(e)
            time.sleep(0.35 * i)
    log(
        f"[sms] complete FAIL id={str(activation_id)[:12]}... "
        f"reason={reason or '-'} err={last_err[:140]} — will try cancel"
    )
    # complete 失败：至少 cancel，别让号永远占坑
    return _safe_cancel(
        sms_provider,
        sms_session,
        activation_id,
        log_fn=log_fn,
        reason=f"complete-fail-fallback-cancel:{reason}",
    )


def _acquire_phone_hold(sms_provider: Any) -> threading.Semaphore:
    global _phone_hold_sem, _phone_hold_sem_n
    n = _phone_hold_limit(sms_provider)
    with _phone_hold_lock:
        if _phone_hold_sem is None or _phone_hold_sem_n != n:
            _phone_hold_sem = threading.Semaphore(n)
            _phone_hold_sem_n = n
        return _phone_hold_sem


def _remember_cancel_fail(sms_provider: Any, activation_id: str) -> None:
    aid = str(activation_id or "").strip()
    if not aid or sms_provider is None:
        return
    with _pending_cancel_lock:
        _pending_cancel_ids.append((sms_provider, aid))
        # 只留最近 40 个，防泄漏
        if len(_pending_cancel_ids) > 40:
            del _pending_cancel_ids[:-40]


def flush_pending_cancels(log_fn: Any = None) -> int:
    """额度满或绑机开始前：冲刷 cancel 失败的租约。"""
    log = log_fn or (lambda _m: None)
    with _pending_cancel_lock:
        items = list(_pending_cancel_ids)
        _pending_cancel_ids.clear()
    if not items:
        return 0
    n_ok = 0
    sess = requests.Session()
    sess.verify = False
    try:
        for prov, aid in items:
            try:
                if _safe_cancel(
                    prov, sess, aid, log_fn=log, reason="flush-pending-cancel"
                ):
                    n_ok += 1
            except Exception:
                _remember_cancel_fail(prov, aid)
    finally:
        try:
            sess.close()
        except Exception:
            pass
    if n_ok:
        log(f"[sms] flushed pending cancels ok~={n_ok}/{len(items)}")
    return n_ok


def _safe_cancel(
    sms_provider: Any,
    sms_session: Any,
    activation_id: str,
    *,
    log_fn: Any = None,
    reason: str = "",
    rented_at: float | None = None,
) -> bool:
    """取消租号；失败多轮重试 + 换 session，尽量释放 active rental。

    拒号必须立刻 cancel，**禁止**先傻等 60s。
    若 API 偶发太早失败，再短退避重试（默认 2s 起，可 env 覆盖）。

    rented_at 仅用于日志/可选最小冷却，默认 0（立即 cancel）。
    GETATEXT_CANCEL_MIN_AGE_S：极少数字段才需要（默认 0）。

    返回 True=取消成功。失败会记入 pending 队列供后续 flush。
    """
    if not activation_id or sms_provider is None:
        return True
    log = log_fn or (lambda _m: None)
    last_err = ""
    is_gt = isinstance(sms_provider, GetatextProvider) or (
        "getatext" in type(sms_provider).__name__.lower()
    )
    # 默认 0：秒级可取消，拒号立刻打 cancel。仅 API 明确要求时再设 min age。
    min_age = 0.0
    if is_gt:
        try:
            min_age = float(
                os.environ.get("GETATEXT_CANCEL_MIN_AGE_S")
                or os.environ.get("SMS_CANCEL_MIN_AGE_S")
                or "0"
            )
        except Exception:
            min_age = 0.0
        min_age = max(0.0, min(min_age, 30.0))  # 硬顶 30s，绝不再锁死 60s
    if is_gt and rented_at is not None and min_age > 0:
        wait_need = min_age - (time.time() - float(rented_at))
        if wait_need > 0.2:
            log(
                f"[sms] Getatext cancel min-age wait {wait_need:.1f}s "
                f"(GETATEXT_CANCEL_MIN_AGE_S={min_age:g}) id={str(activation_id)[:12]}..."
            )
            time.sleep(min(wait_need, min_age))

    for i in range(1, 8):
        try:
            sess = sms_session
            fresh = None
            if i >= 2 or sess is None:
                fresh = requests.Session()
                fresh.verify = False
                sess = fresh
            try:
                sms_provider.cancel(sess, activation_id)
            finally:
                if fresh is not None:
                    try:
                        fresh.close()
                    except Exception:
                        pass
            log(
                f"[sms] cancel ok id={str(activation_id)[:12]}... "
                f"try={i}/7 reason={reason or '-'}"
            )
            _untrack_live_rental(activation_id)
            # Getatext：再查一次 status，确认不是仍 waiting
            if is_gt:
                try:
                    _verify_getatext_cancelled(sms_provider, sess, activation_id, log)
                except Exception as ve:
                    log(
                        f"[sms] cancel verify warn id={str(activation_id)[:12]}... "
                        f"{ve}"
                    )
            return True
        except Exception as e:
            last_err = str(e)
            low = last_err.lower()
            # 仅当 API 明确说太早：短退避（2~5s），不是 15s/60s
            if is_gt and (
                "too-early" in low
                or "1 min" in low
                or "one minute" in low
                or ("wait" in low and "min" in low)
                or "too soon" in low
                or "try again" in low
            ):
                backoff = min(5.0, 1.5 + i * 0.5)
                log(
                    f"[sms] cancel too-early, sleep {backoff:.1f}s then retry "
                    f"id={str(activation_id)[:12]}..."
                )
                time.sleep(backoff)
                continue
            time.sleep(min(2.0, 0.35 * i))
    log(
        f"[sms] cancel FAIL id={str(activation_id)[:12]}... "
        f"reason={reason or '-'} err={last_err[:140]} — queued for flush"
    )
    _remember_cancel_fail(sms_provider, activation_id)
    return False


def _verify_getatext_cancelled(
    sms_provider: Any, session: Any, activation_id: str, log_fn: Any
) -> None:
    """cancel 后抽查 rental-status；若仍 waiting 再 cancel 一次。"""
    log = log_fn or (lambda _m: None)
    if not hasattr(sms_provider, "_call"):
        return
    rid: str | int = str(activation_id).strip()
    try:
        rid = int(str(activation_id).strip())
    except Exception:
        pass
    try:
        st, data = sms_provider._call(
            session,
            "/rental-status",
            {"id": rid},
            throttle=0.0,
            timeout=12,
        )
    except Exception as e:
        log(f"[sms] cancel verify status err: {e}")
        return
    status = ""
    if isinstance(data, dict):
        status = str(data.get("status") or "").lower()
    log(
        f"[sms] cancel verify id={str(activation_id)[:12]}... "
        f"HTTP {st} status={status or '-'}"
    )
    if status in ("waiting", "active", "pending", "in_progress", "rented"):
        log(
            f"[sms] STILL ACTIVE after cancel → force cancel again "
            f"id={str(activation_id)[:12]}... status={status}"
        )
        try:
            sms_provider.cancel(session, activation_id)
        except Exception as e2:
            log(f"[sms] force re-cancel err: {e2}")
            raise


def bind_phone_in_session(
    refresher,
    email: str,
    account_id: str = "",
    sms_provider: Any = None,
) -> dict:
    """
    在已登录的 session 中绑定手机号。
    要求 session 已到达 Codex OAuth 的 add_phone 页面。

    手机号风控（suspicious / add-phone 400）：cancel → 立刻换号，最多 K12_PHONE_SWITCH_MAX 次。
    会话失效（add-phone 409 session no longer valid）：**立刻 abort**，禁止连租 4 号白烧。
    """
    if sms_provider is None:
        pref = (
            os.environ.get("K12_SMS_PROVIDER")
            or os.environ.get("SMS_PROVIDER")
            or "auto"
        ).strip().lower()
        try:
            sms_provider = build_sms_provider(log_fn=refresher._log)
        except Exception as e:
            # 显式指定 vak/hero/smsbower 时禁止静默掉回 Getatext
            if pref in ("", "auto", "any", "getatext", "gt"):
                try:
                    sms_provider = build_getatext_provider(log_fn=refresher._log)
                except Exception:
                    raise RuntimeError(f"SMS provider build failed: {e}") from e
            else:
                raise RuntimeError(
                    f"SMS provider={pref} build failed: {e}"
                ) from e

    if sms_provider is None:
        raise RuntimeError(
            "No SMS provider configured. Set VAK_SMS_API_KEY / vak= or "
            "HERO_SMS_API_KEY / hero= or GETATEXT_API_KEY or SMSBOWER_SMS_API_KEY "
            "(K12_SMS_PROVIDER=getatext|vak|hero|smsbower|auto)"
        )
    try:
        refresher._log(f"[sms] using {type(sms_provider).__name__}")
    except Exception:
        pass

    sms_session = requests.Session()
    sms_session.verify = False
    max_switch = _phone_switch_max()
    last_err = ""
    tried_phones: list[str] = []
    # 当前持有的租约：任何失败路径 + finally 必须 cancel，否则占 active rental
    held_activation_id = ""
    held_rented_at = 0.0
    bind_ok = False

    rent_quota_hits = 0
    log_fn = getattr(refresher, "_log", None) or (lambda _m: None)
    # 全局持号闸：同一时刻只允许少量 rent，避免队列买满导致全家无码
    # ★ 关键：oauth 落地 add_phone 后才 acquire → 排队等待会让 auth flow 过期 → send 409。
    # 拿到闸后若等了太久，必须在租号前 re-oauth 刷新 flow（且不 document-open）。
    hold_sem = _acquire_phone_hold(sms_provider)
    _hold_wait_t0 = time.time()
    hold_sem.acquire()
    hold_wait_s = time.time() - _hold_wait_t0
    try:
        # 开绑前先冲刷之前 cancel 失败的 id，给队列腾位
        flush_pending_cancels(log_fn=log_fn)
        refresher._log(
            f"[sms] phone-hold acquired wait={hold_wait_s:.1f}s "
            f"limit={_phone_hold_limit(sms_provider)}"
        )

        for attempt in range(1, max_switch + 1):
            # 新一轮前若上一号还挂着（理论上不应），先砍掉
            if held_activation_id:
                _safe_cancel(
                    sms_provider,
                    sms_session,
                    held_activation_id,
                    log_fn=log_fn,
                    reason="pre-next-attempt-cleanup",
                    rented_at=held_rented_at or None,
                )
                held_activation_id = ""
                held_rented_at = 0.0

            # ★ 绑机 send 策略（2026-07-27 实测）：
            # - 「收不到验证码」假象：OpenAI send 409 会话死，码根本没发出。
            # - 真 OTP 路径：send HTTP 200 → Getatext 秒级出码。
            # - 主因：oauth 落地后在 hold 闸排队，auth flow TTL 很短 → 409。
            # - 拿到 hold 后：若排队过久(>1.5s)或 attempt>1 → 先 re-oauth（无 doc）
            #   再 rent → 立刻 send；排队很短则沿用外层 oauth flow 直接 rent+send。
            from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout

            def _rent_on_side() -> Any:
                rs = requests.Session()
                rs.verify = False
                try:
                    return sms_provider.rent(rs)
                finally:
                    try:
                        rs.close()
                    except Exception:
                        pass

            def _reopen_add_phone_flow() -> None:
                """刷新 add_phone：优先 bindphone.har 邮箱 OTP 路径（可 send 200）。"""
                from .web import establish_add_phone_via_email_otp

                refresher._log(
                    "[sms] re-open add_phone via email-otp "
                    "(bindphone.har path under hold)"
                )
                st = establish_add_phone_via_email_otp(
                    refresher,
                    email,
                    account_id=account_id or "",
                    mail_url=f"msoauth://{email.strip().lower()}",
                    password="",
                )
                status = str((st or {}).get("_status") or "")
                if status == "add_phone":
                    refresher._log(
                        "[sms] email-otp landed add_phone — ready to rent+send"
                    )
                    try:
                        refresher._last_codex_oauth = st  # type: ignore[attr-defined]
                    except Exception:
                        pass
                    return
                if (st or {}).get("access_token") and (st or {}).get("refresh_token"):
                    refresher._log(
                        f"[sms] email-otp path got tokens without add_phone "
                        f"status={status or 'tokens'}"
                    )
                    try:
                        refresher._last_codex_oauth = st  # type: ignore[attr-defined]
                    except Exception:
                        pass
                    raise RuntimeError("PHONE_BIND_SKIP_ALREADY_TOKENIZED")
                raise RuntimeError(
                    f"session dead email-otp path status={status or '-'} "
                    f"— re-login required (not phone quality)"
                )

            # 仅检查本地标记，不发 HTTP（避免 RTT + 弄脏 auth cookies）
            if getattr(refresher, "oauth_denied", False) or getattr(
                refresher, "_oauth_denied", False
            ):
                raise RuntimeError(
                    "session dead before phone rent (oauth_denied) — re-login required"
                )

            # 拿 hold 后：默认 **不** 清 cookie 重走邮箱 OTP（对齐 31 日完整 oauth HAR：
            # session/select → add_phone → add-phone/send，400 只换号）。
            # 仅 K12_PHONE_FORCE_EMAIL_OTP_REFRESH=1 才 re-open email-otp。
            skip_refresh = (
                os.environ.get("K12_PHONE_SKIP_EMAIL_OTP_REFRESH") or "1"
            ).strip().lower() not in ("0", "false", "no", "off")
            force_refresh = (
                os.environ.get("K12_PHONE_FORCE_EMAIL_OTP_REFRESH") or ""
            ).strip().lower() in ("1", "true", "yes", "on")
            outer_path = ""
            try:
                outer_path = str(
                    ((getattr(refresher, "_last_codex_oauth", None) or {})
                     .get("_oauth") or {})
                    .get("path")
                    or ""
                )
            except Exception:
                outer_path = ""
            need_refresh = bool(force_refresh)
            if not need_refresh:
                refresher._log(
                    f"[sms] HAR path: keep session/select add_phone "
                    f"(hold={hold_wait_s:.1f}s path={outer_path or 'outer'}) "
                    f"→ rent+send; 400 will switch number"
                )
            if need_refresh:
                try:
                    _reopen_add_phone_flow()
                    hold_wait_s = 0.0
                except RuntimeError as pe:
                    if "PHONE_BIND_SKIP_ALREADY_TOKENIZED" in str(pe):
                        st = getattr(refresher, "_last_codex_oauth", None) or {}
                        return {
                            "phone": "",
                            "activation_id": "",
                            "payload": st,
                            "status": "already_tokenized",
                            "sms_provider": type(sms_provider).__name__,
                            "phone_attempts": attempt,
                            "tokens": st,
                        }
                    raise RuntimeError(
                        f"session dead before rent (email-otp): {pe} "
                        f"— re-login required (not phone quality)"
                    ) from pe

            rental = None
            rented_at = time.time()
            with ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(_rent_on_side)
                try:
                    rental = fut.result(timeout=28.0)
                except FutTimeout:
                    last_err = "rent timeout 28s"
                    refresher._log(f"[sms] {last_err}")
                    rental = None
                except Exception as rent_ex:
                    refresher._log(f"[sms] rent err: {rent_ex}")
                    rental = None
                rented_at = time.time()

            if not rental:
                prov_err = str(
                    getattr(sms_provider, "last_rent_error", "") or ""
                ).strip()
                last_err = (
                    f"Failed to rent phone number"
                    + (f": {prov_err}" if prov_err else "")
                )
                refresher._log(
                    f"[sms] rent fail attempt={attempt}/{max_switch} — {last_err[:160]}"
                )
                low = prov_err.lower()
                # ★ HTTP 429 / rate-limit：soft abort，禁止换号循环 / 无限重试
                if (
                    "http 429" in low
                    or "rate-limit" in low
                    or "rate limit" in low
                    or "too many requests" in low
                    or re.search(r"\b429\b", low)
                ):
                    rent_quota_hits += 1
                    flush_pending_cancels(log_fn=log_fn)
                    refresher._log(
                        "[sms] rent HTTP 429 rate-limit → SOFT abort phone bind "
                        f"(free exp slot, no number switch) hits={rent_quota_hits}"
                    )
                    raise RuntimeError(
                        f"phone bind soft: rent HTTP 429 rate-limit "
                        f"(no pack re-rent): {prov_err[:160]}"
                    )
                if (
                    "maximum number of active rentals" in low
                    or ("active rental" in low and "max" in low)
                    or "max retries exceeded" in low
                    or "network:" in low
                ):
                    # 额度满/网络挂：立刻 abort 腾 exp 槽，勿循环占位
                    rent_quota_hits += 1
                    flush_pending_cancels(log_fn=log_fn)
                    refresher._log(
                        "[sms] rent quota/network fail → abort phone bind "
                        f"(free exp slot) hits={rent_quota_hits}"
                    )
                    raise RuntimeError(
                        f"phone bind soft: rent unavailable "
                        f"(quota/network): {prov_err[:160]}"
                    )
                time.sleep(min(0.5, 0.15 * attempt))
                continue
            rent_quota_hits = 0

            phone = str(rental.get("phone") or "").strip()
            activation_id = str(rental.get("activation_id") or "").strip()
            if not phone or not activation_id:
                last_err = "rent returned empty phone/id"
                if activation_id:
                    _safe_cancel(
                        sms_provider,
                        sms_session,
                        activation_id,
                        log_fn=log_fn,
                        reason="empty-phone",
                        rented_at=rented_at,
                    )
                continue
            ctry = str(
                rental.get("country")
                or rental.get("country_used")
                or ""
            ).strip()
            try:
                from .sms_e164 import normalize_e164

                phone = normalize_e164(phone, country=ctry)
            except Exception:
                if not phone.startswith("+"):
                    digits = re.sub(r"\D", "", phone)
                    phone = f"+{digits}" if digits else phone
            digits_only = re.sub(r"\D", "", phone)
            if phone.startswith("+") and len(digits_only) == 10:
                phone = f"+1{digits_only}"
                refresher._log(
                    f"[sms] phone looked national-10 → force E.164 {phone}"
                )

            held_activation_id = activation_id
            held_rented_at = rented_at
            tried_phones.append(phone)
            _track_live_rental(
                sms_provider, activation_id, tag=f"bind:{email[:24]}"
            )
            refresher._log(
                f"Phone rented attempt={attempt}/{max_switch} "
                f"id={activation_id[:12]}... phone={phone} "
                f"via {type(sms_provider).__name__} "
                f"→ IMMEDIATE send (flow refreshed={need_refresh})"
            )

            # ★ 关键：租到号后零额外导航，立刻 POST send
            # bindphone.har 成功 send：**无** openai-sentinel-token / oai-device-id；
            # body 仅 {"phone_number","channel":"sms"}；referer=/add-phone。
            # 乱塞 sentinel 可能直接 409 invalid_state。
            headers = refresher._json_headers(f"{C.AUTH_BASE}/add-phone")
            force_sentinel = (
                os.environ.get("K12_PHONE_SEND_SENTINEL") or ""
            ).strip().lower() in ("1", "true", "yes", "on")
            if force_sentinel:
                try:
                    from .utils import apply_sentinel_headers

                    apply_sentinel_headers(
                        headers,
                        refresher.session,
                        refresher.device_id,
                        "add_phone_send",
                        profile=getattr(refresher, "fingerprint_profile", None),
                    )
                except Exception as se:
                    refresher._log(f"[sms] sentinel soft-fail (send without): {se}")
            # 诊断：HAR 成功路径依赖 login_session + oai-client-auth-session
            # curl_cffi Cookies 迭代产出的是 **名字 str**，不是 Cookie 对象
            try:
                jar = getattr(refresher.session, "cookies", None)
                names: set[str] = set()
                if jar is not None:
                    try:
                        names |= {str(k) for k in jar.keys()}  # type: ignore[attr-defined]
                    except Exception:
                        pass
                    try:
                        for c in jar:
                            if isinstance(c, str):
                                names.add(c)
                            else:
                                n = str(getattr(c, "name", "") or "").strip()
                                if n:
                                    names.add(n)
                    except Exception:
                        pass
                    try:
                        gd = jar.get_dict()  # type: ignore[attr-defined]
                        if isinstance(gd, dict):
                            names |= {str(k) for k in gd.keys()}
                    except Exception:
                        pass
                need = (
                    "login_session",
                    "oai-client-auth-session",
                    "oai-client-auth-info",
                    "auth-session-minimized",
                    "oai-did",
                )
                present = [n for n in need if n in names]
                missing = [n for n in need if n not in names]
                # 额外：get 值长度（确认非空）
                lens = {}
                if jar is not None:
                    for n in need:
                        try:
                            v = jar.get(n)  # type: ignore[attr-defined]
                            lens[n] = len(str(v or ""))
                        except Exception:
                            lens[n] = -1
                refresher._log(
                    f"[sms] pre-send cookies present={present} missing={missing} "
                    f"jar_n={len(names)} lens={lens} "
                    f"sentinel={'on' if force_sentinel else 'off'}"
                )
            except Exception as ce:
                refresher._log(f"[sms] pre-send cookie probe fail: {ce}")
            # HAR 成功 body：phone_number + channel=sms（其余作兜底）
            send_bodies = [
                {"phone_number": phone, "channel": "sms"},
                {"phone_number": phone},
                {"phone": phone, "channel": "sms"},
                {"phone": phone},
            ]
            resp, err = None, ""
            for bi, body in enumerate(send_bodies):
                resp, err = request_with_retry(
                    refresher.session,
                    "post",
                    f"{C.AUTH_BASE}/api/accounts/add-phone/send",
                    json_data=body,
                    headers=headers,
                    verify=False,
                    timeout=15,
                    retry_attempts=1,
                )
                st_try = int(getattr(resp, "status_code", 0) or 0) if resp else 0
                if resp is not None and st_try == 200:
                    refresher._log(
                        f"[sms] add-phone/send OK body#{bi} keys={list(body.keys())}"
                    )
                    break
                if resp is not None and st_try == 409:
                    # 会话死：换 body 无意义
                    break
                if resp is None or st_try in (404, 405):
                    continue
                # 400 风控：换 body 也没用，交给外层
                if st_try == 400:
                    break
            if resp is None or getattr(resp, "status_code", 0) in (404, 405):
                resp, err = request_with_retry(
                    refresher.session,
                    "post",
                    f"{C.AUTH_BASE}/api/accounts/add-phone",
                    json_data={"phone": phone},
                    headers=headers,
                    verify=False,
                    timeout=20,
                    retry_attempts=1,
                )

            if resp is None:
                _safe_cancel(
                    sms_provider,
                    sms_session,
                    activation_id,
                    log_fn=log_fn,
                    reason="add-phone-request-fail",
                    rented_at=rented_at,
                )
                held_activation_id = ""
                held_rented_at = 0.0
                last_err = f"add-phone failed: {err}"
                if _phone_no_retry_this_round() or attempt >= max_switch:
                    raise _soft_skip_bind(last_err)
                refresher._log(f"[sms] {last_err} — switch number")
                continue

            add_payload = response_json(resp)
            status_code = int(getattr(resp, "status_code", 0) or 0)
            save_debug(
                email,
                "phone_send",
                add_payload,
                status_code=status_code,
                extra={"phone": phone, "attempt": attempt},
            )
            refresher._log(f"Phone SMS sent: HTTP {status_code} attempt={attempt}")

            err_msg = ""
            try:
                err_msg = str(
                    (add_payload.get("error") or {}).get("message") or add_payload
                )[:300]
            except Exception:
                err_msg = str(add_payload)[:300]

            if status_code >= 400:
                # 必须真正 cancel 成功（Getatext 用 id=）
                cancelled = _safe_cancel(
                    sms_provider,
                    sms_session,
                    activation_id,
                    log_fn=log_fn,
                    reason=f"add-phone-http-{status_code}",
                    rented_at=rented_at,
                )
                held_activation_id = ""
                held_rented_at = 0.0
                last_err = f"add-phone HTTP {status_code}: {err_msg}"

                _untrack_live_rental(activation_id)
                try:
                    flush_pending_cancels(log_fn=log_fn)
                except Exception:
                    pass
                # ★ 默认本轮不换号：soft 跳过，腾 exp 槽先跑整池
                if _phone_no_retry_this_round() or attempt >= max_switch:
                    kind = (
                        "session_dead"
                        if _is_session_dead_error(status_code, err_msg)
                        else "send_reject"
                    )
                    refresher._log(
                        f"[sms] {kind} HTTP {status_code} → SOFT skip this round "
                        f"(CANCEL {'ok' if cancelled else 'FAIL-queued'}) "
                        f"{err_msg[:100]}"
                    )
                    raise _soft_skip_bind(
                        f"add-phone HTTP {status_code} ({kind}): {err_msg[:120]}"
                    )

                if _is_session_dead_error(status_code, err_msg):
                    refresher._log(
                        f"[sms] SESSION DEAD (HTTP {status_code}) → abort phone bind "
                        f"(rental CANCEL {'ok' if cancelled else 'FAIL-queued'}) "
                        f"{err_msg[:120]}"
                    )
                    raise RuntimeError(
                        f"phone bind aborted: session dead HTTP {status_code}: "
                        f"{err_msg[:160]} — re-login required (not phone quality)"
                    )

                refresher._log(
                    f"[sms] REJECTED/risk number → CANCEL "
                    f"{'ok' if cancelled else 'FAIL-queued'} "
                    f"attempt={attempt}/{max_switch} id={activation_id[:12]}... "
                    f"{err_msg[:100]}"
                )
                time.sleep(min(0.15, _phone_risk_pause_s()))
                continue

            # 等码只从 OpenAI 已接受发短信(HTTP 200) 之后开始计时，不是从 rent 起算
            otp_timeout = _phone_otp_timeout_s(sms_provider)
            refresher._log(
                f"[sms] OpenAI accepted send → wait OTP max={otp_timeout:.0f}s "
                f"(timer starts AFTER send, not rent) "
                f"attempt={attempt}/{max_switch} id={activation_id[:12]}..."
            )
            try:
                code = sms_provider.poll(
                    sms_session,
                    activation_id,
                    timeout_s=otp_timeout,
                )
            except TypeError:
                code = sms_provider.poll(sms_session, activation_id)
            if not code:
                # ★ 无码：必须立刻 cancel（风控号/空号），否则 Getatext 一直「等待中」
                ok_c = _safe_cancel(
                    sms_provider,
                    sms_session,
                    activation_id,
                    log_fn=log_fn,
                    reason=f"otp-timeout-no-code-{otp_timeout:.0f}s",
                    rented_at=rented_at,
                )
                held_activation_id = ""
                held_rented_at = 0.0
                _untrack_live_rental(activation_id)
                last_err = f"Phone OTP timeout after {otp_timeout:.0f}s — cancelled"
                refresher._log(
                    f"[sms] OTP timeout/no-code {otp_timeout:.0f}s "
                    f"attempt={attempt}/{max_switch} — CANCEL "
                    f"{'ok' if ok_c else 'FAIL-queued'} id={activation_id[:12]}..."
                )
                try:
                    flush_pending_cancels(log_fn=log_fn)
                except Exception:
                    pass
                if _phone_no_retry_this_round() or attempt >= max_switch:
                    raise _soft_skip_bind(last_err)
                continue

            # ★ 收码后立刻 complete（不等 OpenAI validate）
            # 否则 Getatext 后台一直「等待中」占 active rental 槽
            refresher._log(
                f"[sms] got OTP code → complete rental immediately "
                f"id={activation_id[:12]}... attempt={attempt}/{max_switch}"
            )
            _safe_complete(
                sms_provider,
                sms_session,
                activation_id,
                log_fn=log_fn,
                reason="otp-received",
            )
            # 已 complete：不再 cancel；清 held 防 finally 误 cancel
            held_activation_id = ""
            held_rented_at = 0.0
            _untrack_live_rental(activation_id)

            headers_v = refresher._json_headers(f"{C.AUTH_BASE}/phone-verification")
            headers_v["referer"] = f"{C.AUTH_BASE}/add-phone"
            resp, err = request_with_retry(
                refresher.session,
                "post",
                f"{C.AUTH_BASE}/api/accounts/phone-otp/validate",
                json_data={"code": code},
                headers=headers_v,
                verify=False,
                timeout=30,
            )
            sc2 = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
            if resp is None or sc2 != 200:
                # 租约已 complete，无需再 cancel
                last_err = f"Phone OTP validate failed: {err or sc2}"
                refresher._log(
                    f"[sms] validate fail attempt={attempt}/{max_switch} "
                    f"HTTP {sc2} (rental already completed)"
                )
                if _phone_no_retry_this_round() or attempt >= max_switch:
                    raise _soft_skip_bind(last_err)
                continue

            bind_ok = True
            refresh_payload = response_json(resp)
            save_debug(
                email,
                "phone_otp_validation",
                refresh_payload,
                status_code=sc2,
                extra={
                    "phone": phone,
                    "activation_id": activation_id,
                    "phone_attempts": attempt,
                    "tried_n": len(tried_phones),
                },
            )

            _kind = _sms_provider_kind(sms_provider)
            prov_name = (
                type(sms_provider).__name__ if _kind == "other" else _kind
            )
            refresher.last_phone = phone
            refresher.last_sms_provider = prov_name
            refresher.last_sms_activation_id = activation_id
            refresher.last_sms_phone = phone
            refresher._log(
                f"Phone bound successfully via {prov_name} "
                f"(attempt={attempt}/{max_switch})"
            )
            return {
                "phone": phone,
                "activation_id": activation_id,
                "payload": refresh_payload,
                "status": "bound",
                "sms_provider": prov_name,
                "phone_attempts": attempt,
            }

        raise _soft_skip_bind(
            f"failed after {max_switch} attempt(s); last={last_err[:180]}; "
            f"tried={len(tried_phones)} numbers"
        )
    finally:
        # 任何异常/失败/线程被杀前：手中租约必须 cancel（无码/风控/409）
        if held_activation_id and not bind_ok:
            try:
                ok_f = _safe_cancel(
                    sms_provider,
                    sms_session,
                    held_activation_id,
                    log_fn=log_fn,
                    reason="finally-release-held-rental",
                    rented_at=held_rented_at or None,
                )
                log_fn(
                    f"[sms] finally CANCEL held id={held_activation_id[:12]}... "
                    f"{'ok' if ok_f else 'FAIL-queued'}"
                )
            except Exception as fe:
                log_fn(f"[sms] finally cancel err: {fe}")
                try:
                    _remember_cancel_fail(sms_provider, held_activation_id)
                except Exception:
                    pass
            _untrack_live_rental(held_activation_id)
        try:
            flush_pending_cancels(log_fn=log_fn)
        except Exception:
            pass
        try:
            hold_sem.release()
        except Exception:
            pass
        try:
            sms_session.close()
        except Exception:
            pass


def finish_codex_after_bind(
    refresher, email: str, phone_payload: dict, oauth_state: dict
) -> dict:
    """
    手机绑定完成后，重新走 Codex OAuth 的 workspace/consent → 提取 code → exchange。
    """
    from .workspace import select_workspace_and_follow, extract_code_from_payload
    from .utils import exchange_code

    payload = phone_payload.get("payload") or phone_payload
    page_type = str(((payload.get("page") or {}).get("type")) or "")

    if page_type in (
        "workspace_select",
        "workspace_selection",
        "select_workspace",
        "workspace_picker",
        "sign_in_with_chatgpt_codex_consent",
        "sign_in_with_chatgpt_consent",
    ):
        payload = select_workspace_and_follow(
            refresher, email, oauth_state.get("account_id", ""), payload
        )

    code = extract_code_from_payload(payload)
    if not code:
        save_debug(email, "post_bind_no_code", payload)
        raise RuntimeError("No auth code after phone bind")

    tokens = exchange_code(
        code=code,
        code_verifier=oauth_state["code_verifier"],
        redirect_uri=oauth_state["redirect_uri"],
        client_id=oauth_state["client_id"],
        proxy_url=refresher.proxy_url,
    )
    if not tokens:
        raise RuntimeError("Token exchange failed after phone bind")

    save_debug(email, "post_bind_codex_token_bundle", tokens)
    return tokens
