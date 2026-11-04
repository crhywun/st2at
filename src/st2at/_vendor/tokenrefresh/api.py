"""高层 API — login_only, refresh_at, bind_phone, check_usage"""
import json, os, time
from typing import Any

from .session import TokenRefresher, _load_hotmail_config
from . import constants as C
from .utils import log_line, is_short_refresh_token, token_exp


def login_only(email: str, password: str = "", mail_url: str = "",
               proxy: str = "", account_id: str = "",
               sms_config: dict | None = None) -> dict:
    """
    完整 Codex OAuth 登录，返回 {access_token, refresh_token, plan_type, ...}
    若遇到 add_phone 且配置了 Getatext，会自动绑机后继续拿 token。
    """
    from .auth import email_login
    from .smsbower_sms import build_sms_provider

    try:
        sms_provider = build_sms_provider(
            sms_config, log_fn=lambda m: log_line(f"[{email}] {m}"),
        )
    except Exception:
        from .getatext import build_getatext_provider

        sms_provider = build_getatext_provider(
            sms_config, log_fn=lambda m: log_line(f"[{email}] {m}"),
        )
    refresher = TokenRefresher(
        proxy_url=proxy,
        fingerprint_seed=email,
        log_fn=lambda m: log_line(f"[{email}] {m}"),
    )
    try:
        tokens = email_login(
            refresher, email, password,
            account_id=account_id, mail_url=mail_url,
            sms_provider=sms_provider,
        )
        if tokens.get("_status") == "add_phone":
            raise RuntimeError(
                "add_phone required but no SMS provider configured "
                "(set GETATEXT_API_KEY or pass sms_config)"
            )
        at = tokens.get("access_token", "")
        rt = tokens.get("refresh_token", "")
        return {
            "email": email,
            "access_token": at,
            "refresh_token": rt,
            "session_token": tokens.get("session_token", ""),
            "expires_at": token_exp(at),
            "plan_type": "unknown",
            "phone_bound": bool(tokens.get("phone_bound")),
            "phone_used": tokens.get("phone_used") or getattr(refresher, "last_phone", ""),
            "ok": bool(at),
        }
    finally:
        refresher.close()


def login_web_only(email: str, password: str = "", mail_url: str = "",
                   proxy: str = "", account_id: str = "") -> dict:
    """仅 ChatGPT Web 登录，返回 web accessToken（不拿 Codex token）"""
    from .web import chatgpt_web_login
    refresher = TokenRefresher(proxy_url=proxy, log_fn=lambda m: log_line(f"[{email}] {m}"))
    try:
        result = chatgpt_web_login(refresher, email, password,
                                    mail_url=mail_url, account_id=account_id)
        return {
            "email": email,
            "access_token": result.get("_chatgpt_access_token", ""),
            "plan_type": result.get("_chatgpt_plan", "unknown"),
            "ok": bool(result.get("_chatgpt_access_token")),
        }
    finally:
        refresher.close()


def refresh_access_token(email: str, password: str = "", mail_url: str = "",
                          proxy: str = "", refresh_token: str = "",
                          account_id: str = "") -> dict:
    """
    刷新 AT：优先用 RT 刷新，失败则完整 Codex OAuth 登录。
    """
    from .auth import refresh_with_refresh_token, email_login

    # 1. 先尝试 RT 刷新
    if refresh_token and is_short_refresh_token(refresh_token):
        tokens = refresh_with_refresh_token(refresh_token, proxy_url=proxy)
        if tokens:
            at = tokens.get("access_token", "")
            return {
                "email": email, "access_token": at,
                "refresh_token": tokens.get("refresh_token", refresh_token),
                "expires_at": token_exp(at),
                "source": "rt_refresh", "ok": True,
            }

    # 2. 完整登录
    return login_only(email, password, mail_url=mail_url,
                      proxy=proxy, account_id=account_id)


def bind_phone(email: str, password: str = "", mail_url: str = "",
               proxy: str = "", account_id: str = "",
               sms_config: dict | None = None) -> dict:
    """
    目标：**先绑机，再拿 Codex RT**（缺一不可）。

    路径对齐真实浏览器 / OAUTH.har：

      1) Platform：ChatGPT Web 登录（邮箱 OTP，建 session cookie）
      2) Codex：同一 session 走 simplified OAuth
         → choose-an-account / session/select
         → **必须**落到 add_phone
      3) Getatext 绑机 → finish OAuth → AT+RT

    成功条件：``phone_bound is True`` 且 ``refresh_token`` 非空。
    若 OAuth 直接 consent/出 token 而 **未** 出现 add_phone，记为失败
    （``error=no_add_phone``），**不**把「未绑机的 RT」当成功。

    Getatext 直连；OpenAI 走 proxy。
    """
    from .web import chatgpt_web_login, codex_oauth_from_web_session
    from .phone import bind_phone_in_session, finish_codex_after_bind
    from .smsbower_sms import build_sms_provider

    try:
        sms_provider = build_sms_provider(
            sms_config, log_fn=lambda m: log_line(f"[{email}] {m}"),
        )
    except Exception:
        from .getatext import build_getatext_provider

        sms_provider = build_getatext_provider(
            sms_config, log_fn=lambda m: log_line(f"[{email}] {m}"),
        )
    if sms_provider is None:
        raise RuntimeError("No SMS provider configured. Set GETATEXT_API_KEY env var.")

    refresher = TokenRefresher(
        proxy_url=proxy,
        fingerprint_seed=email,
        log_fn=lambda m: log_line(f"[{email}] {m}"),
    )
    try:
        # 1) Platform web login — builds reusable auth session
        web = chatgpt_web_login(
            refresher, email, password,
            mail_url=mail_url, account_id=account_id,
        )
        plan = web.get("_chatgpt_plan", "unknown")
        if not web.get("_chatgpt_access_token"):
            raise RuntimeError("platform web login failed (no access token)")

        # 2) Codex OAuth reusing same cookies (HAR: simplified flow → add_phone)
        tokens = codex_oauth_from_web_session(
            refresher, email, account_id=account_id,
        )

        status = str(tokens.get("_status") or "")
        phone_bound = False
        err = ""
        path_used = "platform_web+codex_simplified"

        if status == "add_phone":
            log_line(f"[{email}] add_phone required — binding via SMS provider")
            phone_payload = bind_phone_in_session(
                refresher, email, account_id, sms_provider,
            )
            tokens = finish_codex_after_bind(
                refresher, email, phone_payload, tokens.get("_oauth") or {},
            )
            phone_bound = True
            tokens["phone_bound"] = True
            tokens["phone_used"] = getattr(refresher, "last_phone", "") or ""
        elif status == "existing_phone_otp_required":
            raise RuntimeError("existing_phone_otp_required (not automated)")
        elif tokens.get("access_token") or tokens.get("refresh_token"):
            # 默认快失败：未撞 add_phone 不算成功。
            # 纯 Codex 回退很慢，仅 BIND_PURE_FALLBACK=1 时启用。
            err = "no_add_phone"
            pure_fb = (os.environ.get("BIND_PURE_FALLBACK") or "").strip().lower() in (
                "1", "true", "yes", "on",
            )
            if pure_fb:
                log_line(
                    f"[{email}] platform path no add_phone — pure Codex fallback"
                )
                try:
                    from .auth import email_login

                    pure = email_login(
                        refresher, email, password,
                        account_id=account_id, mail_url=mail_url,
                        sms_provider=sms_provider,
                    )
                    if pure.get("phone_bound") and pure.get("refresh_token"):
                        tokens = pure
                        phone_bound = True
                        err = ""
                        path_used = "platform_web+pure_codex_bind"
                        log_line(f"[{email}] pure Codex bind path succeeded")
                    elif pure.get("_status") == "add_phone":
                        err = "add_phone_unresolved"
                    elif pure.get("access_token") or pure.get("refresh_token"):
                        err = "no_add_phone"
                    else:
                        err = str(pure.get("_status") or "pure_codex_no_tokens")
                except Exception as pure_exc:
                    err = f"no_add_phone;pure_fallback:{type(pure_exc).__name__}"
                    log_line(f"[{email}] pure Codex fallback failed: {pure_exc}")
        else:
            err = status or "codex_oauth_no_tokens"

        # 仅「本 run 完成绑机」才算成功；禁止导出未绑机 RT
        phone_bound = bool(
            phone_bound
            and (getattr(refresher, "last_phone", None) or tokens.get("phone_bound"))
        )
        at = (tokens.get("access_token", "") or "") if phone_bound else ""
        rt = (tokens.get("refresh_token", "") or "") if phone_bound else ""
        ok = bool(phone_bound and at and rt)
        if phone_bound and not rt:
            err = err or "bind_ok_but_no_rt"
        if phone_bound and not at:
            err = err or "bind_ok_but_no_at"
        if not phone_bound and not err:
            err = "no_phone_bound"

        return {
            "email": email,
            "access_token": at,
            "refresh_token": rt,
            "plan_type": plan,
            "phone_bound": phone_bound,
            # 仅进程内/日志用；导出 sanitize 会剥掉
            "phone_used": (
                getattr(refresher, "last_phone", "")
                or tokens.get("phone_used")
                or ""
            ) if phone_bound else "",
            "ok": ok,
            "error": err if not ok else "",
            "path": path_used,
        }
    finally:
        refresher.close()


def check_usage(access_token: str) -> dict | None:
    """查询 Codex usage 额度"""
    import requests
    r = requests.get(C.WHAM_USAGE_URL, headers={
        "Authorization": f"Bearer {access_token}",
        "accept": "application/json",
        "user-agent": C.USER_AGENT,
        "referer": "https://chatgpt.com/codex/cloud/settings/analytics",
    }, timeout=20)
    if r.status_code != 200:
        return None
    data = r.json()
    rl = data.get("rate_limit") or {}
    pw = rl.get("primary_window") or {}
    sec = pw.get("limit_window_seconds", 0)
    return {
        "plan_type": data.get("plan_type", ""),
        "limit_days": round(sec / 86400, 1),
        "used_pct": pw.get("used_percent", 0),
        "limit_reached": rl.get("limit_reached", False),
        "raw": data,
    }


def init_hotmail(doc_path: str = "", api_base: str = "", admin_password: str = ""):
    """初始化 Hotmail API 配置"""
    from .session import _load_hotmail_config
    return _load_hotmail_config(doc_path, api_base, admin_password)


def login_and_export(email: str, password: str = "", mail_url: str = "",
                     proxy: str = "", output_path: str = "",
                     at_only: bool = False,
                     sms_config: dict | None = None,
                     prefer_bind: bool = True) -> str:
    """
    登录（必要时绑机）+ 导出 sub2api 格式。

    at_only=True  → 只导出 AT（不要 RT）
    at_only=False → 导出 AT+RT
    prefer_bind=True → 使用 bind_phone 路径（支持 add_phone）
    """
    if prefer_bind:
        result = bind_phone(
            email, password, mail_url=mail_url, proxy=proxy, sms_config=sms_config,
        )
    else:
        result = login_only(
            email, password, mail_url=mail_url, proxy=proxy, sms_config=sms_config,
        )
    if not result.get("ok"):
        raise RuntimeError(
            f"Login failed for {email}: error={result.get('error') or 'unknown'} "
            f"phone_bound={bool(result.get('phone_bound'))}"
        )
    if prefer_bind and not result.get("phone_bound"):
        raise RuntimeError(
            f"Bind required but phone not bound for {email}: "
            f"{result.get('error') or 'no_add_phone'}"
        )

    rt = "" if at_only else result.get("refresh_token", "")
    if not at_only and not rt:
        raise RuntimeError(f"Login ok but missing refresh_token for {email}")

    # 仅白名单字段进导出 — 禁止 phone/getatext 等出现在交付 JSON
    from .export_format import account_row_for_export, export_sub2api

    accounts = [account_row_for_export({
        "email": email,
        "access_token": result["access_token"],
        "refresh_token": rt,
        "password": password,
    })]

    if not output_path:
        safe = email.replace("@", "_at_").replace(".", "_")
        output_path = f"sub2api_{safe}.json"
    return export_sub2api(accounts, output_path, at_only=at_only)
