"""Auth 核心 — 邮箱登录 + 完整 Codex OAuth"""
import json, os, secrets, time, urllib.parse, uuid
from typing import Any

from . import constants as C
from .session import TokenRefresher
from .utils import (
    generate_pkce, request_with_retry, response_json,
    save_debug, log_line, apply_sentinel_headers,
    is_short_refresh_token, exchange_code,
)
from .workspace import select_workspace_and_follow, extract_code_from_payload
from .email_ import poll_email_direct, resend_email_otp


def refresh_with_refresh_token(refresh_token: str, proxy_url: str = "") -> dict | None:
    """用 RT 刷新获取新 AT+RT"""
    from .session import create_session_with_proxy
    s = create_session_with_proxy(proxy_url)
    try:
        for client_id in [C.CODEX_OAUTH_CLIENT_ID]:
            resp, err = request_with_retry(
                s, "post", f"{C.AUTH_BASE}/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_id,
                },
                headers={"content-type": "application/x-www-form-urlencoded", "accept": "application/json"},
                verify=False, timeout=30,
            )
            if resp is not None and resp.status_code == 200:
                tokens = response_json(resp)
                if "access_token" in tokens:
                    return tokens
    finally:
        s.close()
    return None


def email_login(refresher: TokenRefresher, email: str, password: str = "",
                account_id: str = "", mail_url: str = "",
                sms_provider=None) -> dict:
    """
    完整 Codex OAuth 登录流程：
      1. Init OAuth + PKCE
      2. Email → Password → Email OTP
      3. add_phone（可选 sms_provider）→ Workspace/Consent
      4. Extract code → Exchange → AT+RT
    返回 {access_token, refresh_token, session_token, ...}
    """
    # 1. Init OAuth
    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    params = {
        "issuer": C.AUTH_BASE, "client_id": C.CODEX_OAUTH_CLIENT_ID,
        "audience": C.CODEX_OAUTH_AUDIENCE,
        "redirect_uri": C.CODEX_OAUTH_REDIRECT_URI,
        "device_id": refresher.device_id,
        "screen_hint": "login", "max_age": "0", "login_hint": "",
        "scope": C.CODEX_OAUTH_SCOPE, "response_type": "code",
        "response_mode": "query", "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
        "auth0Client": C.AUTH0_CLIENT,
    }
    resp, err = request_with_retry(
        refresher.session, "get",
        f"{C.AUTH_BASE}/api/accounts/authorize?{urllib.parse.urlencode(params)}",
        headers=refresher._navigate_headers(C.CODEX_OAUTH_REDIRECT_URI),
        allow_redirects=True, verify=False, timeout=20,
    )
    if resp is None:
        raise RuntimeError(f"oauth_init_failed: {err}")

    # 2. authorize/continue (email)
    email_otp_not_before = time.time() - C.EMAIL_OTP_TIME_SKEW
    h = refresher._json_headers(f"{C.AUTH_BASE}/log-in")
    apply_sentinel_headers(h, refresher.session, refresher.device_id, "authorize_continue", profile=getattr(refresher, "fingerprint_profile", None))
    resp, err = request_with_retry(
        refresher.session, "post",
        f"{C.AUTH_BASE}/api/accounts/authorize/continue",
        json_data={"username": {"kind": "email", "value": email}},
        headers=h, verify=False,
    )
    if resp is None or resp.status_code != 200:
        body = ""
        try:
            body = (getattr(resp, "text", "") or "")[:240] if resp is not None else str(err)
        except Exception:
            body = str(err)
        raise RuntimeError(f"authorize_continue failed: {body}")
    payload = response_json(resp)
    if isinstance(payload.get("error"), dict):
        err_code = str((payload.get("error") or {}).get("code") or "")
        err_msg = str((payload.get("error") or {}).get("message") or payload)
        if err_code == "rate_limit_exceeded" or "too many requests" in err_msg.lower():
            raise RuntimeError(f"rate_limit_exceeded: {err_msg}")
        if err_code == "account_deactivated":
            raise RuntimeError(f"account_deactivated: {err_msg}")
        raise RuntimeError(f"authorize_continue error: {err_msg}")
    save_debug(email, "authorize_continue", payload,
               status_code=str(resp.status_code))
    page_type = str(((payload.get("page") or {}).get("type")) or "")
    refresher._log(f"Page after auth: {page_type}")

    # 3. 默认邮箱 OTP（passwordless）
    #    OpenAI 可能返回 login_password 页；有 mail_url 时不验密码，直接 email-otp/send。
    #    仅当 TOKENREFRESH_PREFER_PASSWORD=1 且无 mail_url 时才走密码。
    prefer_email_otp = bool(str(mail_url or "").strip()) and (
        os.environ.get("TOKENREFRESH_PREFER_PASSWORD", "").strip().lower()
        not in ("1", "true", "yes", "on")
    )
    if page_type in ("login_password", "password"):
        email_otp_not_before = time.time() - C.EMAIL_OTP_TIME_SKEW
        password_ok = False
        force_password = (
            os.environ.get("TOKENREFRESH_PREFER_PASSWORD", "").strip().lower()
            in ("1", "true", "yes", "on")
        )
        if force_password and str(password or "").strip() and not prefer_email_otp:
            h = refresher._json_headers(f"{C.AUTH_BASE}/log-in/password")
            apply_sentinel_headers(
                h, refresher.session, refresher.device_id, "password_verify",
                profile=getattr(refresher, "fingerprint_profile", None),
            )
            resp, err = request_with_retry(
                refresher.session, "post",
                f"{C.AUTH_BASE}/api/accounts/password/verify",
                json_data={"password": password},
                headers=h, allow_redirects=False, verify=False,
            )
            if resp is not None and resp.status_code == 200:
                payload = response_json(resp)
                save_debug(email, "password_verify", payload,
                           status_code=str(resp.status_code))
                page_type = str(((payload.get("page") or {}).get("type")) or "")
                refresher._log(f"Page after password: {page_type}")
                password_ok = True
            elif not mail_url:
                raise RuntimeError("password_verify failed")
            else:
                refresher._log(
                    f"password_verify failed "
                    f"(HTTP {getattr(resp, 'status_code', None)}), "
                    f"fallback email OTP"
                )

        if not password_ok:
            if not mail_url:
                raise RuntimeError(
                    "email OTP required but no mail_url "
                    "(password page and no passwordless path)"
                )
            refresher._log("login_password page → email OTP (default passwordless)")
            email_otp_not_before = time.time() - C.EMAIL_OTP_TIME_SKEW
            send_ok = False
            last_send_err = ""
            for attempt in range(2):
                h = refresher._json_headers(f"{C.AUTH_BASE}/email-verification")
                apply_sentinel_headers(
                    h, refresher.session, refresher.device_id, "email_otp_resend",
                    profile=getattr(refresher, "fingerprint_profile", None),
                )
                # 密码页上部分会话要先打开 verification 文档
                request_with_retry(
                    refresher.session, "get",
                    f"{C.AUTH_BASE}/email-verification",
                    headers=refresher._navigate_headers(f"{C.AUTH_BASE}/log-in/password"),
                    allow_redirects=True, verify=False, timeout=15,
                )
                resp, err = request_with_retry(
                    refresher.session, "post",
                    f"{C.AUTH_BASE}/api/accounts/email-otp/send",
                    json_data={}, headers=h, verify=False,
                )
                sc = getattr(resp, "status_code", None)
                payload = response_json(resp) if resp is not None else {}
                save_debug(
                    email, "email_otp_send_response", payload,
                    status_code=str(sc or ""),
                    extra={"attempt": attempt, "err": err},
                )
                if resp is not None and sc in (200, 201):
                    send_ok = True
                    page_type = str(((payload.get("page") or {}).get("type")) or "")
                    if page_type not in ("email_otp_verification", "email_otp_send"):
                        page_type = "email_otp_verification"
                    refresher._log(
                        f"Passwordless: email OTP sent (HTTP {sc}) page={page_type}"
                    )
                    break
                last_send_err = (
                    f"HTTP {sc} "
                    f"{str((payload.get('error') or payload) or err)[:180]}"
                )
                refresher._log(f"email_otp_send failed: {last_send_err}")
                if attempt == 0:
                    # 重新 authorize/continue，再发 OTP（对齐 web 的 force passwordless）
                    refresher._log("re-authorize then retry email OTP send")
                    resp_a, _ = request_with_retry(
                        refresher.session, "get",
                        f"{C.AUTH_BASE}/api/accounts/authorize?"
                        + urllib.parse.urlencode({
                            "issuer": C.AUTH_BASE,
                            "client_id": C.CODEX_OAUTH_CLIENT_ID,
                            "audience": C.CODEX_OAUTH_AUDIENCE,
                            "redirect_uri": C.CODEX_OAUTH_REDIRECT_URI,
                            "device_id": refresher.device_id,
                            "screen_hint": "login",
                            "max_age": "0",
                            "login_hint": email,
                            "scope": C.CODEX_OAUTH_SCOPE,
                            "response_type": "code",
                            "response_mode": "query",
                            "state": secrets.token_urlsafe(16),
                            "nonce": secrets.token_urlsafe(16),
                            "code_challenge": challenge,
                            "code_challenge_method": "S256",
                            "auth0Client": C.AUTH0_CLIENT,
                        }),
                        headers=refresher._navigate_headers(C.CODEX_OAUTH_REDIRECT_URI),
                        allow_redirects=True, verify=False, timeout=20,
                    )
                    h_c = refresher._json_headers(f"{C.AUTH_BASE}/log-in")
                    apply_sentinel_headers(
                        h_c, refresher.session, refresher.device_id, "authorize_continue",
                        profile=getattr(refresher, "fingerprint_profile", None),
                    )
                    request_with_retry(
                        refresher.session, "post",
                        f"{C.AUTH_BASE}/api/accounts/authorize/continue",
                        json_data={"username": {"kind": "email", "value": email}},
                        headers=h_c, verify=False,
                    )
                    email_otp_not_before = time.time() - C.EMAIL_OTP_TIME_SKEW
            if not send_ok:
                raise RuntimeError(f"email_otp_send failed: {last_send_err}")

    # 4. Email OTP
    if page_type in ("email_otp_verification", "email_otp_send"):
        time.sleep(5)
        # 重发后靠 not_before/收件时间吃新信；不要用「码相同」排除
        # （OpenAI 连点两次可能验证码一样、到达时间不同）
        code = None
        for round_idx in range(C.EMAIL_OTP_VALIDATION_ROUNDS):
            if round_idx > 0:
                refresher._log("Email OTP timeout, resending...")
                resend_email_otp(refresher, email)
                not_before = time.time() - 2
                time.sleep(C.EMAIL_RESEND_WAIT_SECONDS)
            else:
                not_before = email_otp_not_before

            code = poll_email_direct(
                mail_url,
                email,
                not_before=not_before,
                ignore_codes=None,
            )
            if not code:
                continue

            h = refresher._json_headers(f"{C.AUTH_BASE}/email-verification")
            h["oai-device-id"] = refresher.device_id
            resp, err = request_with_retry(
                refresher.session, "post",
                f"{C.AUTH_BASE}/api/accounts/email-otp/validate",
                json_data={"code": code}, headers=h, verify=False,
            )
            if resp is not None and resp.status_code == 200:
                payload = response_json(resp)
                save_debug(email, "email_otp_validation", payload,
                           status_code=str(resp.status_code))
                page_type = str(((payload.get("page") or {}).get("type")) or "")
                refresher._log(f"Page after email OTP: {page_type}")
                break
            if resp is not None:
                err_body = response_json(resp)
                err_code = str(((err_body.get("error") or {}) if isinstance(err_body, dict) else {}).get("code") or "")
                if err_code == "account_deactivated":
                    raise RuntimeError(
                        f"account_deactivated: {(err_body.get('error') or {}).get('message', '')}"
                    )
            code = None

        if not code:
            raise RuntimeError("Could not get email OTP")

    # 4b. add_phone — bind via Getatext when provider is supplied
    cont = str(payload.get("continue_url") or "")
    if page_type == "add_phone" or "add-phone" in cont:
        if sms_provider is None:
            oauth_state = {
                "code_verifier": verifier,
                "redirect_uri": C.CODEX_OAUTH_REDIRECT_URI,
                "client_id": C.CODEX_OAUTH_CLIENT_ID,
                "account_id": account_id,
            }
            return {
                "_status": "add_phone",
                "_oauth": oauth_state,
                "access_token": "",
                "refresh_token": "",
            }
        from .phone import bind_phone_in_session, finish_codex_after_bind

        if cont:
            request_with_retry(
                refresher.session, "get", cont,
                headers=refresher._navigate_headers(f"{C.AUTH_BASE}/email-verification"),
                allow_redirects=True, verify=False, timeout=20,
            )
        refresher._log("add_phone required — binding via SMS provider")
        phone_payload = bind_phone_in_session(
            refresher, email, account_id=account_id, sms_provider=sms_provider,
        )
        oauth_state = {
            "code_verifier": verifier,
            "redirect_uri": C.CODEX_OAUTH_REDIRECT_URI,
            "client_id": C.CODEX_OAUTH_CLIENT_ID,
            "account_id": account_id,
        }
        tokens = finish_codex_after_bind(refresher, email, phone_payload, oauth_state)
        tokens["session_token"] = tokens.get("session_token", "")
        tokens["phone_bound"] = True
        tokens["phone_used"] = getattr(refresher, "last_phone", "")
        save_debug(email, "token_bundle_after_phone", tokens)
        return tokens

    # 5. Workspace / Consent
    if page_type in ("workspace_select", "workspace_selection", "select_workspace",
                     "workspace_picker", "sign_in_with_chatgpt_codex_consent",
                     "sign_in_with_chatgpt_consent"):
        continue_url = str(payload.get("continue_url") or
                          ((payload.get("page") or {}).get("payload") or {}).get("url") or "")
        if continue_url:
            refresher._log(f"Consent/workspace: {page_type}")
            resp, err = request_with_retry(
                refresher.session, "get", continue_url,
                headers=refresher._navigate_headers(f"{C.AUTH_BASE}/log-in/password"),
                allow_redirects=False, verify=False,
            )
            if resp is not None:
                location = str(resp.headers.get("Location") or resp.headers.get("location") or "").strip()
                final_url = urllib.parse.urljoin(continue_url, location) if location else str(resp.url or continue_url)
                payload = {
                    "continue_url": final_url, "method": "GET",
                    "page": {"type": f"{page_type}_follow"},
                }
                save_debug(email, "consent_follow", payload,
                           status_code=getattr(resp, "status_code", ""))
        payload = select_workspace_and_follow(refresher, email, account_id, payload)
        page_type = str(((payload.get("page") or {}).get("type")) or "")

    # 6. Extract code → Exchange
    code = extract_code_from_payload(payload)
    if not code:
        save_debug(email, "no_auth_code", payload, extra={"page_type": page_type})
        raise RuntimeError("No auth code in response")

    tokens = exchange_code(code=code, code_verifier=verifier,
                           redirect_uri=C.CODEX_OAUTH_REDIRECT_URI,
                           client_id=C.CODEX_OAUTH_CLIENT_ID,
                           proxy_url=refresher.proxy_url)
    if not tokens:
        raise RuntimeError("Token exchange failed")

    tokens["session_token"] = tokens.get("session_token", "")
    save_debug(email, "token_bundle", tokens)
    return tokens
