"""Password/TOTP login and one-time security initialization for relogin jobs."""

from __future__ import annotations

import os
import time
import urllib.parse
import uuid
from typing import Any, Callable


CHATGPT_BASE = "https://chatgpt.com"
AUTH_BASE = "https://auth.openai.com"
# NextAuth, ChatGPT frontend, and auth.openai.com JSON use distinct families.
# Do not copy turb-gpt's older Sentinel SDK / SPA build onto these requests.
_OAI_CLIENT_HEADER_NAMES = {
    "oai-client-build-number",
    "oai-client-version",
    "oai-session-id",
    "oai-device-id",
    "oai-language",
}
_AUTH_WEB_RUM_HEADER_NAMES = {
    "x-access-flow-invocation-id",
    "traceparent",
    "tracestate",
    "x-datadog-origin",
    "x-datadog-parent-id",
    "x-datadog-sampling-priority",
    "x-datadog-trace-id",
}
_AUTHORIZE_STOP_STATUSES = {403, 429}
OTP_TIME_SKEW_S = 30.0


def is_browser_challenge(response: Any) -> bool:
    headers = getattr(response, "headers", {}) or {}
    return int(getattr(response, "status_code", 0) or 0) == 403 and any(
        str(key).lower() == "cf-mitigated" and str(value).lower() == "challenge"
        for key, value in headers.items()
    )


class MfaVerificationExhaustedError(RuntimeError):
    """Fresh TOTP codes were rejected after bounded session rebuilds."""


class _MfaVerifyAttemptError(RuntimeError):
    """One TOTP submission failed in the active MFA session."""

    def __init__(self, message: str, *, used_code: str):
        super().__init__(message)
        self.used_code = used_code


def _log_fn(log: Callable[[str], None] | None) -> Callable[[str], None]:
    def emit(message: str) -> None:
        try:
            (log or print)(f"[security] {message}")
        except Exception:
            pass

    return emit


def _normalize_proxy(proxy: str) -> str:
    value = str(proxy or "").strip()
    if not value or "://" in value:
        return value
    parts = value.split(":")
    if len(parts) >= 4:
        host, port, user = parts[:3]
        password = ":".join(parts[3:])
        return f"socks5h://{user}:{password}@{host}:{port}"
    if len(parts) == 2:
        return f"socks5h://{parts[0]}:{parts[1]}"
    return value


def _new_refresher(
    email: str,
    proxy: str,
    log: Callable[[str], None],
    *,
    device_id: str = "",
    fingerprint_seed: str = "",
    profile_region: str = "",
    chrome_major: int | None = None,
):
    from tokenrefresh.session import TokenRefresher

    seed = str(fingerprint_seed or email or "").strip()
    region = str(profile_region or "").strip().upper()
    major = 150 if chrome_major is None else chrome_major
    kwargs = {
        "proxy_url": _normalize_proxy(proxy),
        # Registration uses the mailbox as its deterministic persona seed.
        # Re-login/security setup must use the same seed instead of adding a
        # random salt and silently switching UA/TLS/locale.
        "fingerprint_seed": seed,
        "log_fn": lambda message: log(str(message)[:220]),
        "locale": "auto",
        "chrome_major": major,
    }
    if str(device_id or "").strip():
        kwargs["device_id"] = str(device_id).strip()
    if region:
        kwargs["profile_region"] = region
    refresher = TokenRefresher(**kwargs)
    try:
        from tokenrefresh.client_identity import bind_session_on_refresher

        bind_session_on_refresher(refresher, rotate=True)
    except Exception:
        pass
    _align_refresher_identity(refresher, seed=seed, region=region, device_id=device_id)
    return refresher


def _align_refresher_identity(
    refresher: Any, *, seed: str, region: str, device_id: str = ""
) -> None:
    """Match toSub2: chrome150 TLS, JP har_parity locale, per-email CH/device."""
    if not seed:
        return
    from .registration_fingerprint import (
        apply_seeded_chrome_identity,
        seeded_chrome_identity,
    )

    identity = seeded_chrome_identity(seed=seed, region=region or "JP")
    profile = getattr(refresher, "fingerprint_profile", None)
    if not isinstance(profile, dict):
        profile = {}
        try:
            refresher.fingerprint_profile = profile
        except Exception:
            return
    apply_seeded_chrome_identity(profile, identity)
    try:
        refresher.impersonate = profile.get("impersonate") or "chrome150"
    except Exception:
        pass
    if str(device_id or "").strip():
        return
    try:
        refresher.device_id = identity["device_id"]
    except Exception:
        pass


def native_otp_mail_url(mail_url: str) -> str:
    """Mark the native HTTPS OTP endpoint so tokenrefresh uses its JSON parser."""
    value = str(mail_url or "").strip()
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme.lower() in {"http", "https"}
        and parsed.hostname
        and parsed.path == "/api/v1/otp"
        and urllib.parse.parse_qs(parsed.query).get("token")
    ):
        return urllib.parse.urlunsplit(
            ("icloudv2", parsed.netloc, parsed.path, parsed.query, parsed.fragment)
        )
    return value


def _snapshot_otp_codes(mail_url: str) -> set[str]:
    return set(_snapshot_otp_inbox(mail_url)["codes"])


def _snapshot_otp_inbox(mail_url: str) -> dict[str, Any]:
    """Capture visible OTP messages so a later poll can keep a new mail with the same digits."""
    seen_at = time.time()
    items = _list_icloudv2_otp_items(mail_url)
    codes = {item["code"] for item in items}
    fingerprints = {(item["code"], item["received_at"]) for item in items}
    return {"seen_at": seen_at, "codes": codes, "fingerprints": fingerprints}


def _list_icloudv2_otp_items(mail_url: str) -> list[dict[str, Any]]:
    value = native_otp_mail_url(mail_url)
    if not value.lower().startswith("icloudv2://"):
        return []
    try:
        from tokenrefresh.email_ import _icloudv2_https_url, _icloudv2_timestamp
        from curl_cffi import requests as curl_requests

        endpoint = _icloudv2_https_url(value)
        if not endpoint:
            return []
        session = curl_requests.Session(impersonate="chrome")
        try:
            response = session.get(
                endpoint, headers={"Accept": "application/json"}, timeout=20
            )
            response.raise_for_status()
            payload = response.json()
        finally:
            session.close()
    except Exception:
        return []
    if not isinstance(payload, list):
        return []
    items = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        code = str(entry.get("otp") or "").strip()
        if len(code) != 6 or not code.isdigit():
            continue
        items.append(
            {"code": code, "received_at": _icloudv2_timestamp(entry.get("time"))}
        )
    return items


def _otp_time_skew_s() -> float:
    try:
        value = float(
            os.environ.get("EMAIL_OTP_TIME_SKEW", str(OTP_TIME_SKEW_S))
            or OTP_TIME_SKEW_S
        )
    except ValueError:
        value = OTP_TIME_SKEW_S
    return max(0.0, min(180.0, value))


def _select_new_icloudv2_otp(
    items: list[dict[str, Any]], inbox: dict[str, Any], not_before: float = 0
) -> str:
    fingerprints = inbox.get("fingerprints") or set()
    seen_codes = inbox.get("codes") or set()
    seen_at = float(inbox.get("seen_at") or 0)
    threshold = float(not_before or 0)
    skew = _otp_time_skew_s()
    candidates: list[tuple[float, str]] = []
    for item in items:
        code, received_at = item["code"], float(item["received_at"] or 0)
        if (code, received_at) in fingerprints:
            continue
        if received_at > 0 and seen_at and received_at <= seen_at - skew:
            continue
        if received_at <= 0 and code in seen_codes:
            continue
        if threshold and received_at > 0 and received_at < threshold - skew:
            continue
        candidates.append((received_at, code))
    if not candidates:
        return ""
    candidates.sort(reverse=True)
    return candidates[0][1]


def _poll_add_password_otp(
    mail_url: str,
    email: str,
    *,
    seen: set[str] | None = None,
    inbox: dict[str, Any] | None = None,
    not_before: float = 0,
):
    snapshot = dict(inbox or {})
    if seen and not snapshot.get("codes"):
        snapshot["codes"] = {str(code).strip() for code in seen if str(code).strip()}
        snapshot.setdefault("fingerprints", set())
        snapshot.setdefault("seen_at", 0)
    value = native_otp_mail_url(mail_url)
    if value.lower().startswith("icloudv2://"):
        from relogin_service import _email_poll_seconds

        deadline = time.time() + max(60, _email_poll_seconds())
        interval = 0.5
        try:
            from tokenrefresh import constants as tokenrefresh_constants

            interval = float(
                getattr(tokenrefresh_constants, "EMAIL_OTP_POLL_INTERVAL", 0.5) or 0.5
            )
        except Exception:
            pass
        while time.time() < deadline:
            code = _select_new_icloudv2_otp(
                _list_icloudv2_otp_items(value), snapshot, not_before
            )
            if code:
                return code
            time.sleep(max(0.2, interval))
        return ""
    try:
        from tokenrefresh.email_ import poll_email_direct

        code = poll_email_direct(
            mail_url,
            email,
            not_before=not_before,
            ignore_codes=snapshot.get("codes") or None,
        )
        if code:
            return code
    except Exception:
        pass
    from tokenrefresh.web import _poll_otp

    return _poll_otp(mail_url, email, not_before=not_before)


def _header_name_key(name: str) -> str:
    return str(name or "").strip().lower()


def _without_headers(headers: dict[str, Any] | None, names: set[str]) -> dict[str, Any]:
    blocked = {name.lower() for name in names}
    return {
        key: value
        for key, value in dict(headers or {}).items()
        if _header_name_key(key) not in blocked
    }


def _nextauth_headers(refresher: Any, referer: str = "") -> dict[str, str]:
    """Headers for chatgpt.com `/api/auth/*` — no oai-client-* and no Auth RUM."""
    raw = {}
    getter = getattr(refresher, "_json_headers", None)
    if callable(getter):
        try:
            raw = dict(getter(referer or f"{CHATGPT_BASE}/") or {})
        except Exception:
            raw = {}
    headers = _without_headers(
        raw, _OAI_CLIENT_HEADER_NAMES | _AUTH_WEB_RUM_HEADER_NAMES
    )
    profile = getattr(refresher, "fingerprint_profile", None) or {}
    user_agent = str(profile.get("user_agent") or headers.get("user-agent") or "")
    if user_agent:
        headers["user-agent"] = user_agent
    headers["accept"] = "application/json"
    headers["origin"] = CHATGPT_BASE
    headers["referer"] = referer or f"{CHATGPT_BASE}/"
    headers["sec-fetch-dest"] = "empty"
    headers["sec-fetch-mode"] = "cors"
    headers["sec-fetch-site"] = "same-origin"
    return headers


def _auth_web_json_headers(refresher: Any, referer: str = "") -> dict[str, str]:
    """Headers for auth.openai.com JSON — Auth RUM, never oai-client-*."""
    raw = {}
    getter = getattr(refresher, "_json_headers", None)
    if callable(getter):
        try:
            raw = dict(getter(referer) or {})
        except Exception:
            raw = {}
    headers = _without_headers(raw, _OAI_CLIENT_HEADER_NAMES)
    if "x-access-flow-invocation-id" not in {key.lower() for key in headers}:
        headers["x-access-flow-invocation-id"] = str(uuid.uuid4())
    return headers


def _chatgpt_frontend_header_names() -> set[str]:
    return set(_OAI_CLIENT_HEADER_NAMES)


def _is_oauth_callback(url: str) -> bool:
    parsed = urllib.parse.urlsplit(str(url or ""))
    path = parsed.path or ""
    host = (parsed.netloc or "").lower()
    if "chatgpt.com" not in host:
        return False
    return (
        path.startswith("/api/auth/callback")
        or path.startswith("/auth/callback")
        or "callback" in path
    )


def _oauth_callback_error(url: str) -> str:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(str(url or "")).query)
    return str((query.get("error") or [""])[0] or "").strip()


def _is_email_verification_url(url: str) -> bool:
    return "email-verification" in (urllib.parse.urlsplit(str(url or "")).path or "")


def _is_authorize_url(url: str) -> bool:
    parsed = urllib.parse.urlsplit(str(url or ""))
    path = parsed.path or ""
    host = (parsed.netloc or "").lower()
    if "auth.openai.com" not in host:
        return False
    return path.startswith("/api/accounts/authorize") or path.startswith(
        "/api/oauth/oauth2/auth"
    )


def _oauth_callback_url(*candidates: str) -> str:
    for raw in candidates:
        value = str(raw or "").strip()
        if not value:
            continue
        if value.startswith("/"):
            if value.startswith("/api/auth/callback") or value.startswith(
                "/auth/callback"
            ):
                value = urllib.parse.urljoin(CHATGPT_BASE, value)
            else:
                continue
        if _is_oauth_callback(value):
            error = _oauth_callback_error(value)
            if error:
                continue
            return value
    return ""


def _resolve_oauth_callback(
    refresher: Any, url: str, emit: Callable[[str], None]
) -> str:
    value = str(url or "").strip()
    callback = _oauth_callback_url(value)
    if callback:
        return callback
    if not _is_authorize_url(value):
        return ""
    from tokenrefresh.utils import request_with_retry, response_json

    try:
        headers = refresher._navigate_headers(f"{AUTH_BASE}/")
    except Exception:
        headers = {"referer": f"{AUTH_BASE}/"}
    emit("authorize 不自动跟随，读取 Location callback")
    response, _error = request_with_retry(
        refresher.session,
        "get",
        value,
        headers=headers,
        allow_redirects=False,
        verify=False,
        timeout=25,
    )
    status = int(getattr(response, "status_code", 0) or 0)
    if response is None or status not in (200, 201, 302, 303):
        emit(f"authorize 未给出 callback HTTP={status or '?'}")
        return ""
    headers_out = getattr(response, "headers", {}) or {}
    location = str(
        headers_out.get("Location") or headers_out.get("location") or ""
    ).strip()
    if location.startswith("/"):
        location = urllib.parse.urljoin(
            CHATGPT_BASE
            if location.startswith("/api/auth") or location.startswith("/auth/callback")
            else value,
            location,
        )
    callback = _oauth_callback_url(location, str(getattr(response, "url", "") or ""))
    if callback:
        return callback
    if status in (200, 201):
        data = response_json(response)
        if isinstance(data, dict):
            callback = _oauth_callback_url(_continue_url(data, response))
            if callback:
                return callback
    path = (
        urllib.parse.urlsplit(location or str(getattr(response, "url", "") or "")).path
        or "-"
    )
    emit(f"authorize 未跳到 callback HTTP={status} path={path}")
    return ""


def _continue_url(payload: dict, response: Any | None = None) -> str:
    data = payload or {}
    for key in ("continue_url", "continueUrl", "redirect_url", "redirectUrl"):
        value = str(data.get(key) or "").strip()
        if value:
            return value
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    page_type = str(page.get("type") or "")
    intermediate = page_type in {
        "login_password",
        "password",
        "email_otp_verification",
        "email_verification",
        "mfa_challenge",
    }
    page_keys = (
        ("continue_url", "continueUrl")
        if intermediate
        else (
            "continue_url",
            "continueUrl",
            "url",
            "redirect_url",
            "redirectUrl",
        )
    )
    for key in page_keys:
        value = str(page.get(key) or "").strip()
        if value:
            return value
    nested = page.get("payload") if isinstance(page.get("payload"), dict) else {}
    for key in ("continue_url", "continueUrl", "url"):
        value = str(nested.get(key) or "").strip()
        if value and (not intermediate or _is_oauth_callback(value)):
            return value
    session = (
        data.get("client_auth_session")
        if isinstance(data.get("client_auth_session"), dict)
        else {}
    )
    for key in ("continue_url", "url"):
        value = str(session.get(key) or "").strip()
        if value:
            return value
    headers = getattr(response, "headers", {}) or {}
    location = str(headers.get("Location") or headers.get("location") or "").strip()
    if location:
        return location
    response_url = str(
        getattr(response, "url", "") or data.get("_response_url") or ""
    ).strip()
    if _is_oauth_callback(response_url):
        return response_url
    return ""


def _session_dump_continue_url(refresher: Any) -> str:
    try:
        from tokenrefresh.web import _auth_session_continue_url

        return str(_auth_session_continue_url(refresher) or "").strip()
    except Exception:
        return ""


def _json_request(
    refresher: Any, method: str, url: str, *, headers: dict, **kwargs
) -> dict:
    from tokenrefresh.utils import request_with_retry, response_json

    kwargs.setdefault("allow_redirects", False)
    response, error = request_with_retry(
        refresher.session,
        method,
        url,
        headers=headers,
        verify=False,
        timeout=30,
        **kwargs,
    )
    status = int(getattr(response, "status_code", 0) or 0)
    if response is None or status not in (200, 201, 302, 303):
        body = str(getattr(response, "text", "") or "")[:180]
        raise RuntimeError(
            f"{method.upper()} {urllib.parse.urlsplit(url).path} HTTP={status or '?'} {error or body}"
        )
    data = response_json(response)
    if not isinstance(data, dict):
        data = {}
    data["_status"] = status
    data["_response_url"] = str(getattr(response, "url", "") or "")
    location = _continue_url(data, response)
    if location and not str(data.get("continue_url") or "").strip():
        if location.startswith("/"):
            base = CHATGPT_BASE if location.startswith("/api/auth") else url
            location = urllib.parse.urljoin(base, location)
        data["continue_url"] = location
    return data


def _start_password_authorize(
    refresher: Any,
    email: str,
    *,
    add_password: bool,
) -> tuple[dict, str]:
    from tokenrefresh.utils import request_with_retry, response_json

    device_id = str(getattr(refresher, "device_id", "") or "")
    if add_password:
        query = {
            "connection": "password",
            "login_hint": email,
            "ext-oai-did": device_id,
        }
        query.update(
            {
                "reauth": "password",
                "post_login_add_password": "true",
                "max_age": "0",
            }
        )
    else:
        # Start the regular login surface.  When the UI defaults to email OTP,
        # setup below follows the visible "use password" page action.
        query = {
            "prompt": "login",
            "ext-oai-did": device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "screen_hint": "login_or_signup",
            "login_hint": email,
        }
    signin_url = (
        f"{CHATGPT_BASE}/api/auth/signin/openai?{urllib.parse.urlencode(query)}"
    )
    profile = getattr(refresher, "fingerprint_profile", None) or {}
    user_agent = str(profile.get("user_agent") or "")
    last_detail = ""
    authorize_url = ""
    for attempt in range(1, 4):
        try:
            request_with_retry(
                refresher.session,
                "get",
                f"{CHATGPT_BASE}/",
                headers=refresher._navigate_headers(f"{CHATGPT_BASE}/"),
                allow_redirects=True,
                verify=False,
                timeout=12,
            )
            request_with_retry(
                refresher.session,
                "get",
                f"{CHATGPT_BASE}/auth/login",
                headers=refresher._navigate_headers(f"{CHATGPT_BASE}/"),
                allow_redirects=True,
                verify=False,
                timeout=12,
            )
        except Exception:
            pass
        try:
            request_with_retry(
                refresher.session,
                "get",
                f"{CHATGPT_BASE}/api/auth/providers",
                headers=_nextauth_headers(refresher, f"{CHATGPT_BASE}/"),
                verify=False,
                timeout=10,
            )
        except Exception:
            pass
        csrf_response, csrf_error = request_with_retry(
            refresher.session,
            "get",
            f"{CHATGPT_BASE}/api/auth/csrf",
            headers=_nextauth_headers(refresher, f"{CHATGPT_BASE}/"),
            verify=False,
            timeout=15,
        )
        csrf_status = int(getattr(csrf_response, "status_code", 0) or 0)
        csrf_data = response_json(csrf_response) if csrf_response is not None else {}
        csrf = str(csrf_data.get("csrfToken") or "")
        if not csrf:
            last_detail = (
                f"csrf HTTP={csrf_status or '?'} {csrf_error or str(csrf_data)[:100]}"
            )
            if attempt < 3:
                time.sleep(0.35 * attempt)
            continue

        signin_response, signin_error = request_with_retry(
            refresher.session,
            "post",
            signin_url,
            data={"callbackUrl": f"{CHATGPT_BASE}/", "csrfToken": csrf, "json": "true"},
            headers={
                **_nextauth_headers(refresher, f"{CHATGPT_BASE}/"),
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded",
                "origin": CHATGPT_BASE,
                "referer": f"{CHATGPT_BASE}/",
                "user-agent": user_agent,
            },
            allow_redirects=False,
            verify=False,
            timeout=25,
        )
        signin_status = int(getattr(signin_response, "status_code", 0) or 0)
        signin = response_json(signin_response) if signin_response is not None else {}
        location = ""
        if signin_response is not None:
            location = str(
                signin_response.headers.get("Location")
                or signin_response.headers.get("location")
                or ""
            )
        authorize_url = str(signin.get("url") or location or "").strip()
        if authorize_url:
            authorize_url = urllib.parse.urljoin(CHATGPT_BASE, authorize_url)
            break
        body = str(getattr(signin_response, "text", "") or "").replace("\n", " ")[:140]
        last_detail = (
            f"signin HTTP={signin_status or '?'} "
            f"{signin_error or body or str(signin)[:100]}"
        )
        if attempt < 3:
            time.sleep(0.4 * attempt)
    if not authorize_url:
        raise RuntimeError(
            f"password signin did not return authorize URL after 3 attempts: {last_detail}"
        )
    auth_response, auth_error = request_with_retry(
        refresher.session,
        "get",
        authorize_url,
        headers=refresher._navigate_headers(f"{CHATGPT_BASE}/"),
        allow_redirects=True,
        verify=False,
        timeout=30,
        retry_attempts=1,
        retry_statuses=(),
    )
    if auth_response is None:
        raise RuntimeError(f"password authorize failed: {auth_error}")
    auth_status = int(getattr(auth_response, "status_code", 0) or 0)
    if is_browser_challenge(auth_response):
        raise RuntimeError(
            "password authorize HTTP=403 browser_challenge (session stopped)"
        )
    if auth_status in _AUTHORIZE_STOP_STATUSES:
        raise RuntimeError(f"password authorize HTTP={auth_status} (session stopped)")
    final_url = str(getattr(auth_response, "url", "") or "")
    if (
        not add_password
        and urllib.parse.urlsplit(final_url).path == "/email-verification"
    ):
        password_page, password_error = request_with_retry(
            refresher.session,
            "get",
            f"{AUTH_BASE}/log-in/password",
            headers=refresher._navigate_headers(final_url),
            allow_redirects=True,
            verify=False,
            timeout=25,
        )
        if password_page is not None:
            auth_response = password_page
            final_url = str(getattr(password_page, "url", "") or final_url)
        elif password_error:
            raise RuntimeError(f"password page navigation failed: {password_error}")
    return response_json(auth_response), final_url


def _payload_page(payload: dict, fallback_url: str = "") -> str:
    page = str(((payload or {}).get("page") or {}).get("type") or "")
    if page:
        return page
    path = urllib.parse.urlsplit(
        str((payload or {}).get("continue_url") or fallback_url)
    ).path
    if path.startswith("/mfa-challenge/"):
        return "mfa_challenge"
    if "email-verification" in path:
        return "email_otp_verification"
    if path.endswith("/password"):
        return "login_password"
    return ""


def _authorize_intermediate_state(payload: dict, final_url: str) -> bool:
    """Return whether authorize stopped on its HTML/API intermediate state.

    A successful re-auth may still have an ``/api/accounts/authorize`` URL
    while carrying a page descriptor.  Only treat the response as stuck when
    both the URL is the authorize endpoint and no usable page was returned.
    """
    path = urllib.parse.urlsplit(str(final_url or "")).path.rstrip("/").lower()
    return path.endswith("/api/accounts/authorize") and not _payload_page(
        payload, final_url
    )


def _clear_reauth_authorize_state(refresher: Any, emit: Callable[[str], None]) -> None:
    """Clear auth-domain state that can pin a dead re-auth transaction.

    Keep the ChatGPT NextAuth session cookie intact: it is the authenticated
    session that authorizes adding the first password.  The vendor helper only
    removes auth.openai.com cookies and is therefore safe to reuse here.
    """
    try:
        from tokenrefresh.web import _clear_openai_auth_cookies

        _clear_openai_auth_cookies(refresher)
    except Exception as exc:
        emit(f"清理新增密码授权状态失败，继续重试: {str(exc)[:100]}")


def _start_password_authorize_with_recovery(
    refresher: Any,
    email: str,
    *,
    add_password: bool,
    emit: Callable[[str], None],
    attempts: int = 3,
) -> tuple[dict, str]:
    """Start password auth and recover a dead ``/authorize`` state in-place."""
    max_attempts = max(1, min(3, int(attempts or 1)))
    payload: dict = {}
    final_url = ""
    for attempt in range(1, max_attempts + 1):
        payload, final_url = _start_password_authorize(
            refresher,
            email,
            add_password=add_password,
        )
        if not _authorize_intermediate_state(payload, final_url):
            return payload, final_url
        if attempt >= max_attempts:
            break
        emit(
            "新增密码授权停留在中间态，清理 auth 状态并重建会话 "
            f"{attempt}/{max_attempts - 1}"
        )
        _clear_reauth_authorize_state(refresher, emit)
        time.sleep(0.35 * attempt)
    return payload, final_url


def _sentinel_headers(refresher: Any, referer: str, flow: str) -> dict:
    from tokenrefresh.utils import apply_sentinel_headers

    headers = _auth_web_json_headers(refresher, referer)
    log = getattr(refresher, "_log", None)
    try:
        from tokenrefresh.formal_frame import build_formal_bundle, formal_frame_enabled

        if formal_frame_enabled():
            headers.update(
                build_formal_bundle(
                    refresher.session,
                    refresher.device_id,
                    flow,
                    profile=getattr(refresher, "fingerprint_profile", None),
                    page_url=str(referer or ""),
                    log=log,
                )
            )
            return headers
    except Exception as exc:
        if callable(log):
            try:
                log(f"sentinel {flow} formal-frame skipped: {type(exc).__name__}")
            except Exception:
                pass
    try:
        apply_sentinel_headers(
            headers,
            refresher.session,
            refresher.device_id,
            flow,
            profile=getattr(refresher, "fingerprint_profile", None),
        )
    except Exception as exc:
        if callable(log):
            try:
                log(f"sentinel {flow} skipped: {type(exc).__name__}")
            except Exception:
                pass
    return headers


def _request_email_otp_send(refresher: Any, emit: Callable[[str], None]) -> int:
    try:
        from tokenrefresh.utils import request_with_retry
    except Exception as exc:
        emit(f"邮箱验证码发送失败: {type(exc).__name__}")
        return 0
    status = 0
    for attempt in range(2):
        try:
            headers = refresher._navigate_headers(f"{AUTH_BASE}/email-verification")
        except Exception:
            headers = {"referer": f"{AUTH_BASE}/email-verification"}
        try:
            response, _error = request_with_retry(
                refresher.session,
                "get",
                f"{AUTH_BASE}/api/accounts/email-otp/send",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=20,
            )
        except Exception as exc:
            emit(f"邮箱验证码发送失败: {type(exc).__name__}")
            response = None
        status = int(getattr(response, "status_code", 0) or 0)
        if status == 200:
            break
        if attempt == 0:
            time.sleep(1.0)
    emit(f"邮箱验证码发送 HTTP={status or '?'}")
    return status


def _poll_fresh_email_otp(
    refresher: Any,
    mail_url: str,
    email: str,
    emit: Callable[[str], None],
    inbox: dict[str, Any] | None,
) -> str:
    _request_email_otp_send(refresher, emit)
    code = _poll_add_password_otp(
        mail_url, email, inbox=inbox, not_before=time.time() - 2
    )
    if code:
        return code
    emit("邮箱验证码未到，再发一次")
    _request_email_otp_send(refresher, emit)
    return _poll_add_password_otp(
        mail_url, email, inbox=inbox, not_before=time.time() - 2
    )


def _follow_callback(refresher: Any, payload: dict) -> None:
    from tokenrefresh.web import _follow_oauth_callback, _warm_chatgpt_home

    callback = str((payload or {}).get("continue_url") or "")
    if not callback:
        raise RuntimeError("authentication completed without callback URL")
    if not _is_oauth_callback(callback) and _is_authorize_url(callback):
        resolved = _resolve_oauth_callback(
            refresher,
            callback,
            lambda message: print(f"[security] {message}", flush=True),
        )
        if resolved:
            callback = resolved
    parsed = urllib.parse.urlsplit(callback)
    if not _is_oauth_callback(callback):
        raise RuntimeError(
            "refusing non-callback "
            f"host={parsed.netloc or '-'} path={parsed.path or '-'}"
        )
    error = _oauth_callback_error(callback)
    if error:
        raise RuntimeError(
            f"OAuth callback failed: {error} host={parsed.netloc or '-'} path={parsed.path or '-'}"
        )
    result = str(_follow_oauth_callback(refresher, callback) or "")
    if result.startswith("ERROR:"):
        raise RuntimeError(
            f"OAuth callback failed: {result[6:]} "
            f"host={parsed.netloc or '-'} path={parsed.path or '-'}"
        )
    try:
        setattr(refresher, "_last_oauth_callback", callback)
    except Exception:
        pass
    try:
        token, _detail = _warm_chatgpt_home(refresher, "post-callback")
    except Exception:
        return
    token = str(token or "").strip()
    if not token:
        return
    for attr in ("access_token", "web_access_token"):
        try:
            setattr(refresher, attr, token)
        except Exception:
            pass


def _password_already_usable(
    refresher: Any, email: str, password: str, emit: Callable[[str], None]
) -> bool | None:
    """Return whether the submitted password already works.

    True means verify succeeded. False means the account still has no such
    password. None means the check itself failed and the add result is unknown.
    """
    try:
        payload, final_url = _start_password_authorize(
            refresher, email, add_password=False
        )
        page = _payload_page(payload, final_url)
        if (
            page not in {"login_password", "password"}
            and "/log-in/password" not in final_url
        ):
            emit(
                f"核对密码未进入密码页: {page or urllib.parse.urlsplit(final_url).path or '-'}"
            )
            return False
        try:
            payload = _json_request(
                refresher,
                "post",
                f"{AUTH_BASE}/api/accounts/password/verify",
                headers=_sentinel_headers(
                    refresher, f"{AUTH_BASE}/log-in/password", "password_verify"
                ),
                json_data={"password": password},
            )
        except RuntimeError as exc:
            if "HTTP=400" in str(exc) or "HTTP=401" in str(exc):
                emit("核对确认密码尚未生效")
                return False
            emit(f"核对已提交密码失败: {type(exc).__name__}")
            return None
        page = _payload_page(payload)
        if page == "mfa_challenge" or _continue_url(payload):
            emit("核对确认密码已经生效")
            return True
        emit("核对密码响应无法确认是否生效")
        return None
    except Exception as exc:
        emit(f"核对已提交密码失败: {type(exc).__name__}")
        return None


def _should_fallback_to_add_password(exc: BaseException) -> bool:
    text = str(exc)
    if "browser_challenge" in text:
        return False
    if "HTTP=403" in text:
        return False
    if "HTTP=401" in text or "HTTP=400" in text:
        return True
    if "未进入密码登录页" in text or "email-verification" in text:
        return True
    return False


def _login_with_stored_password(
    refresher: Any,
    email: str,
    password: str,
    emit: Callable[[str], None],
    mail_url: str = "",
) -> None:
    seen_inbox = _snapshot_otp_inbox(mail_url) if mail_url else None
    payload, final_url = _start_password_authorize_with_recovery(
        refresher,
        email,
        add_password=False,
        emit=emit,
    )
    page = _payload_page(payload, final_url)
    if page in {"email_otp_verification"} or "email-verification" in final_url:
        raise RuntimeError("已有密码账号未进入密码登录页: email-verification")
    if (
        page not in {"login_password", "password"}
        and "/log-in/password" not in final_url
    ):
        raise RuntimeError("已有密码账号未进入密码登录页")
    payload = _json_request(
        refresher,
        "post",
        f"{AUTH_BASE}/api/accounts/password/verify",
        headers=_sentinel_headers(
            refresher, f"{AUTH_BASE}/log-in/password", "password_verify"
        ),
        json_data={"password": password},
    )
    if _payload_page(payload) == "mfa_challenge":
        raise RuntimeError("账号已启用 2FA，但数据库没有可用密钥")
    if _oauth_callback_url(str((payload or {}).get("_response_url") or "")):
        emit("password verify 已落到 callback")
        return
    callback = _pick_oauth_callback(refresher, payload, emit)
    if callback:
        _follow_callback(refresher, {**payload, "continue_url": callback})
        return
    if _needs_login_email_otp(payload, refresher):
        if not mail_url:
            raise RuntimeError("password verify 后需要邮箱验证: email-verification")
        emit("password verify 后进入邮箱验证，改收 OTP")
        code = _poll_fresh_email_otp(refresher, mail_url, email, emit, seen_inbox)
        if not code:
            raise RuntimeError("password login 邮箱验证未收到验证码")
        payload = _json_request(
            refresher,
            "post",
            f"{AUTH_BASE}/api/accounts/email-otp/validate",
            headers=_sentinel_headers(
                refresher, f"{AUTH_BASE}/email-verification", "email_otp_validate"
            ),
            json_data={"code": code},
        )
        if _oauth_callback_url(str((payload or {}).get("_response_url") or "")):
            emit("邮箱验证已落到 callback")
            return
        callback = _pick_oauth_callback(refresher, payload, emit)
        if callback:
            _follow_callback(refresher, {**payload, "continue_url": callback})
            return
        raise RuntimeError(
            "password login 邮箱验证后未取得 chatgpt callback "
            f"page={_payload_page(payload) or '-'}"
        )
    emit("password verify 没有 chatgpt callback，改从当前会话取 AT")


def _needs_login_email_otp(payload: dict, refresher: Any) -> bool:
    if _payload_page(payload) == "email_otp_verification":
        return True
    if _is_email_verification_url(_continue_url(payload)):
        return True
    if _is_email_verification_url(_session_dump_continue_url(refresher)):
        return True
    if _is_oauth_callback(str((payload or {}).get("_response_url") or "")):
        return False
    return False


def _pick_oauth_callback(
    refresher: Any, payload: dict, emit: Callable[[str], None]
) -> str:
    candidates = [_continue_url(payload), _session_dump_continue_url(refresher)]
    callback = _oauth_callback_url(*candidates)
    if callback:
        return callback
    for candidate in candidates:
        callback = _resolve_oauth_callback(refresher, candidate, emit)
        if callback:
            if _is_authorize_url(candidate):
                emit("从 authorize Location 取得 callback")
            elif candidate:
                emit("从 session dump 取得 callback")
            return callback
        if (
            candidate
            and not _is_authorize_url(candidate)
            and not _is_email_verification_url(candidate)
        ):
            emit(
                f"continue_url 不是 chatgpt callback path={urllib.parse.urlsplit(candidate).path or '-'}"
            )
    return ""


def _add_first_password(
    refresher: Any,
    *,
    email: str,
    mail_url: str,
    password: str,
    session_token: str,
    injected_refresher: bool,
    checkpoint: Any | None,
    emit: Callable[[str], None],
) -> None:
    from tokenrefresh.web import chatgpt_web_login

    if not mail_url:
        raise RuntimeError("首次设置密码需要取码 URL")
    session_ready = injected_refresher
    if session_ready:
        emit("沿用注册 callback 会话，跳过 ST 重建")
    elif session_token:
        try:
            _restore_session_token(refresher, session_token)
            session_ready = bool(_collect_tokens(refresher, emit).get("access_token"))
            if session_ready:
                emit("已恢复数据库 ST，本次跳过首次邮箱登录")
        except Exception as exc:
            emit(f"数据库 ST 已失效，改走邮箱登录: {str(exc)[:120]}")
    if not session_ready:
        chatgpt_web_login(
            refresher,
            email=email,
            password="",
            mail_url=mail_url,
            account_id="",
            fast=True,
        )
    seen_inbox = _snapshot_otp_inbox(mail_url)
    payload, final_url = _start_password_authorize_with_recovery(
        refresher,
        email,
        add_password=True,
        emit=emit,
    )
    page = _payload_page(payload, final_url)
    if "email-verification" not in final_url and page != "email_otp_verification":
        final_path = urllib.parse.urlsplit(final_url).path
        continue_path = urllib.parse.urlsplit(
            str(payload.get("continue_url") or "")
        ).path
        raise RuntimeError(
            "新增密码重新认证未进入邮箱验证页: "
            f"page={page or '-'} final={final_path or '-'} "
            f"continue={continue_path or '-'} keys={sorted(payload.keys())}"
        )
    code = _poll_fresh_email_otp(refresher, mail_url, email, emit, seen_inbox)
    if not code:
        raise RuntimeError("新增密码流程未收到邮箱验证码")
    payload = _json_request(
        refresher,
        "post",
        f"{AUTH_BASE}/api/accounts/email-otp/validate",
        headers=_sentinel_headers(
            refresher, f"{AUTH_BASE}/email-verification", "email_otp_validate"
        ),
        json_data={"code": code},
    )
    if _payload_page(payload) != "reset_password_new_password":
        raise RuntimeError("邮箱验证后未进入新增密码页")
    if checkpoint is not None:
        checkpoint.prepare("password", {"password": password})
        checkpoint.sent("password")
    try:
        payload = _json_request(
            refresher,
            "post",
            f"{AUTH_BASE}/api/accounts/password/add",
            headers=_sentinel_headers(
                refresher,
                f"{AUTH_BASE}/reset-password/new-password",
                "email_otp_validate",
            ),
            json_data={"password": password},
        )
    except RuntimeError as exc:
        if "HTTP=400" not in str(exc):
            raise
        emit("新增密码返回 400，核对密码是否已经生效")
        dump = _session_dump_continue_url(refresher)
        callback = _oauth_callback_url(dump) or _resolve_oauth_callback(
            refresher, dump, emit
        )
        if callback:
            emit("新增密码 400，改跟 session dump callback")
            if checkpoint is not None:
                checkpoint.confirm("password")
            _follow_callback(refresher, {"continue_url": callback})
            return
        usable = _password_already_usable(refresher, email, password, emit)
        if usable is True:
            payload = {}
        else:
            try:
                _warm_chatgpt_session(refresher)
                if _collect_tokens(refresher, emit, email=email).get("access_token"):
                    emit("新增密码 400，当前会话已有 AT")
                    if checkpoint is not None:
                        checkpoint.confirm("password")
                    return
            except Exception:
                pass
            if usable is False and checkpoint is not None:
                checkpoint.reject("password")
            raise
    if checkpoint is not None:
        checkpoint.confirm("password")
    if payload:
        _follow_callback(refresher, payload)


def _complete_totp_challenge(
    refresher: Any,
    payload: dict,
    totp_secret: str,
    *,
    previous_code: str = "",
    email: str = "",
) -> dict:
    from tokenrefresh.mfa import totp_code

    session = (payload or {}).get("oai-client-auth-session") or {}
    factors = [
        *(session.get("mfa_challenge_factors") or []),
        *(session.get("mfa_factors") or []),
    ]
    factor = next(
        (
            item
            for item in factors
            if item.get("factor_type") == "totp" and item.get("id")
        ),
        None,
    )
    if not factor:
        raise RuntimeError("2FA challenge missing TOTP factor")
    factor_id = str(factor["id"])
    challenge_url = str(
        payload.get("continue_url") or f"{AUTH_BASE}/mfa-challenge/{factor_id}"
    )
    remaining = 30 - (time.time() % 30)
    if previous_code:
        code = totp_code(totp_secret)
        if code == previous_code:
            code = _wait_for_new_totp_code(totp_secret, previous_code, email)
    else:
        if remaining < 2:
            time.sleep(remaining + 0.25)
        code = totp_code(totp_secret)
    headers = _auth_web_json_headers(refresher, challenge_url)
    _json_request(
        refresher,
        "post",
        f"{AUTH_BASE}/api/accounts/mfa/issue_challenge",
        headers=headers,
        json_data={"type": "totp", "id": factor_id, "force_fresh_challenge": False},
    )
    try:
        return _json_request(
            refresher,
            "post",
            f"{AUTH_BASE}/api/accounts/mfa/verify",
            headers=_auth_web_json_headers(refresher, challenge_url),
            json_data={"type": "totp", "id": factor_id, "code": code},
            retry_attempts=1,
        )
    except RuntimeError as exc:
        # A failed verify can invalidate the auth session and its challenge.
        # The caller must wait for a new code and rebuild the full session.
        raise _MfaVerifyAttemptError(str(exc), used_code=code) from exc


def _wait_for_new_totp_code(totp_secret: str, used_code: str, email: str) -> str:
    from tokenrefresh.mfa import totp_code

    jitter = (sum(str(email or "").encode("utf-8")) % 5000) / 1000
    for _attempt in range(2):
        remaining = 30 - (time.time() % 30)
        time.sleep(max(1.0, remaining + 0.25 + jitter))
        code = totp_code(totp_secret)
        if code != used_code:
            return code
    raise RuntimeError("TOTP code did not advance to a new time window")


def _homepage_access_token(refresher: Any, log: Callable[[str], None]) -> str:
    """HAR-aligned AT: chatgpt.com HTML often has accessToken when /api/auth/session is empty."""
    try:
        from tokenrefresh.web import _fetch_web_access_token

        web_at, _plan, _detail = _fetch_web_access_token(
            refresher,
            tries=2,
            base_pause=0.4,
            fail_fast_net=True,
        )
    except Exception as exc:
        log(f"homepage AT 提取失败: {type(exc).__name__}")
        return ""
    token = str(web_at or "").strip()
    if not token:
        log("homepage HTML 未包含 AT")
        return ""
    log("homepage HTML 已取得 AT")
    for attr in ("access_token", "web_access_token"):
        try:
            setattr(refresher, attr, token)
        except Exception:
            pass
    return token


def _retry_oauth_callback(refresher: Any, log: Callable[[str], None]) -> None:
    callback = str(getattr(refresher, "_last_oauth_callback", "") or "").strip()
    if not callback or getattr(refresher, "_oauth_callback_retried", False):
        return
    if not _is_oauth_callback(callback):
        return
    try:
        setattr(refresher, "_oauth_callback_retried", True)
    except Exception:
        pass
    try:
        from tokenrefresh.web import _follow_oauth_callback

        log("会话仍无 AT，再跟一次 callback")
        result = str(_follow_oauth_callback(refresher, callback) or "")
    except Exception as exc:
        log(f"callback 重试失败: {type(exc).__name__}")
        return
    if result.startswith("ERROR:"):
        log("callback 重试仍失败")


def _chatgpt_signin_next_url(
    refresher: Any, email: str, log: Callable[[str], None]
) -> str:
    from tokenrefresh.utils import request_with_retry, response_json

    csrf_resp, csrf_error = request_with_retry(
        refresher.session,
        "get",
        f"{CHATGPT_BASE}/api/auth/csrf",
        headers={"accept": "application/json", "referer": f"{CHATGPT_BASE}/"},
        verify=False,
        timeout=12,
    )
    csrf = response_json(csrf_resp) if csrf_resp is not None else {}
    csrf_token = str((csrf or {}).get("csrfToken") or "").strip()
    if not csrf_token:
        log(f"relink csrf 失败: {csrf_error or 'no csrfToken'}")
        return ""
    signin_params = {
        "prompt": "none",
        "ext-oai-did": str(getattr(refresher, "device_id", "") or ""),
        "auth_session_logging_id": str(uuid.uuid4()),
        "screen_hint": "login",
        "login_hint": email,
    }
    resp, err = request_with_retry(
        refresher.session,
        "post",
        f"{CHATGPT_BASE}/api/auth/signin/openai?"
        + urllib.parse.urlencode(signin_params),
        headers={
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "origin": CHATGPT_BASE,
            "referer": f"{CHATGPT_BASE}/",
            "user-agent": str(
                (getattr(refresher, "fingerprint_profile", None) or {}).get(
                    "user_agent"
                )
                or ""
            ),
        },
        data={
            "callbackUrl": f"{CHATGPT_BASE}/",
            "csrfToken": csrf_token,
            "json": "true",
        },
        allow_redirects=False,
        verify=False,
        timeout=25,
    )
    if resp is None:
        log(f"relink signin 失败: {err}")
        return ""
    try:
        next_url = str(
            (response_json(resp) or {}).get("url")
            or resp.headers.get("Location")
            or resp.headers.get("location")
            or ""
        ).strip()
    except Exception:
        next_url = str(
            resp.headers.get("Location") or resp.headers.get("location") or ""
        ).strip()
    if next_url:
        next_url = urllib.parse.urljoin(CHATGPT_BASE, next_url)
    return next_url


def _relink_chatgpt_access_token(
    refresher: Any,
    email: str,
    log: Callable[[str], None],
) -> str:
    if not str(email or "").strip() or getattr(
        refresher, "_chatgpt_relink_attempted", False
    ):
        return ""
    try:
        setattr(refresher, "_chatgpt_relink_attempted", True)
    except Exception:
        pass
    try:
        from tokenrefresh.web import _has_nextauth_session_cookie

        if _has_nextauth_session_cookie(refresher.session):
            return ""
        log("next-auth cookie 缺失，补一次 chatgpt signin")
        next_url = _chatgpt_signin_next_url(refresher, email, log)
        callback = _resolve_oauth_callback(refresher, next_url, log)
        if not callback:
            path = urllib.parse.urlsplit(next_url).path or "-"
            log(f"relink 未取得 chatgpt callback path={path}")
            return ""
        _follow_callback(refresher, {"continue_url": callback})
    except Exception as exc:
        log(f"chatgpt signin 补链失败: {type(exc).__name__}")
        return ""
    return _homepage_access_token(refresher, log)


def _collect_tokens(
    refresher: Any,
    log: Callable[[str], None],
    email: str = "",
) -> dict[str, Any]:
    from .chatgpt_login_st import fetch_st_from_auth_session

    access_token = str(
        getattr(refresher, "web_access_token", "")
        or getattr(refresher, "access_token", "")
        or ""
    )
    if not access_token:
        access_token = _homepage_access_token(refresher, log)
    if not access_token:
        access_token = _relink_chatgpt_access_token(refresher, email, log)
    st, session_at, cookies, session_http = fetch_st_from_auth_session(refresher, log)
    if not access_token:
        access_token = str(session_at or "")
    if not access_token and not st:
        raise RuntimeError(
            f"login completed without AT/ST (auth/session HTTP={session_http})"
        )
    return {
        "ok": True,
        "access_token": access_token,
        "st": st,
        "cookies": cookies,
        "cookies_json": __import__("json").dumps(cookies, ensure_ascii=False),
    }


def _warm_chatgpt_session(refresher: Any) -> None:
    try:
        from tokenrefresh.web import _warm_chatgpt_home

        at, _detail = _warm_chatgpt_home(refresher, "require-at")
        token = str(at or "").strip()
        if token:
            for attr in ("access_token", "web_access_token"):
                try:
                    setattr(refresher, attr, token)
                except Exception:
                    pass
            return
    except Exception:
        pass
    from tokenrefresh.utils import request_with_retry

    try:
        request_with_retry(
            refresher.session,
            "get",
            f"{CHATGPT_BASE}/",
            headers=refresher._navigate_headers(f"{CHATGPT_BASE}/"),
            allow_redirects=True,
            verify=False,
            timeout=12,
        )
    except Exception:
        pass


def _require_access_token(
    refresher: Any,
    emit: Callable[[str], None],
    email: str = "",
) -> dict[str, Any]:
    last_error: Exception | None = None
    tokens: dict[str, Any] = {}
    for attempt in range(2):
        if attempt:
            emit(f"会话未取得 AT，刷新后重试 {attempt}/1")
            _retry_oauth_callback(refresher, emit)
            _warm_chatgpt_session(refresher)
            time.sleep(0.4)
        try:
            tokens = _collect_tokens(refresher, emit, email=email)
        except Exception as exc:
            last_error = exc
            tokens = {}
            continue
        if str(tokens.get("access_token") or "").strip():
            return tokens
        last_error = RuntimeError("设置 2FA 前未取得 access token")
    if last_error:
        raise last_error
    raise RuntimeError("设置 2FA 前未取得 access token")


def _reset_mfa_checkpoint(checkpoint: Any | None) -> None:
    if checkpoint is None:
        return
    checkpoint.mfa_phase = False
    checkpoint.candidate = ""
    checkpoint.mfa_sent = False
    dispatched = getattr(checkpoint, "dispatched", None)
    if isinstance(dispatched, set):
        dispatched.clear()
    if hasattr(checkpoint, "last_error_detail"):
        checkpoint.last_error_detail = {}


def _enable_totp_on_refresher(
    refresher: Any,
    access_token: str,
    *,
    email: str,
    emit: Callable[[str], None],
    checkpoint: Any | None,
    warm_mfa_surface: bool,
) -> Any:
    from tokenrefresh.mfa import enable_totp_mfa_on_session

    if checkpoint is not None:
        checkpoint.begin_mfa()
    return enable_totp_mfa_on_session(
        refresher.session,
        access_token,
        email=email,
        device_id=str(getattr(refresher, "device_id", "") or ""),
        user_agent=str(getattr(refresher, "user_agent", "") or ""),
        skip_if_enabled=True,
        log_fn=emit,
        refresher=refresher,
        warm_surface=warm_mfa_surface,
    )


def _restore_session_token(refresher: Any, session_token: str) -> None:
    token = str(session_token or "").strip()
    if not token:
        return
    jar = refresher.session.cookies
    chunks = [token[index : index + 3800] for index in range(0, len(token), 3800)]
    names = (
        ["__Secure-next-auth.session-token"]
        if len(chunks) == 1
        else [
            f"__Secure-next-auth.session-token.{index}" for index in range(len(chunks))
        ]
    )
    for name, value in zip(names, chunks):
        jar.set(name, value, domain="chatgpt.com", path="/", secure=True)


def _select_web_workspace_if_needed(
    refresher: Any,
    email: str,
    workspace_id: str,
    payload: dict,
    emit: Callable[[str], None],
) -> dict:
    """Complete the /workspace step that password login can land on."""
    page = _payload_page(payload)
    continue_url = str((payload or {}).get("continue_url") or "")
    path = urllib.parse.urlsplit(continue_url).path.rstrip("/")
    workspace_pages = {
        "workspace",
        "workspace_select",
        "workspace_selection",
        "select_workspace",
        "workspace_picker",
    }
    if page not in workspace_pages and path not in {"/workspace", "/workspace/select"}:
        return payload

    from tokenrefresh.utils import request_with_retry, response_json
    from tokenrefresh.workspace import select_web_workspace

    dump_resp, dump_error = request_with_retry(
        refresher.session,
        "get",
        f"{AUTH_BASE}/api/accounts/client_auth_session_dump",
        headers={"accept": "application/json", "referer": f"{AUTH_BASE}/workspace"},
        verify=False,
        timeout=20,
    )
    dump = response_json(dump_resp) if dump_resp is not None else {}
    if not isinstance(dump, dict) or not dump:
        emit(f"workspace dump failed: {dump_error or 'empty'}")
        return payload
    selected = select_web_workspace(refresher, email, workspace_id, dump)
    emit("workspace selected")
    return selected if isinstance(selected, dict) and selected else payload


def login_with_password_totp(
    email: str,
    *,
    password: str,
    totp_secret: str = "",
    proxy: str = "",
    log: Callable[[str], None] | None = None,
    checkpoint: Any | None = None,
    profile_region: str = "JP",
    workspace_id: str = "",
) -> dict[str, Any]:
    """Login without mailbox access, using an account password and optional TOTP."""
    emit = _log_fn(log)
    authorize_recoveries = 0
    mfa_attempts = 0
    first_mfa_error = ""
    previous_mfa_code = ""
    for _session_attempt in range(4):
        refresher = None
        try:
            refresher = _new_refresher(
                email, proxy, emit, profile_region=profile_region
            )
            if checkpoint is not None:
                checkpoint.check()
                refresher.session = checkpoint.wrap_session(refresher.session)
            payload, final_url = _start_password_authorize(
                refresher, email, add_password=False
            )
            page = _payload_page(payload, final_url)
            authorize_stuck = (
                urllib.parse.urlsplit(final_url).path == "/api/accounts/authorize"
                and not page
            )
            if authorize_stuck:
                authorize_recoveries += 1
                if authorize_recoveries <= 2:
                    emit(
                        f"authorize 停留在中间态，重建认证会话 {authorize_recoveries}/2"
                    )
                    continue
            if (
                page not in {"login_password", "password"}
                and "/log-in/password" not in final_url
            ):
                raise RuntimeError(
                    f"password login expected password page, got {page or final_url[:100]}"
                )
            payload = _json_request(
                refresher,
                "post",
                f"{AUTH_BASE}/api/accounts/password/verify",
                headers=_sentinel_headers(
                    refresher, f"{AUTH_BASE}/log-in/password", "password_verify"
                ),
                json_data={"password": password},
            )
            page = _payload_page(payload)
            if page == "mfa_challenge":
                if not totp_secret:
                    raise RuntimeError("账号要求 2FA，但数据库没有 TOTP 密钥")
                mfa_attempts += 1
                payload = _complete_totp_challenge(
                    refresher,
                    payload,
                    totp_secret,
                    previous_code=previous_mfa_code,
                    email=email,
                )
            payload = _select_web_workspace_if_needed(
                refresher, email, workspace_id, payload, emit
            )
            _follow_callback(refresher, payload)
            return _collect_tokens(refresher, emit, email=email)
        except _MfaVerifyAttemptError as exc:
            current_error = str(exc)
            first_mfa_error = first_mfa_error or current_error
            if mfa_attempts >= 2:
                raise MfaVerificationExhaustedError(
                    "MFA verify failed after 2 fresh codes; "
                    f"first={first_mfa_error[:180]}; last={current_error[:180]}"
                ) from exc
            emit(
                f"MFA 校验失败，等待新 TOTP code 并重建认证会话 "
                f"{mfa_attempts}/2: {current_error[:140]}"
            )
            previous_mfa_code = exc.used_code
        except Exception as exc:
            if first_mfa_error:
                raise MfaVerificationExhaustedError(
                    "MFA fresh-code retry session failed; "
                    f"first={first_mfa_error[:180]}; retry={str(exc)[:180]}"
                ) from exc
            raise
        finally:
            if refresher is not None:
                try:
                    refresher.close()
                except Exception:
                    pass
    if first_mfa_error:
        raise MfaVerificationExhaustedError(
            f"MFA fresh-code retry exhausted; first={first_mfa_error[:180]}"
        )
    raise RuntimeError("password authorize recovery exhausted")


def restore_session_tokens(
    email: str,
    *,
    session_token: str,
    proxy: str = "",
    log: Callable[[str], None] | None = None,
    checkpoint: Any | None = None,
) -> dict[str, Any]:
    """Restore an existing NextAuth ST and collect the current AT/cookies.

    This is intentionally a best-effort fast path. Callers should fall back to
    password/TOTP login when the stored session has expired or was revoked.
    """
    emit = _log_fn(log)
    refresher = _new_refresher(email, proxy, emit)
    try:
        if checkpoint is not None:
            checkpoint.check()
            refresher.session = checkpoint.wrap_session(refresher.session)
        _restore_session_token(refresher, session_token)
        tokens = _collect_tokens(refresher, emit)
        if not tokens.get("access_token"):
            raise RuntimeError("恢复 ST 后未取得 AT")
        return tokens
    finally:
        try:
            refresher.close()
        except Exception:
            pass


def setup_login_security(
    email: str,
    *,
    mail_url: str,
    password: str,
    existing_password: bool,
    session_token: str = "",
    access_token: str = "",
    proxy: str = "",
    device_id: str = "",
    fingerprint_seed: str = "",
    profile_region: str = "",
    warm_mfa_surface: bool = True,
    post_success_check: Callable[[Any, str], dict[str, Any]] | None = None,
    log: Callable[[str], None] | None = None,
    refresher: Any | None = None,
    close_refresher: bool | None = None,
    chrome_major: int | None = None,
    checkpoint: Any | None = None,
) -> dict[str, Any]:
    """Set the first password through email OTP, then enable TOTP on the session."""
    mail_url = native_otp_mail_url(mail_url)
    emit = _log_fn(log)
    injected_refresher = refresher is not None
    if refresher is None:
        refresher = _new_refresher(
            email,
            proxy,
            emit,
            device_id=device_id,
            fingerprint_seed=fingerprint_seed or email,
            profile_region=str(profile_region or "JP").strip().upper() or "JP",
            chrome_major=150 if chrome_major is None else chrome_major,
        )
    else:
        # A transferred signup session owns the callback cookies, TLS handle,
        # device identity and proxy.  Reject an opaque/incomplete object early
        # instead of silently rebuilding a second session.
        session = getattr(refresher, "session", None)
        if not callable(getattr(session, "get", None)):
            raise RuntimeError("injected registration refresher has no live session")
    if close_refresher is None:
        close_refresher = not injected_refresher
    password_added = bool(existing_password)
    confirmed_secret = ""
    stored_access_token = str(access_token or "").strip()
    if checkpoint is not None:
        checkpoint.check()
        refresher.session = checkpoint.wrap_session(refresher.session)
    post_mfa_credential_refresh = "not_attempted"
    post_mfa_access_token_state = "unknown"
    try:
        tokens: dict[str, Any] = {}
        used_stored_at = False
        if existing_password and stored_access_token and not injected_refresher:
            emit("沿用已保存 AT，直接设置 2FA")
            tokens = {"ok": True, "access_token": stored_access_token}
            for attr in ("access_token", "web_access_token"):
                try:
                    setattr(refresher, attr, stored_access_token)
                except Exception:
                    pass
            try:
                mfa = _enable_totp_on_refresher(
                    refresher,
                    stored_access_token,
                    email=email,
                    emit=emit,
                    checkpoint=checkpoint,
                    warm_mfa_surface=warm_mfa_surface,
                )
                secret = str(getattr(mfa, "secret", "") or "")
                if getattr(mfa, "ok", False) and secret:
                    used_stored_at = True
                elif getattr(mfa, "already_enabled", False):
                    raise RuntimeError("账号已启用 2FA，但无法取得原 TOTP 密钥")
                else:
                    emit(
                        str(
                            getattr(mfa, "error", "")
                            or "已保存 AT 无法启用 2FA，改走登录"
                        )
                    )
            except RuntimeError as exc:
                if "已启用 2FA" in str(exc):
                    raise
                emit(f"已保存 AT 无法启用 2FA，改走登录: {str(exc)[:120]}")
            except Exception as exc:
                emit(f"已保存 AT 无法启用 2FA，改走登录: {type(exc).__name__}")
            if not used_stored_at:
                _reset_mfa_checkpoint(checkpoint)
                for attr in ("access_token", "web_access_token"):
                    try:
                        setattr(refresher, attr, "")
                    except Exception:
                        pass
                tokens = {}
                if not injected_refresher:
                    emit("已保存 AT 会话作废，重建浏览器会话后再登录")
                    try:
                        refresher.close()
                    except Exception:
                        pass
                    refresher = _new_refresher(
                        email,
                        proxy,
                        emit,
                        device_id=device_id,
                        fingerprint_seed=fingerprint_seed or email,
                        profile_region=str(profile_region or "JP").strip().upper()
                        or "JP",
                        chrome_major=150 if chrome_major is None else chrome_major,
                    )
                    if checkpoint is not None:
                        checkpoint.check()
                        refresher.session = checkpoint.wrap_session(refresher.session)

        if not used_stored_at:
            need_add_password = not existing_password
            if existing_password:
                restored = False
                if session_token and not injected_refresher:
                    try:
                        _restore_session_token(refresher, session_token)
                        restored = bool(
                            _collect_tokens(refresher, emit).get("access_token")
                        )
                        if restored:
                            emit("已恢复数据库 ST，跳过密码登录，直接设置 2FA")
                    except Exception as exc:
                        emit(f"数据库 ST 无法用于设置 2FA: {type(exc).__name__}")
                if not restored:
                    try:
                        _login_with_stored_password(
                            refresher, email, password, emit, mail_url=mail_url
                        )
                    except RuntimeError as exc:
                        if not _should_fallback_to_add_password(exc):
                            raise
                        emit(f"库内密码无法登录，改走新增密码: {str(exc)[:120]}")
                        _clear_reauth_authorize_state(refresher, emit)
                        need_add_password = True
            if need_add_password:
                _add_first_password(
                    refresher,
                    email=email,
                    mail_url=mail_url,
                    password=password,
                    session_token=session_token,
                    injected_refresher=injected_refresher,
                    checkpoint=checkpoint,
                    emit=emit,
                )
                password_added = True
            tokens = _require_access_token(refresher, emit, email=email)
            live_access_token = str(tokens.get("access_token") or "")
            if not live_access_token:
                raise RuntimeError("设置 2FA 前未取得 access token")
            mfa = _enable_totp_on_refresher(
                refresher,
                live_access_token,
                email=email,
                emit=emit,
                checkpoint=checkpoint,
                warm_mfa_surface=warm_mfa_surface,
            )
            secret = str(getattr(mfa, "secret", "") or "")
            if not getattr(mfa, "ok", False) or not secret:
                if getattr(mfa, "already_enabled", False):
                    raise RuntimeError("账号已启用 2FA，但无法取得原 TOTP 密钥")
                raise RuntimeError(str(getattr(mfa, "error", "") or "启用 2FA 失败"))

        secret = str(secret or "")
        access_token = str(tokens.get("access_token") or stored_access_token)
        if not access_token:
            raise RuntimeError("设置 2FA 前未取得 access token")
        pre_mfa_access_token = access_token
        confirmed_secret = secret
        if checkpoint is not None:
            checkpoint.complete_mfa(secret)
        try:
            refreshed_tokens = _collect_tokens(refresher, emit)
        except Exception as exc:
            post_mfa_credential_refresh = "failed"
            # MFA may rotate the SPA session, but refresh failure must not
            # invalidate password and TOTP setup that already completed.
            emit(f"MFA 后令牌刷新失败，继续使用原令牌: {type(exc).__name__}")
        else:
            post_mfa_credential_refresh = "succeeded"
            refreshed_access_token = str(refreshed_tokens.get("access_token") or "")
            if not refreshed_access_token:
                post_mfa_access_token_state = "missing"
            elif refreshed_access_token == pre_mfa_access_token:
                post_mfa_access_token_state = "unchanged"
            else:
                post_mfa_access_token_state = "rotated"
            for key in (
                "access_token",
                "st",
                "session_token",
                "cookies",
                "cookies_json",
            ):
                value = refreshed_tokens.get(key)
                if key == "cookies_json" and str(value or "").strip() in {"[]", "{}"}:
                    continue
                if value not in (None, "", [], {}):
                    tokens[key] = value
            access_token = str(tokens.get("access_token") or access_token)
        result = {
            **tokens,
            "password_added": password_added,
            "totp_enabled": True,
            "totp_secret": secret,
            "post_mfa_credential_refresh": post_mfa_credential_refresh,
            "post_mfa_access_token_state": post_mfa_access_token_state,
            # Preserve the non-secret identity that minted the rotated AT so
            # the sole post-registration check stays on this session's device
            # profile whether the refresher was injected or newly built.
            "oai_did": str(getattr(refresher, "device_id", "") or ""),
            "fingerprint": dict(getattr(refresher, "fingerprint_profile", None) or {}),
        }
        if post_success_check is not None:
            try:
                checked = post_success_check(refresher, access_token)
                if not isinstance(checked, dict):
                    raise TypeError("post-success check did not return an object")
                result["post_success_check"] = checked
            except Exception as exc:
                # Eligibility lookup is observational. A transport or adapter
                # failure must not invalidate completed password/TOTP setup.
                result["post_success_check"] = {
                    "ok": False,
                    "trial_ok": False,
                    "plus_trial_eligible": None,
                    "outcome": "check_error",
                    "error": f"post-success check failed: {type(exc).__name__}",
                }
        return result
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc)[:500],
            "password_added": password_added,
            "totp_enabled": bool(confirmed_secret),
            "totp_secret": confirmed_secret,
        }
    finally:
        if close_refresher:
            try:
                refresher.close()
            except Exception:
                pass
