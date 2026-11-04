"""ChatGPT Web 登录 + Codex OAuth（web session 路径）"""
import json, os, random, re, time, urllib.parse, uuid
from typing import Any

from . import constants as C
from .session import TokenRefresher
from .utils import (
    request_with_retry, response_json, save_debug, log_line,
    generate_pkce, apply_sentinel_headers,
)
from .workspace import select_web_workspace, select_workspace_and_follow, extract_code_from_payload
from .email_ import poll_email_direct, resend_email_otp, smsbower_set_status
from .email_ import _parse_smsbower_mail_url
# 已撤销今早 CF managed-challenge 自动 pass / rotate_proxy（速度拖垮）
# 保留 409/403 dead-state 软恢复判定，不把裸 403 当封号
from .cf_challenge import is_dead_authorize_continue_status

# 仅 SMSBower 等「多号共用一个收件箱」时按码去重；Hotmail 独立邮箱按 message_id/收件时间
_USED_OTP_CODES: set[str] = set()


def _apply_required_sentinel_headers(
    headers: dict[str, str],
    refresher: TokenRefresher,
    flow: str,
) -> None:
    """Attach and validate the complete Sentinel bundle for protected signup calls."""
    try:
        apply_sentinel_headers(
            headers,
            refresher.session,
            refresher.device_id,
            flow,
            profile=getattr(refresher, "fingerprint_profile", None),
        )
    except Exception as exc:
        # Do not copy provider/runtime exception text into job logs; it can
        # contain opaque token material. The exception chain remains available
        # to the caller for local diagnostics.
        raise RuntimeError(f"required_sentinel_failed flow={flow}") from exc

    main_raw = str(headers.get("openai-sentinel-token") or "")
    observer_raw = str(headers.get("openai-sentinel-so-token") or "")
    if not main_raw or not observer_raw:
        missing = []
        if not main_raw:
            missing.append("main")
        if not observer_raw:
            missing.append("so")
        raise RuntimeError(
            f"required_sentinel_incomplete flow={flow} missing={','.join(missing)}"
        )

    expected_id = str(refresher.device_id or "")
    for label, raw in (("main", main_raw), ("so", observer_raw)):
        try:
            token = json.loads(raw)
        except Exception as exc:
            raise RuntimeError(
                f"required_sentinel_invalid_json flow={flow} token={label}"
            ) from exc
        if not isinstance(token, dict):
            raise RuntimeError(
                f"required_sentinel_invalid_shape flow={flow} token={label}"
            )
        if str(token.get("flow") or "") != flow:
            raise RuntimeError(
                f"required_sentinel_flow_mismatch flow={flow} token={label}"
            )
        if expected_id and str(token.get("id") or "") != expected_id:
            raise RuntimeError(
                f"required_sentinel_device_mismatch flow={flow} token={label}"
            )


def _is_shared_inbox_mail_url(mail_url: str) -> bool:
    """共用收件箱才需要 ignore_codes；Hotmail API 不走码值去重。"""
    u = str(mail_url or "").lower()
    if not u:
        return False
    if "outlook.aitokensale.com" in u or u.startswith("hotmail://"):
        return False
    if "smsbower" in u:
        return True
    # 无明确 hotmail 标记的 http mail_url 按共享箱保守处理
    return u.startswith("http://") or u.startswith("https://")


def _poll_otp(mail_url, email, not_before=0, exclude_message_ids=None):
    """轮询 OTP。

    Hotmail：只靠 exclude_message_ids + received_at/not_before（新信同码可用）。
    共享 SMSBower 箱：才 ignore 已用过的码字符串。
    """
    ignore = None
    if _is_shared_inbox_mail_url(mail_url) and _USED_OTP_CODES:
        ignore = set(_USED_OTP_CODES)
    return poll_email_direct(
        mail_url,
        email,
        not_before=not_before,
        ignore_codes=ignore,
        exclude_message_ids=exclude_message_ids,
    )


def _build_chatgpt_web_authorize_url(email: str, device_id: str) -> str:
    """对齐浏览器：ChatGPT Web client + login_or_signup + login_hint。

    2026-07-22 HAR（22日注册抓包）额外 query：
      - auth_session_logging_id: 随机 UUID
      - ccaps=login_methods
    """
    import secrets as _sec

    params = {
        "client_id": C.CHATGPT_WEB_CLIENT_ID,
        "scope": C.CHATGPT_WEB_SCOPE,
        "response_type": "code",
        "redirect_uri": C.CHATGPT_WEB_REDIRECT_URI,
        "audience": "https://api.openai.com/v1",
        "device_id": device_id,
        "prompt": "login",
        "ext-oai-did": device_id,
        "screen_hint": C.CHATGPT_WEB_SCREEN_HINT,
        "login_hint": email,
        "state": _sec.token_urlsafe(32),
        # 对齐今日浏览器抓包（此前本地缺这两项）
        "auth_session_logging_id": str(uuid.uuid4()),
        "ccaps": "login_methods",
    }
    return f"{C.AUTH_BASE}/api/accounts/authorize?{urllib.parse.urlencode(params)}"


def _cookie_names(session) -> list[str]:
    names: list[str] = []
    try:
        for c in session.cookies:
            n = str(getattr(c, "name", "") or "")
            if n:
                names.append(n)
    except Exception:
        try:
            names = list(getattr(session.cookies, "keys", lambda: [])())
        except Exception:
            pass
    return names


def _has_nextauth_session_cookie(session) -> bool:
    for n in _cookie_names(session):
        low = n.lower()
        if "next-auth.session-token" in low or low == "__secure-next-auth.session-token":
            return True
        if low.startswith("__secure-next-auth.session-token"):
            return True
    return False


def _clear_stale_nextauth_cookies(session) -> int:
    """Drop next-auth cookies that break OAuth code exchange (→ OAuthCallback)."""
    removed = 0
    try:
        jar = session.cookies
        doomed = []
        for c in list(jar):
            n = str(getattr(c, "name", "") or "")
            low = n.lower()
            if "next-auth" in low:
                doomed.append(c)
        for c in doomed:
            try:
                jar.clear(
                    getattr(c, "domain", None) or "chatgpt.com",
                    getattr(c, "path", None) or "/",
                    getattr(c, "name", "") or "",
                )
                removed += 1
            except Exception:
                try:
                    del jar[getattr(c, "name", "")]
                    removed += 1
                except Exception:
                    pass
    except Exception:
        pass
    return removed


def _begin_nextauth_openai_signin(
    refresher: TokenRefresher,
    email: str,
    *,
    prompt: str = "login",
    clear_stale: bool = False,
    attempts: int = 3,
) -> str:
    """CSRF + POST signin/openai → authorize URL with next-auth state.

    Bare authorize without this step is the main source of error=OAuthCallback.
    """
    if clear_stale:
        n = _clear_stale_nextauth_cookies(refresher.session)
        if n:
            refresher._log(f"cleared {n} stale next-auth cookie(s)")

    fp = getattr(refresher, "fingerprint_profile", None) or {}
    ua = str(fp.get("user_agent") or C.USER_AGENT)

    for attempt in range(1, max(1, int(attempts)) + 1):
        try:
            request_with_retry(
                refresher.session,
                "get",
                "https://chatgpt.com/",
                headers=_nav_headers(refresher, "https://chatgpt.com/"),
                allow_redirects=True,
                verify=False,
                timeout=12,
            )
            request_with_retry(
                refresher.session,
                "get",
                "https://chatgpt.com/auth/login",
                headers=_nav_headers(refresher, "https://chatgpt.com/"),
                allow_redirects=True,
                verify=False,
                timeout=12,
            )
        except Exception:
            pass

        # csrf before signin/openai (providers warm removed — not ban-critical)
        try:
            request_with_retry(
                refresher.session,
                "get",
                "https://chatgpt.com/api/auth/providers",
                headers=_session_headers(refresher),
                verify=False,
                timeout=8,
            )
        except Exception:
            pass

        csrf_token = ""
        try:
            csrf_resp, _ = request_with_retry(
                refresher.session,
                "get",
                "https://chatgpt.com/api/auth/csrf",
                headers=_session_headers(refresher),
                verify=False,
                timeout=10,
            )
            csrf = response_json(csrf_resp) if csrf_resp is not None else {}
            csrf_token = str(csrf.get("csrfToken") or "").strip()
        except Exception as e:
            refresher._log(f"csrf attempt {attempt}/{attempts}: {e}")
            csrf_token = ""

        if not csrf_token:
            refresher._log(f"csrf empty attempt={attempt}/{attempts}")
            if attempt < attempts:
                _warm_chatgpt_home(refresher, f"csrf-retry-{attempt}")
                time.sleep(0.35 * attempt)
            continue

        # 8-2 HAR 对齐：浏览器 signin/openai 与 authorize 均不带 ext-passkey-client-capabilities
        signin_params = {
            "prompt": prompt,
            "ext-oai-did": refresher.device_id,
            "auth_session_logging_id": str(
                getattr(refresher, "_signup_auth_session_logging_id", "") or uuid.uuid4()
            ),
            "screen_hint": C.CHATGPT_WEB_SCREEN_HINT,
            "login_hint": email,
        }
        signin_url = (
            "https://chatgpt.com/api/auth/signin/openai?"
            + urllib.parse.urlencode(signin_params)
        )
        resp, err = request_with_retry(
            refresher.session,
            "post",
            signin_url,
            headers={
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded",
                "origin": "https://chatgpt.com",
                "referer": "https://chatgpt.com/",
                "user-agent": ua,
            },
            data={
                "callbackUrl": "https://chatgpt.com/",
                "csrfToken": csrf_token,
                "json": "true",
            },
            allow_redirects=False,
            verify=False,
            timeout=18,
        )
        if resp is None:
            refresher._log(f"signin/openai fail attempt={attempt}: {err}")
            if attempt < attempts:
                time.sleep(0.35 * attempt)
            continue

        next_url = ""
        try:
            payload = response_json(resp) if resp is not None else {}
            next_url = str(
                (payload or {}).get("url")
                or resp.headers.get("Location")
                or resp.headers.get("location")
                or ""
            ).strip()
        except Exception:
            next_url = str(
                resp.headers.get("Location") or resp.headers.get("location") or ""
            ).strip()

        if next_url:
            auth_url = urllib.parse.urljoin("https://chatgpt.com", next_url)
            refresher._log(
                f"next-auth signin OK attempt={attempt} "
                f"http={getattr(resp, 'status_code', '?')} url={auth_url[:120]}"
            )
            return auth_url

        refresher._log(
            f"signin/openai no url attempt={attempt} "
            f"http={getattr(resp, 'status_code', '?')} body={(resp.text or '')[:120]}"
        )
        if attempt < attempts:
            _clear_stale_nextauth_cookies(refresher.session)
            _warm_chatgpt_home(refresher, f"signin-retry-{attempt}")
            time.sleep(0.4 * attempt)

    return ""


def _nav_headers(refresher: TokenRefresher, referer: str = "") -> dict:
    return refresher._navigate_headers(referer or "https://chatgpt.com/")


def _session_headers(refresher: TokenRefresher) -> dict:
    fp = getattr(refresher, "fingerprint_profile", None) or {}
    ua = str(fp.get("user_agent") or C.USER_AGENT)
    lang = str(fp.get("language") or "en-US")
    accept_language = str(fp.get("accept_language") or "").strip()
    h = {
        "accept": "application/json",
        "user-agent": ua,
        "referer": C.CHATGPT_WEB_REFERER,
        "origin": "https://chatgpt.com",
        "oai-language": lang,
        "accept-language": accept_language or f"{lang},{lang.split('-')[0]};q=0.9",
    }
    did = getattr(refresher, "device_id", None)
    if did:
        h["oai-device-id"] = str(did)
    return h


def _extract_access_token_from_html(html: str) -> str:
    """Pull next-auth accessToken embedded in chatgpt.com HTML (manual HAR path).

    Real browsers after callback load https://chatgpt.com/ which SSR/hydrates
    ``"accessToken":"eyJ..."`` — they often never hit /api/auth/session.
    """
    text = str(html or "")
    if "accessToken" not in text and "access_token" not in text:
        return ""
    patterns = (
        r'"accessToken"\s*:\s*"(eyJ[^"]+)"',
        r'"access_token"\s*:\s*"(eyJ[^"]+)"',
        r'\\"accessToken\\"\s*:\s*\\"(eyJ[^\\"]+)\\"',
        r'accessToken&quot;:&quot;(eyJ[^&]+)',
    )
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            tok = (m.group(1) or "").strip()
            if tok.startswith("eyJ") and tok.count(".") >= 2:
                return tok
    return ""


def _plan_from_access_token(access_token: str) -> str:
    """Best-effort plan label from JWT payload (no network)."""
    try:
        parts = str(access_token or "").split(".")
        if len(parts) < 2:
            return "unknown"
        import base64

        pad = "=" * ((4 - len(parts[1]) % 4) % 4)
        raw = base64.urlsafe_b64decode(parts[1] + pad)
        data = json.loads(raw.decode("utf-8", errors="replace"))
        if not isinstance(data, dict):
            return "unknown"
        auth = data.get("https://api.openai.com/auth") or {}
        if isinstance(auth, dict):
            pt = str(auth.get("chatgpt_plan_type") or "").strip()
            if pt:
                return pt
        return str(data.get("chatgpt_plan_type") or data.get("plan_type") or "free")
    except Exception:
        return "unknown"


def _warm_chatgpt_home(
    refresher: TokenRefresher, reason: str = ""
) -> tuple[str, str]:
    """GET https://chatgpt.com/ (browser post-callback). Return (accessToken, detail).

    Body is parsed for embedded accessToken — aligns with manual DE/KR/JP HARs
    that never call /api/auth/session during signup.
    """
    if reason:
        refresher._log(f"warm chatgpt.com ({reason})")
    resp, err = request_with_retry(
        refresher.session,
        "get",
        "https://chatgpt.com/",
        headers=_nav_headers(refresher, "https://chatgpt.com/"),
        allow_redirects=True,
        verify=False,
        timeout=15,
    )
    if resp is None:
        return "", f"home_get_failed:{err}"
    body = getattr(resp, "text", None) or ""
    status = getattr(resp, "status_code", "?")
    final = str(getattr(resp, "url", "") or "")[:120]
    at = _extract_access_token_from_html(body)
    detail = (
        f"home HTTP={status} body_len={len(body)} token_len={len(at)} final={final}"
    )
    if at:
        refresher._log(f"accessToken from homepage HTML ({reason or 'warm'}): {detail}")
    else:
        refresher._log(f"homepage has no accessToken yet ({reason or 'warm'}): {detail}")
    return at, detail


def _session_get(
    refresher: TokenRefresher,
    url: str,
    *,
    referer: str = "https://chatgpt.com/",
    timeout: float = 40,
):
    return request_with_retry(
        refresher.session,
        "get",
        url,
        headers=_nav_headers(refresher, referer),
        allow_redirects=True,
        verify=False,
        timeout=timeout,
    )


def _authorize_get_with_cf_pass(
    refresher: TokenRefresher,
    auth_url: str,
    *,
    referer: str = "https://chatgpt.com/",
    timeout: float = 40,
):
    """GET authorize（已关闭今早 CF auto-pass / rotate_proxy，等同普通导航 GET）。

    函数名保留以免大面积改调用点；行为回到 request_with_retry 直连。
    """
    return _session_get(refresher, auth_url, referer=referer, timeout=timeout)


def _login_hint_from_url(url: str) -> str:
    try:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(str(url or "")).query)
        return str((qs.get("login_hint") or [""])[0] or "").strip()
    except Exception:
        return ""


def _oauth_error_from_url(url: str) -> tuple[str, str]:
    """Parse error / error_description from OAuth callback URL."""
    try:
        from urllib.parse import parse_qs, unquote, urlparse

        qs = parse_qs(urlparse(str(url or "")).query)
        err = str((qs.get("error") or [""])[0] or "").strip()
        desc = unquote(str((qs.get("error_description") or [""])[0] or "")).strip()
        return err, desc
    except Exception:
        return "", ""


def _is_soft_callback_error(err_tag: str) -> bool:
    """Callback failures that must NOT be treated as account ban/deactivated.

    HAR (vtwnnamuba): browser also sees authorize/callback 403 under CF, then
    recovers; create_account may already have succeeded. Recover path re-OTP.
    """
    t = str(err_tag or "").strip()
    low = t.lower()
    if not low:
        return False
    if low in (
        "access_denied",
        "oauthcallback",
        "callback",
        "auth_error",
        "auth/error",
    ):
        return True
    if low.startswith("access_denied"):
        return True
    # CF / WAF / edge on chatgpt.com callback — soft, recover via fresh authorize
    if low.startswith("callback_http_403") or low == "callback_http_403":
        return True
    if low.startswith("callback_http_429") or low == "callback_http_429":
        return True
    if low in ("callback_no_redirect", "callback_request_failed", "callback_empty"):
        return True
    return False


def _follow_oauth_callback(refresher: TokenRefresher, callback_url: str) -> str:
    """Follow create_account/workspace continue_url; return final URL.

    Returns "" if skipped; "ERROR:<code>" if callback is an OAuth error URL
    or the exchange permanently fails (HTTP 5xx / stuck on callback URL).

    Important: HTTP 503/403 on /api/auth/callback must NOT be treated as
    account ban. 403 is often CF/WAF (see browser HAR). Retry + warm home;
    remaining soft codes are recovered by caller via fresh authorize+OTP.
    """
    url = str(callback_url or "").strip()
    if not url:
        return ""
    if url.startswith("/"):
        url = urllib.parse.urljoin("https://chatgpt.com", url)
    err, desc = _oauth_error_from_url(url)
    if err:
        refresher._log(
            f"OAuth callback ERROR error={err} desc={desc[:160]} — do not follow"
        )
        return f"ERROR:{err}"
    refresher._log(f"following OAuth callback... {url[:140]}")

    # BrowserParity: overlap final oauth_create_account challenge with callback
    # (Eda ConcurrentFinalSentinel). Fire-and-forget; failure is non-fatal.
    _final_sen_done = None
    try:
        from .formal_frame import formal_frame_enabled

        _parity = (os.environ.get("TOKENREFRESH_BROWSER_PARITY") or "1").strip().lower() not in (
            "0", "false", "no", "off",
        )
        if formal_frame_enabled() or _parity:
            import concurrent.futures

            def _final_create_sen():
                try:
                    apply_sentinel_headers(
                        {},
                        refresher.session,
                        refresher.device_id,
                        "oauth_create_account",
                        profile=getattr(refresher, "fingerprint_profile", None),
                    )
                    return True
                except Exception as e:
                    refresher._log(f"post-callback sentinel ignore: {e}")
                    return False

            _pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            _final_sen_done = _pool.submit(_final_create_sen)
            try:
                refresher._log("concurrent final oauth_create_account sentinel started")
            except Exception:
                pass
    except Exception:
        _final_sen_done = None

    final = ""
    last_status: Any = "?"
    last_err = ""
    # 503/502/403 common under concurrent proxy / CF; short retries + warm.
    max_tries = 4
    for attempt in range(1, max_tries + 1):
        # 8-2 callback HAR：完整 Client Hints（arch/bitness/full-version-list…）必须带上，
        # 只发基础 sec-ch-ua 三件套会被 chatgpt.com 的 CF/WAF 直接 403
        # Firefox formal-frame: no Client Hints (stripped in _apply_client_hints)
        cb_h = _nav_headers(refresher, f"{C.AUTH_BASE}/")
        try:
            refresher._apply_client_hints(cb_h)
        except Exception:
            pass
        cb_h.setdefault("sec-fetch-site", "cross-site")
        resp, err2 = request_with_retry(
            refresher.session,
            "get",
            url,
            headers=cb_h,
            allow_redirects=True,
            verify=False,
            timeout=25,
        )
        if resp is None:
            last_err = str(err2 or "")
            refresher._log(
                f"callback request failed attempt={attempt}/{max_tries}: {last_err[:160]}"
            )
            if attempt < max_tries:
                try:
                    _warm_chatgpt_home(refresher, "callback-net-retry")
                except Exception:
                    pass
                time.sleep(0.4 * attempt)
                continue
            return "ERROR:callback_request_failed"

        last_status = getattr(resp, "status_code", "?")
        final = str(getattr(resp, "url", "") or "")
        ferr, fdesc = _oauth_error_from_url(final)
        if ferr or "/auth/error" in final:
            refresher._log(
                f"callback landed on error final={final[:140]} "
                f"err={ferr or 'auth/error'} {fdesc[:80]}"
            )
            return f"ERROR:{ferr or 'auth_error'}"

        status_i = int(last_status) if str(last_status).isdigit() else 0
        still_on_callback = "/api/auth/callback" in (final or "")
        sess_ok = _has_nextauth_session_cookie(refresher.session)
        refresher._log(
            f"callback done HTTP={last_status} "
            f"final={final[:140]} sess_cookie={sess_ok} attempt={attempt}/{max_tries}"
        )

        # Healthy path (matches historical success logs): HTTP 200 and left
        # the callback URL (or already has next-auth session cookie).
        if status_i == 200 and (not still_on_callback or sess_ok or "chatgpt.com" in final):
            if still_on_callback and not sess_ok and "code=" in (final or url):
                # 200 but never redirected off callback — treat as soft fail, retry
                if attempt < max_tries:
                    time.sleep(0.4 * attempt)
                    continue
                if _final_sen_done is not None:
                    try:
                        _final_sen_done.result(timeout=45)
                    except Exception:
                        pass
                return "ERROR:callback_no_redirect"
            if _final_sen_done is not None:
                try:
                    _final_sen_done.result(timeout=45)
                except Exception:
                    pass
            _warm_chatgpt_home(refresher, "post-callback")
            return final

        # Transient: gateway 5xx + WAF 403 + rate-limit 429（不再做 CF form pass）
        if status_i in (502, 503, 504, 403, 408, 429) or (status_i >= 500):
            if attempt < max_tries:
                refresher._log(
                    f"callback soft HTTP {status_i} — warm chatgpt.com + retry "
                    f"(not account deactivated)"
                )
                try:
                    _warm_chatgpt_home(refresher, f"callback-retry-{status_i}")
                except Exception:
                    pass
                time.sleep(0.55 * attempt)
                continue
            return f"ERROR:callback_http_{status_i}"

        # Other non-200
        if status_i and status_i != 200:
            return f"ERROR:callback_http_{status_i or 'unknown'}"

        if attempt < max_tries:
            time.sleep(0.4 * attempt)
            continue
        break

    # Always land on chatgpt.com so next-auth can finish writing cookies
    _warm_chatgpt_home(refresher, "post-callback")
    return final or "ERROR:callback_empty"


def _complete_create_account_about_you(refresher: TokenRefresher) -> dict[str, Any]:
    """POST create_account name/birthdate; return payload with continue_url if any.

    UI collects **age**; client wires ``birthdate`` = today − age years (HAR).
    We sample age first, then derive birthdate — never random Y-M-D segments.
    """
    from .names import random_about_you_detailed
    from .humanize import human_pause

    human_pause("pre_create")
    refresher._log("completing about_you (create_account)...")
    about = random_about_you_detailed(refresher)
    name = str(about.get("name") or "").strip()
    age = int(about.get("age") or 0)
    # HARD RULE: UI only types age → wire birthdate = today − age years (same M/D).
    # Never trust a random Y-M-D (e.g. shadowed legacy names.random_birthdate).
    from .names import birthdate_from_age

    if age < 18:
        age = 18
    birthdate = birthdate_from_age(age)
    try:
        setattr(refresher, "_about_you_age", age)
        setattr(refresher, "_about_you_birthdate", birthdate)
    except Exception:
        pass
    refresher._log(
        f"about_you name={name!r} age={age} birthdate={birthdate} "
        f"(UI=age → wire=today-{age}y same month/day)"
    )
    h = refresher._json_headers(f"{C.AUTH_BASE}/about-you")
    # BrowserParity: prime the same flow used by the browser create request.
    _parity = (os.environ.get("TOKENREFRESH_BROWSER_PARITY") or "1").strip().lower() not in (
        "0", "false", "no", "off",
    )
    create_flow = "oauth_create_account"
    try:
        from .formal_frame import formal_frame_enabled

        if formal_frame_enabled() or _parity:
            try:
                apply_sentinel_headers(
                    {},
                    refresher.session,
                    refresher.device_id,
                    "oauth_create_account",
                    profile=getattr(refresher, "fingerprint_profile", None),
                )
            except Exception as pe:
                refresher._log(f"sentinel prime ignore: {pe}")
    except Exception:
        pass
    _apply_required_sentinel_headers(h, refresher, create_flow)
    human_pause("micro")
    resp, err = request_with_retry(
        refresher.session,
        "post",
        f"{C.AUTH_BASE}/api/accounts/create_account",
        json_data={"name": name, "birthdate": birthdate},
        headers=h,
        verify=False,
        timeout=25,
        allow_redirects=False,
    )
    status = getattr(resp, "status_code", "?")
    refresher._log(f"create_account: HTTP {status}")
    if resp is None:
        raise RuntimeError(f"create_account request failed: {err}")
    payload = response_json(resp) if resp.status_code in (200, 302, 303) else {}
    if not isinstance(payload, dict):
        payload = {}
    cont = str(payload.get("continue_url") or "").strip()
    if not cont and resp.status_code in (302, 303):
        cont = str(resp.headers.get("Location") or resp.headers.get("location") or "")
        if cont:
            payload = {"continue_url": cont, "page": {"type": "external_url"}}
    page_type = str(((payload.get("page") or {}).get("type")) or "")
    refresher._log(
        f"create_account done: page_type={page_type or '-'} "
        f"continue_url={(cont[:100] if cont else '-')}"
    )
    if resp.status_code not in (200, 302, 303):
        body = (resp.text or "")[:200]
        raise RuntimeError(f"create_account failed HTTP {status}: {body}")
    return payload


def _recover_after_oauth_denied(
    refresher: TokenRefresher,
    email: str,
    mail_url: str,
    *,
    exclude_message_ids: set[str] | None = None,
) -> tuple[str, str, str]:
    """Fresh next-auth signin + optional OTP after access_denied / OAuthCallback.

    Must restart via csrf+signin (not bare authorize), or chatgpt.com keeps
    returning error=OAuthCallback. Prefer NEW mail OTP (not_before now).
    """
    refresher._log("recover: fresh next-auth signin after OAuthCallback/access_denied")
    _warm_chatgpt_home(refresher, "recover-start")
    try:
        _try_relink_chatgpt_signin(refresher, email)
        web_at, plan, detail = _fetch_web_access_token(
            refresher, tries=2, base_pause=0.35, fail_fast_net=True
        )
        if web_at:
            refresher._log(f"recover: relink produced token plan={plan}")
            return web_at, plan, detail
    except Exception as e:
        refresher._log(f"recover relink soft: {e}")

    auth_url = _begin_nextauth_openai_signin(
        refresher, email, prompt="login", clear_stale=True, attempts=3
    )
    if not auth_url:
        refresher._log("recover: next-auth failed — last resort direct authorize")
        auth_url = _build_chatgpt_web_authorize_url(email, refresher.device_id)
    # Force NEW otp: ignore mail older than now-2s (avoid consent verifier reuse)
    not_before = time.time() - 2.0
    resp, err = _authorize_get_with_cf_pass(
        refresher,
        auth_url,
        referer="https://chatgpt.com/",
        timeout=40,
    )
    if resp is None:
        return "", "unknown", f"recover authorize failed: {err}"
    final_url = str(getattr(resp, "url", "") or "")
    refresher._log(f"recover authorize final_url={final_url[:140]}")
    payload: dict[str, Any] = {}
    page_type = ""
    need_otp = "email-verification" in final_url or "email_otp" in final_url

    if not need_otp:
        h = refresher._json_headers(f"{C.AUTH_BASE}/create-account")
        try:
            apply_sentinel_headers(
            h, refresher.session, refresher.device_id, "authorize_continue",
            profile=getattr(refresher, "fingerprint_profile", None))
        except Exception:
            pass
        resp2, _ = request_with_retry(
            refresher.session,
            "post",
            f"{C.AUTH_BASE}/api/accounts/authorize/continue",
            json_data={
                "username": {"kind": "email", "value": email},
                "screen_hint": C.CHATGPT_WEB_SCREEN_HINT,
            },
            headers=h,
            verify=False,
        )
        if resp2 is not None and resp2.status_code == 200:
            payload = response_json(resp2) or {}
            page_type = str(((payload.get("page") or {}).get("type")) or "")
            refresher._log(f"recover continue page_type={page_type}")
            if page_type in (
                "email_otp_verification",
                "email_otp_send",
                "email_otp_verification_registration",
            ):
                need_otp = True
            elif page_type == "create_account_password":
                need_otp = _force_passwordless_otp(refresher, email)
                not_before = time.time() - 5.0

    if need_otp:
        if not mail_url:
            return "", "unknown", "recover needs mail_url for second OTP"
        payload = {}
        page_type = ""
        otp_ok = False
        for recover_otp_try in range(2):
            if recover_otp_try > 0:
                refresher._log("recover OTP 401 → reopen challenge once")
                if not _reopen_email_otp_challenge(refresher, email):
                    break
                not_before = time.time() - 2
                time.sleep(max(0.8, float(getattr(C, "EMAIL_RESEND_WAIT_SECONDS", 2.0) or 2.0)))
            code = _poll_otp(
                mail_url,
                email,
                not_before=not_before,
                exclude_message_ids=exclude_message_ids,
            )
            if not code:
                if recover_otp_try == 0:
                    continue
                return "", "unknown", "recover second OTP missing"
            # 码到即提交（与主路径一致；不再强制 2~5s）
            h = refresher._json_headers(f"{C.AUTH_BASE}/email-verification")
            _apply_required_sentinel_headers(
                h, refresher, "email_otp_validate"
            )
            refresher._log(f"recover OTP validating code={code}...")
            vresp, verr = request_with_retry(
                refresher.session,
                "post",
                f"{C.AUTH_BASE}/api/accounts/email-otp/validate",
                json_data={"code": code},
                headers=h,
                verify=False,
                timeout=25,
            )
            st = getattr(vresp, "status_code", None)
            if vresp is not None and st == 200:
                payload = response_json(vresp) or {}
                page_type = str(((payload.get("page") or {}).get("type")) or "")
                _USED_OTP_CODES.add(code)
                refresher._log(f"recover OTP ok page_type={page_type}")
                otp_ok = True
                break
            _USED_OTP_CODES.add(code)
            if st == 401 and recover_otp_try == 0:
                refresher._log(f"recover OTP validate HTTP 401, will reopen authorize")
                continue
            return "", "unknown", f"recover OTP validate failed: {verr or st or '?'}"
        if not otp_ok:
            return "", "unknown", "recover OTP validate failed after reopen"

    if page_type == "about_you":
        try:
            payload = _complete_create_account_about_you(refresher)
            page_type = str(((payload.get("page") or {}).get("type")) or page_type)
        except Exception as e:
            return "", "unknown", f"recover create_account: {e}"

    if page_type in (
        "workspace",
        "workspace_select",
        "workspace_selection",
        "select_workspace",
        "workspace_picker",
    ):
        dump_resp, _ = request_with_retry(
            refresher.session,
            "get",
            f"{C.AUTH_BASE}/api/accounts/client_auth_session_dump",
            headers={"accept": "application/json", "referer": f"{C.AUTH_BASE}/workspace"},
            verify=False,
            timeout=20,
        )
        if dump_resp is not None:
            from .workspace import select_web_workspace

            payload = select_web_workspace(
                refresher, email, "", response_json(dump_resp)
            )
            page_type = str(((payload.get("page") or {}).get("type")) or page_type)

    cont = str((payload or {}).get("continue_url") or "").strip()
    if cont:
        followed = _follow_oauth_callback(refresher, cont)
        if str(followed).startswith("ERROR:"):
            return "", "unknown", f"recover still oauth error: {followed}"
    else:
        _warm_chatgpt_home(refresher, "recover-no-continue")

    # recover path: short poll only
    return _fetch_web_access_token(refresher, tries=3, base_pause=0.4, fail_fast_net=True)


def _fetch_web_access_token_login_mode(
    refresher: TokenRefresher,
    *,
    tries: int = 1,
    base_pause: float = 0.15,
) -> tuple[str, str, str]:
    """Fast AT probe for login-existing: **1 home + at most 1 session poll**.

    Previous version nested tries=3 home × tries=3 session with fallback re-entry
    and burned 60–120s spinning on WARNING_BANNER-only session JSON (no login).
    """
    # One homepage dig only
    at, detail = _warm_chatgpt_home(refresher, "login-at-home")
    if at:
        plan = _plan_from_access_token(at)
        try:
            refresher.web_access_token = at
            refresher.access_token = at
            refresher.web_plan_type = plan
        except Exception:
            pass
        return at, plan, detail

    # Single /api/auth/session — fail immediately if not logged in
    refresher._log("login-existing: one-shot /api/auth/session probe")
    resp, err = request_with_retry(
        refresher.session,
        "get",
        C.CHATGPT_SESSION_URL,
        headers=_session_headers(refresher),
        verify=False,
        timeout=12,
    )
    if resp is None:
        return "", "unknown", f"session probe err={err}"
    data = response_json(resp) if getattr(resp, "status_code", 0) == 200 else {}
    if not isinstance(data, dict):
        data = {}
    at = str(data.get("accessToken") or data.get("access_token") or "").strip()
    keys = list(data.keys())[:8]
    refresher._log(
        f"login-existing session probe HTTP={getattr(resp, 'status_code', '?')} "
        f"keys={keys} token_len={len(at)}"
    )
    if at:
        plan = _classify_session_plan(data)
        try:
            refresher.web_access_token = at
            refresher.access_token = at
            refresher.web_plan_type = plan
        except Exception:
            pass
        return at, plan, f"session_ok keys={keys}"
    # WARNING_BANNER-only / empty = not logged in — do NOT retry loops
    return "", "unknown", f"session_no_token keys={keys}"


def _auth_session_continue_url(refresher: TokenRefresher) -> str:
    """Best-effort continue_url from auth.openai.com client_auth_session_dump."""
    try:
        dump_resp, _ = request_with_retry(
            refresher.session,
            "get",
            f"{C.AUTH_BASE}/api/accounts/client_auth_session_dump",
            headers={
                "accept": "application/json",
                "referer": f"{C.AUTH_BASE}/",
            },
            verify=False,
            timeout=20,
        )
        if dump_resp is None or getattr(dump_resp, "status_code", 0) != 200:
            return ""
        payload = response_json(dump_resp) or {}
        if not isinstance(payload, dict):
            return ""
        cont = str(payload.get("continue_url") or "").strip()
        if cont:
            return cont
        page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
        cont = str(
            (page or {}).get("continue_url")
            or (page or {}).get("url")
            or ""
        ).strip()
        if cont:
            return cont
        # nested client_auth_session
        cas = payload.get("client_auth_session")
        if isinstance(cas, dict):
            cont = str(cas.get("continue_url") or cas.get("url") or "").strip()
            if cont:
                return cont
    except Exception as exc:
        try:
            refresher._log(f"login-existing: session_dump ignore: {exc}")
        except Exception:
            pass
    return ""


def _login_existing_account_for_at(
    refresher: TokenRefresher,
    email: str,
    mail_url: str,
    *,
    exclude_message_ids: set[str] | None = None,
    redirect_uri: str = "",
    reason: str = "user_already_exists",
) -> tuple[str, str, str]:
    """Existing ChatGPT account → one lean passwordless login → accessToken.

    Time budget target: ~20–45s (one OTP), not 120–180s.

    Anti-patterns removed vs first draft:
      - no multi-round home dig + session poll spin on WARNING_BANNER
      - no full signup then full login then otp_proxy attempt=2 cascade by default
      - only one authorize+OTP leg; fail fast if still no token
    """
    email = (email or "").strip().lower()
    mail_url = (mail_url or "").strip() or f"msoauth://{email}"
    try:
        setattr(refresher, "_account_already_exists", True)
    except Exception:
        pass
    t0 = time.time()
    refresher._log(f"login-existing ({reason}): lean login path for accessToken")

    # ── A) cheap: dump continue_url / one redirect / one AT probe (≤ few seconds) ──
    cont0 = _auth_session_continue_url(refresher)
    if cont0:
        refresher._log(f"login-existing: dump continue_url={cont0[:100]}")
        followed = _follow_oauth_callback(refresher, cont0)
        if not str(followed).startswith("ERROR:"):
            at, plan, detail = _fetch_web_access_token_login_mode(refresher)
            if at:
                return at, plan, detail

    redir = (redirect_uri or "").strip()
    if redir:
        try:
            refresher._log(f"login-existing: one redirect {redir[:100]}")
            request_with_retry(
                refresher.session,
                "get",
                redir,
                headers=refresher._navigate_headers(f"{C.AUTH_BASE}/about-you"),
                allow_redirects=True,
                verify=False,
                timeout=20,
            )
            at, plan, detail = _fetch_web_access_token_login_mode(refresher)
            if at:
                return at, plan, detail
        except Exception as exc:
            refresher._log(f"login-existing: redirect soft: {exc}")

    # ── B) one next-auth + OTP login (main path) ──
    auth_url = _begin_nextauth_openai_signin(
        refresher, email, prompt="login", clear_stale=True, attempts=2
    )
    if not auth_url:
        auth_url = _build_chatgpt_web_authorize_url(email, refresher.device_id)
    not_before = time.time() - 2.0
    resp, err = _authorize_get_with_cf_pass(
        refresher,
        auth_url,
        referer="https://chatgpt.com/",
        timeout=25,
    )
    if resp is None:
        return "", "unknown", f"login-existing authorize failed: {err}"
    final_url = str(getattr(resp, "url", "") or "")
    refresher._log(f"login-existing authorize final_url={final_url[:140]}")
    payload: dict[str, Any] = {}
    page_type = ""
    need_otp = "email-verification" in final_url or "email_otp" in final_url

    if not need_otp:
        h = refresher._json_headers(f"{C.AUTH_BASE}/create-account")
        try:
            apply_sentinel_headers(
                h,
                refresher.session,
                refresher.device_id,
                "authorize_continue",
                profile=getattr(refresher, "fingerprint_profile", None),
            )
        except Exception:
            pass
        resp2, _ = request_with_retry(
            refresher.session,
            "post",
            f"{C.AUTH_BASE}/api/accounts/authorize/continue",
            json_data={
                "username": {"kind": "email", "value": email},
                "screen_hint": C.CHATGPT_WEB_SCREEN_HINT,
            },
            headers=h,
            verify=False,
            timeout=20,
        )
        if resp2 is not None and resp2.status_code == 200:
            payload = response_json(resp2) or {}
            page_type = str(((payload.get("page") or {}).get("type")) or "")
            cont = str(payload.get("continue_url") or "").strip()
            refresher._log(f"login-existing continue page_type={page_type}")
            if page_type in (
                "email_otp_verification",
                "email_otp_send",
                "email_otp_verification_registration",
            ):
                need_otp = True
            elif page_type == "create_account_password":
                need_otp = _force_passwordless_otp(refresher, email)
                not_before = time.time() - 5.0
            elif cont:
                page_type = page_type or "external_url"

    if need_otp:
        # Single OTP attempt (no 401 reopen loop — that alone can +30s)
        code = _poll_otp(
            mail_url,
            email,
            not_before=not_before,
            exclude_message_ids=exclude_message_ids,
        )
        if not code:
            return "", "unknown", "login-existing OTP missing"
        h = refresher._json_headers(f"{C.AUTH_BASE}/email-verification")
        try:
            apply_sentinel_headers(
                h,
                refresher.session,
                refresher.device_id,
                "email_otp_validate",
                profile=getattr(refresher, "fingerprint_profile", None),
            )
        except Exception:
            pass
        refresher._log(f"login-existing OTP validating code={code}...")
        vresp, verr = request_with_retry(
            refresher.session,
            "post",
            f"{C.AUTH_BASE}/api/accounts/email-otp/validate",
            json_data={"code": code},
            headers=h,
            verify=False,
            timeout=20,
        )
        st = getattr(vresp, "status_code", None)
        _USED_OTP_CODES.add(code)
        if vresp is None or st != 200:
            return "", "unknown", f"login-existing OTP validate failed: {verr or st}"
        payload = response_json(vresp) or {}
        page_type = str(((payload.get("page") or {}).get("type")) or "")
        refresher._log(f"login-existing OTP ok page_type={page_type}")

    # about_you on existing: one create try only; already_exists → harvest continue
    if page_type == "about_you":
        try:
            payload = _complete_create_account_about_you(refresher)
            page_type = str(((payload.get("page") or {}).get("type")) or page_type)
        except Exception as ca_exc:
            refresher._log(f"login-existing create on about_you: {str(ca_exc)[:120]}")
            payload = payload if isinstance(payload, dict) else {}
            page_type = "external_url"

    if page_type in (
        "workspace",
        "workspace_select",
        "workspace_selection",
        "select_workspace",
        "workspace_picker",
    ):
        dump_resp, _ = request_with_retry(
            refresher.session,
            "get",
            f"{C.AUTH_BASE}/api/accounts/client_auth_session_dump",
            headers={"accept": "application/json", "referer": f"{C.AUTH_BASE}/workspace"},
            verify=False,
            timeout=15,
        )
        if dump_resp is not None:
            from .workspace import select_web_workspace

            payload = select_web_workspace(
                refresher, email, "", response_json(dump_resp)
            )
            page_type = str(((payload.get("page") or {}).get("type")) or page_type)

    cont = str((payload or {}).get("continue_url") or "").strip()
    if not cont:
        cont = _auth_session_continue_url(refresher)
    if cont:
        refresher._log(f"login-existing: follow continue_url={cont[:100]}")
        followed = _follow_oauth_callback(refresher, cont)
        if str(followed).startswith("ERROR:"):
            refresher._log(f"login-existing callback soft: {followed}")
        else:
            at, plan, detail = _fetch_web_access_token_login_mode(refresher)
            if at:
                refresher._log(
                    f"login-existing OK in {time.time() - t0:.1f}s token_len={len(at)}"
                )
                return at, plan, detail
    else:
        # one relink only — no multi session spin
        try:
            _try_relink_chatgpt_signin(refresher, email)
        except Exception:
            pass

    at, plan, detail = _fetch_web_access_token_login_mode(refresher)
    if at:
        refresher._log(
            f"login-existing OK in {time.time() - t0:.1f}s token_len={len(at)}"
        )
        return at, plan, detail
    return (
        "",
        plan or "unknown",
        f"login-existing no AT in {time.time() - t0:.1f}s: {detail or '-'}",
    )


def _try_relink_chatgpt_signin(refresher: TokenRefresher, email: str) -> None:
    """If auth.openai.com session exists but next-auth cookie missing, re-run web signin."""
    refresher._log("relink: chatgpt.com csrf + signin/openai (no token yet)")
    csrf_token = ""
    try:
        csrf_resp, _ = request_with_retry(
            refresher.session,
            "get",
            "https://chatgpt.com/api/auth/csrf",
            headers=_session_headers(refresher),
            verify=False,
            timeout=12,
        )
        csrf = response_json(csrf_resp) if csrf_resp is not None else {}
        csrf_token = str(csrf.get("csrfToken") or "").strip()
    except Exception as e:
        refresher._log(f"relink csrf failed: {e}")
        return
    if not csrf_token:
        refresher._log("relink: no csrfToken")
        return
    signin_params = {
        "prompt": "none",
        "ext-oai-did": refresher.device_id,
        "auth_session_logging_id": str(uuid.uuid4()),
        "screen_hint": C.CHATGPT_WEB_SCREEN_HINT,
        "login_hint": email,
    }
    auth_url = (
        "https://chatgpt.com/api/auth/signin/openai?"
        + urllib.parse.urlencode(signin_params)
    )
    resp, err = request_with_retry(
        refresher.session,
        "post",
        auth_url,
        headers={
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "origin": "https://chatgpt.com",
            "referer": "https://chatgpt.com/",
            "user-agent": (getattr(refresher, "fingerprint_profile", None) or {}).get(
                "user_agent", C.USER_AGENT
            ),
        },
        data={
            "callbackUrl": "https://chatgpt.com/",
            "csrfToken": csrf_token,
            "json": "true",
        },
        allow_redirects=False,
        verify=False,
        timeout=25,
    )
    if resp is None:
        refresher._log(f"relink signin failed: {err}")
        return
    next_url = ""
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
        next_url = urllib.parse.urljoin("https://chatgpt.com", next_url)
        refresher._log(f"relink follow {next_url[:140]}")
        request_with_retry(
            refresher.session,
            "get",
            next_url,
            headers=_nav_headers(refresher, "https://chatgpt.com/"),
            allow_redirects=True,
            verify=False,
            timeout=40,
        )
    _warm_chatgpt_home(refresher, "post-relink")


def _session_fallback_enabled() -> bool:
    """Default OFF: manual HARs never hit /api/auth/session during signup.

    Set TOKENREFRESH_SESSION_FALLBACK=1 to restore old session-poll path.
    """
    return (os.environ.get("TOKENREFRESH_SESSION_FALLBACK") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _skip_post_create_enabled() -> bool:
    """Hard cut after create_account: no OAuth callback, no homepage AT, no session.

    TOKENREFRESH_SKIP_POST_CREATE=1 (alias: TOKENREFRESH_NO_AT=1)
    Used for A/B: control keeps full post-create; treatment stops at account create.
    """
    for key in ("TOKENREFRESH_SKIP_POST_CREATE", "TOKENREFRESH_NO_AT"):
        if (os.environ.get(key) or "").strip().lower() in ("1", "true", "yes", "on"):
            return True
    return False


def _fetch_web_access_token(
    refresher: TokenRefresher,
    *,
    tries: int = 4,
    base_pause: float = 0.4,
    fail_fast_net: bool = True,
) -> tuple[str, str, str]:
    """Obtain web accessToken after OAuth callback.

    Default (HAR-aligned): GET https://chatgpt.com/ and parse embedded
    accessToken from HTML. No /api/auth/session unless
    TOKENREFRESH_SESSION_FALLBACK=1.

    Returns (token, plan, last_detail).
    """
    web_at = ""
    plan = "unknown"
    detail = ""

    # ── Path A (default): homepage HTML — same as manual DE/KR/JP HARs ──
    home_tries = max(1, min(int(tries), 3))
    net_fails = 0
    for attempt in range(home_tries):
        at, detail = _warm_chatgpt_home(
            refresher, f"at-from-home#{attempt + 1}" if attempt else "at-from-home"
        )
        if at:
            web_at = at
            plan = _plan_from_access_token(at)
            try:
                refresher.web_access_token = web_at
                refresher.access_token = web_at
                refresher.web_plan_type = plan
            except Exception:
                pass
            return web_at, plan, detail
        # network failure vs empty body
        if "home_get_failed" in (detail or ""):
            net_fails += 1
            if fail_fast_net and net_fails >= 2:
                refresher._log("home AT fetch: net errors x2 — fail-fast")
                break
        if attempt + 1 < home_tries:
            time.sleep(base_pause + attempt * 0.2)

    if not _session_fallback_enabled():
        refresher._log(
            "no accessToken in homepage HTML — session fallback disabled "
            "(TOKENREFRESH_SESSION_FALLBACK=1 to enable /api/auth/session)"
        )
        return web_at, plan, detail or "home_no_token"

    # ── Path B (opt-in legacy): poll /api/auth/session ──
    refresher._log("TOKENREFRESH_SESSION_FALLBACK on — polling /api/auth/session")
    net_fails = 0
    for attempt in range(max(1, tries)):
        if attempt == 1:
            _warm_chatgpt_home(refresher, f"session-retry#{attempt + 1}")
        resp, err = request_with_retry(
            refresher.session,
            "get",
            C.CHATGPT_SESSION_URL,
            headers=_session_headers(refresher),
            verify=False,
            timeout=15,
        )
        if resp is None:
            net_fails += 1
            detail = f"session attempt={attempt + 1} err={err}"
            refresher._log(f"session poll: {detail}")
            err_l = str(err or "").lower()
            if fail_fast_net and net_fails >= 2 and any(
                x in err_l for x in ("ssl", "proxy", "curl", "timeout", "connect")
            ):
                refresher._log("session poll: net errors x2 — fail-fast")
                break
        else:
            net_fails = 0
            body = (resp.text or "")[:180].replace("\n", " ")
            detail = f"session attempt={attempt + 1} HTTP={resp.status_code} body={body}"
            if resp.status_code == 200:
                data = response_json(resp)
                if not isinstance(data, dict):
                    data = {}
                web_at = str(
                    data.get("accessToken") or data.get("access_token") or ""
                ).strip()
                plan = _classify_session_plan(data) if data else "unknown"
                keys = list(data.keys())[:8] if data else []
                refresher._log(
                    f"session poll: HTTP=200 keys={keys} token_len={len(web_at)} "
                    f"plan={plan} sess_cookie={_has_nextauth_session_cookie(refresher.session)}"
                )
                if web_at:
                    try:
                        refresher.web_access_token = web_at
                        refresher.access_token = web_at
                        refresher.web_plan_type = plan
                    except Exception:
                        pass
                    return web_at, plan, detail
            else:
                refresher._log(f"session poll: {detail}")
        time.sleep(base_pause + attempt * 0.25)
    return web_at, plan, detail


def _force_passwordless_otp(
    refresher: TokenRefresher,
    email: str,
    password: str = "",
) -> bool:
    """Open the OTP challenge, submitting the signup password when provided.

    The current ChatGPT signup UI defaults to passwordless OTP, but the
    explicit "use password" path still posts ``user/register`` before the
    OTP. That request creates the server-side password.
    """
    if str(password or "").strip():
        refresher._log("password page detected; submitting signup password before OTP...")
        h = refresher._json_headers(f"{C.AUTH_BASE}/create-account/password")
        try:
            apply_sentinel_headers(
                h,
                refresher.session,
                refresher.device_id,
                "username_password_create",
                profile=getattr(refresher, "fingerprint_profile", None),
            )
        except Exception as exc:
            refresher._log(f"sentinel for username/password signup failed: {exc}")
        resp, err = request_with_retry(
            refresher.session,
            "post",
            f"{C.AUTH_BASE}/api/accounts/user/register",
            json_data={"password": str(password), "username": str(email)},
            headers=h,
            verify=False,
            timeout=25,
            allow_redirects=False,
        )
        status = getattr(resp, "status_code", None) if resp is not None else None
        if resp is None or status != 200:
            body = str(getattr(resp, "text", "") or "")[:240]
            if status in (400, 409) and any(
                marker in body.lower()
                for marker in ("user_already_exists", "account already exists")
            ):
                refresher._log("signup password path reports existing account; continuing with OTP login")
                return True
            raise RuntimeError(
                f"signup password submit failed HTTP {status or '?'}: {body or err or 'no response'}"
            )
        payload = response_json(resp) or {}
        page_type = str(((payload.get("page") or {}).get("type")) or "")
        refresher._log(f"signup password accepted: page_type={page_type or '-'}")
        try:
            setattr(refresher, "_password_added", True)
        except Exception:
            pass
        continue_url = str(payload.get("continue_url") or "").strip()
        if continue_url:
            send_resp, send_err = request_with_retry(
                refresher.session,
                "get",
                continue_url,
                headers=refresher._navigate_headers(
                    f"{C.AUTH_BASE}/create-account/password"
                ),
                allow_redirects=True,
                verify=False,
                timeout=20,
            )
            send_status = getattr(send_resp, "status_code", None) if send_resp is not None else None
            refresher._log(
                f"signup email OTP send: HTTP={send_status or '?'} "
                f"err={send_err[:100] if send_err else 'None'}"
            )
        return True

    refresher._log("password page detected; forcing passwordless OTP (no user/register)...")
    auth_url = _build_chatgpt_web_authorize_url(email, refresher.device_id)
    resp, err = _authorize_get_with_cf_pass(
        refresher,
        auth_url,
        referer="https://chatgpt.com/",
        timeout=40,
    )
    final_url = str(getattr(resp, "url", "") or "") if resp is not None else ""
    refresher._log(f"passwordless re-authorize final_url: {final_url[:120]}")
    if "email-verification" in final_url or "email_otp" in final_url:
        return True

    # continue 也改用 login_or_signup
    h = refresher._json_headers(f"{C.AUTH_BASE}/create-account")
    try:
        apply_sentinel_headers(
            h, refresher.session, refresher.device_id, "authorize_continue",
            profile=getattr(refresher, "fingerprint_profile", None))
    except Exception as e:
        refresher._log(f"sentinel token failed ({e}), trying without...")
    resp2, err2 = request_with_retry(
        refresher.session, "post",
        f"{C.AUTH_BASE}/api/accounts/authorize/continue",
        json_data={
            "username": {"kind": "email", "value": email},
            "screen_hint": C.CHATGPT_WEB_SCREEN_HINT,
        },
        headers=h, verify=False,
    )
    if resp2 is not None and resp2.status_code == 200:
        payload = response_json(resp2)
        page_type = str(((payload.get("page") or {}).get("type")) or "")
        refresher._log(f"passwordless continue page_type={page_type}")
        if page_type in (
            "email_otp_verification",
            "email_otp_send",
            "email_otp_verification_registration",
        ):
            return True

    # 最后直接触发 OTP 发送
    request_with_retry(
        refresher.session, "get",
        f"{C.AUTH_BASE}/api/accounts/email-otp/send",
        headers=refresher._navigate_headers(f"{C.AUTH_BASE}/email-verification"),
        allow_redirects=True, verify=False, timeout=20,
    )
    refresher._log("passwordless: called email-otp/send")
    return True


def _clear_openai_auth_cookies(refresher: TokenRefresher) -> None:
    """Drop auth.openai.com cookies that pin a dead OAuth state (common 409 cause)."""
    sess = getattr(refresher, "session", None)
    if sess is None:
        return
    try:
        jar = sess.cookies
    except Exception:
        return
    names: list[str] = []
    try:
        for c in list(jar):
            dom = str(getattr(c, "domain", "") or "").lstrip(".").lower()
            if "openai.com" in dom or "chatgpt.com" in dom:
                # keep chatgpt.com cf/session lightly; clear auth.openai hard
                if "auth.openai.com" in dom or "openai.com" in dom:
                    n = str(getattr(c, "name", "") or "")
                    if n:
                        names.append(n)
                        try:
                            jar.clear(domain=getattr(c, "domain", None), path=getattr(c, "path", "/"), name=n)
                        except Exception:
                            try:
                                del jar[n]
                            except Exception:
                                pass
    except Exception:
        # best-effort bulk clear by name
        try:
            for n in list(getattr(jar, "keys", lambda: [])()):
                try:
                    del jar[n]
                except Exception:
                    pass
        except Exception:
            pass
    if names:
        refresher._log(f"cleared auth cookies n={len(names)} sample={names[:6]}")


def _authorize_landed_on_otp(final_url: str) -> bool:
    u = str(final_url or "").lower()
    return "email-verification" in u or "email_otp" in u


def _authorize_stuck_on_authorize(final_url: str) -> bool:
    u = str(final_url or "").lower()
    return "api/accounts/authorize" in u and not _authorize_landed_on_otp(u)


def _authorize_timeout_s() -> float:
    """authorize GET 超时：默认 15s（旧 40s 会把 stuck 拖到 80s+）。"""
    try:
        return max(8.0, min(40.0, float(os.environ.get("TOKENREFRESH_AUTHORIZE_TIMEOUT") or "15")))
    except (TypeError, ValueError):
        return 15.0


def _recover_dead_authorize_state(refresher: TokenRefresher, email: str) -> bool:
    """authorize/continue 409 (or CF-like 403): dead OAuth state — NOT account ban.

    快失败：默认 **1 次** 短超时 fresh authorize；不再 2×40s 空转。
    TOKENREFRESH_AUTHORIZE_RECOVER_ROUNDS=2 可恢复旧双次逻辑。
    Returns True only if OTP challenge is really open (do NOT fake need_otp).
    """
    try:
        rounds = int(os.environ.get("TOKENREFRESH_AUTHORIZE_RECOVER_ROUNDS") or "1")
    except ValueError:
        rounds = 1
    rounds = max(1, min(2, rounds))
    t_auth = _authorize_timeout_s()
    refresher._log(
        f"recover dead authorize state: fresh authorize×{rounds} "
        f"timeout={t_auth:.0f}s — NOT deactivated"
    )
    try:
        _clear_openai_auth_cookies(refresher)
    except Exception:
        pass
    try:
        _warm_chatgpt_home(refresher, "dead-auth-state")
    except Exception:
        pass

    # Prefer clean direct authorize (signin path can re-pin bad state)
    auth_url = _build_chatgpt_web_authorize_url(email, refresher.device_id)
    resp, err = _authorize_get_with_cf_pass(
        refresher,
        auth_url,
        referer="https://chatgpt.com/",
        timeout=t_auth,
    )
    if resp is None:
        refresher._log(f"dead-auth authorize failed: {err}")
        return False
    final_url = str(getattr(resp, "url", "") or "")
    st = getattr(resp, "status_code", "?")
    refresher._log(
        f"dead-auth authorize HTTP={st} final_url={final_url[:140]}"
    )
    if _authorize_landed_on_otp(final_url):
        return True
    if "create-account/password" in final_url or final_url.rstrip("/").endswith(
        "/password"
    ):
        return _force_passwordless_otp(refresher, email)

    # 仍 stuck：默认 fail-fast 不再第二轮 40s；仅 rounds>=2 时再试一次
    if _authorize_stuck_on_authorize(final_url) and rounds >= 2:
        refresher._log("dead-auth still stuck — 2nd clear + re-auth (explicit rounds=2)")
        try:
            _clear_openai_auth_cookies(refresher)
        except Exception:
            pass
        auth_url = _build_chatgpt_web_authorize_url(email, refresher.device_id)
        resp, err = _authorize_get_with_cf_pass(
            refresher,
            auth_url,
            referer="https://chatgpt.com/",
            timeout=t_auth,
        )
        final_url = str(getattr(resp, "url", "") or "") if resp is not None else ""
        refresher._log(f"dead-auth 2nd authorize final_url={final_url[:140]}")
        if _authorize_landed_on_otp(final_url):
            return True
    elif _authorize_stuck_on_authorize(final_url):
        refresher._log(
            "dead-auth still stuck on authorize URL — fail-fast "
            "(set TOKENREFRESH_AUTHORIZE_RECOVER_ROUNDS=2 to retry)"
        )
        return False

    h = refresher._json_headers(f"{C.AUTH_BASE}/create-account")
    try:
        apply_sentinel_headers(
            h, refresher.session, refresher.device_id, "authorize_continue",
            profile=getattr(refresher, "fingerprint_profile", None),
        )
    except Exception:
        pass
    resp2, err2 = request_with_retry(
        refresher.session,
        "post",
        f"{C.AUTH_BASE}/api/accounts/authorize/continue",
        json_data={
            "username": {"kind": "email", "value": email},
            "screen_hint": C.CHATGPT_WEB_SCREEN_HINT,
        },
        headers=h,
        verify=False,
        timeout=min(20.0, t_auth + 5.0),
        retry_attempts=1,
    )
    st2 = getattr(resp2, "status_code", None) if resp2 is not None else None
    if resp2 is not None and st2 == 200:
        payload = response_json(resp2) or {}
        page_type = str(((payload.get("page") or {}).get("type")) or "")
        refresher._log(f"dead-auth retry continue page_type={page_type}")
        if page_type in (
            "email_otp_verification",
            "email_otp_send",
            "email_otp_verification_registration",
        ):
            return True
        if page_type == "create_account_password":
            return _force_passwordless_otp(refresher, email)
        if page_type == "external_url" and str(
            payload.get("continue_url") or ""
        ).strip():
            followed = _follow_oauth_callback(
                refresher, str(payload.get("continue_url") or "")
            )
            if not str(followed).startswith("ERROR:"):
                return True
            return False
    refresher._log(
        f"dead-auth recover incomplete HTTP {st2} err={err2} "
        f"(soft env fail, NOT deactivated) — no fake OTP wait"
    )
    return False


def _reopen_email_otp_challenge(refresher: TokenRefresher, email: str) -> bool:
    """OTP validate 返回 401 时：旧 authorize state 已失效，必须重新 authorize。

    仅 resend 仍挂在死 state 上，会连着 401。新 authorize 会触发新邮件 OTP。
    """
    refresher._log("OTP 401 recovery: fresh authorize for new email-verification state")
    try:
        _warm_chatgpt_home(refresher, "otp401-reauth")
    except Exception:
        pass
    auth_url = _build_chatgpt_web_authorize_url(email, refresher.device_id)
    resp, err = _authorize_get_with_cf_pass(
        refresher,
        auth_url,
        referer="https://chatgpt.com/",
        timeout=40,
    )
    if resp is None:
        refresher._log(f"OTP 401 recovery authorize failed: {err}")
        return False
    final_url = str(getattr(resp, "url", "") or "")
    refresher._log(f"OTP 401 recovery authorize final_url={final_url[:140]}")
    if "email-verification" in final_url or "email_otp" in final_url:
        return True
    # continue → email_otp_verification
    h = refresher._json_headers(f"{C.AUTH_BASE}/create-account")
    try:
        apply_sentinel_headers(
            h, refresher.session, refresher.device_id, "authorize_continue",
            profile=getattr(refresher, "fingerprint_profile", None))
    except Exception:
        pass
    resp2, _ = request_with_retry(
        refresher.session,
        "post",
        f"{C.AUTH_BASE}/api/accounts/authorize/continue",
        json_data={
            "username": {"kind": "email", "value": email},
            "screen_hint": C.CHATGPT_WEB_SCREEN_HINT,
        },
        headers=h,
        verify=False,
    )
    if resp2 is not None and resp2.status_code == 200:
        payload = response_json(resp2) or {}
        page_type = str(((payload.get("page") or {}).get("type")) or "")
        refresher._log(f"OTP 401 recovery continue page_type={page_type}")
        if page_type in (
            "email_otp_verification",
            "email_otp_send",
            "email_otp_verification_registration",
        ):
            return True
        if page_type == "create_account_password":
            return _force_passwordless_otp(refresher, email)
    # last resort send — only if we already have some auth session cookies
    send_resp, send_err = request_with_retry(
        refresher.session,
        "get",
        f"{C.AUTH_BASE}/api/accounts/email-otp/send",
        headers=refresher._navigate_headers(f"{C.AUTH_BASE}/email-verification"),
        allow_redirects=True,
        verify=False,
        timeout=20,
    )
    send_st = getattr(send_resp, "status_code", None) if send_resp is not None else None
    send_final = str(getattr(send_resp, "url", "") or "") if send_resp is not None else ""
    refresher._log(
        f"OTP 401 recovery: email-otp/send HTTP={send_st} "
        f"final={send_final[:100]} err={send_err}"
    )
    # 仅当真正落到验证页 / send 200 时才算 OTP 已打开；否则勿假成功空等 OTP
    if _authorize_landed_on_otp(send_final) or send_st in (200, 204):
        # 200 仍可能是空页：若仍卡在 authorize URL 则失败
        if _authorize_stuck_on_authorize(send_final):
            return False
        return True
    return False


def chatgpt_web_login(refresher: TokenRefresher, email: str, password: str = "",
                       mail_url: str = "", account_id: str = "",
                       *, fast: bool | None = None,
                       exclude_message_ids: set[str] | None = None) -> dict:
    """
    ChatGPT 注册/登录，拿到 web 会话 cookie 和 accessToken。
    对齐浏览器抓包：screen_hint=login_or_signup + ChatGPT Web client + passwordless OTP。

    fast=True（或 TOKENREFRESH_FAST_WEB_LOGIN）：跳过 chatgpt.com 预热/CSRF，直连 authorize，
    缩短分裂批量时的注册 RTT；OTP 仍严格串行由调用方保证。
    """
    if fast is None:
        fast = bool(getattr(C, "FAST_WEB_LOGIN", True))
    refresher._log(
        f"Opening ChatGPT web passwordless signup{' (fast)' if fast else ''}..."
    )

    # Gold-standard path trace (Bit 289 checklist) — device_id continuity + order audit
    _birth_device_id = str(getattr(refresher, "device_id", "") or "").strip()
    try:
        from chatgpt_register.protocol.gold_path import (
            attach_path_trace,
            ensure_device_id_bound,
            gold_path_enabled,
            mark as gold_mark,
        )

        if gold_path_enabled():
            attach_path_trace(refresher, device_id=_birth_device_id)
            ensure_device_id_bound(refresher, log=refresher._log)
            refresher._log(
                f"[gold-path] enabled birth_did={_birth_device_id[:18]}…"
            )
    except Exception as _gp_e:
        refresher._log(f"[gold-path] init ignore: {_gp_e}")

    # Path warm / pre-auth spine / CES telemetry removed (not ban-critical).
    try:
        from .humanize import human_pause

        human_pause("micro")
    except Exception:
        pass

    # Re-bind device_id before authorize
    try:
        from chatgpt_register.protocol.gold_path import (
            assert_stable_device_id,
            ensure_device_id_bound,
            gold_path_enabled,
        )

        if gold_path_enabled():
            if _birth_device_id:
                assert_stable_device_id(refresher, _birth_device_id)
            ensure_device_id_bound(refresher, log=refresher._log)
    except Exception as _gp_e2:
        refresher._log(f"[gold-path] pre-authorize bind ignore: {_gp_e2}")

    auth_url = _begin_nextauth_openai_signin(
        refresher,
        email,
        prompt="login",
        clear_stale=True,
        attempts=3 if not fast else 2,
    )
    if not auth_url:
        refresher._log(
            "CSRF/signin incomplete after retries — last-chance next-auth"
        )
        auth_url = _begin_nextauth_openai_signin(
            refresher, email, prompt="login", clear_stale=True, attempts=1
        )
    if not auth_url:
        # 高风险兜底：多数会 OAuthCallback；仅当环境完全拿不到 csrf 时
        refresher._log(
            "WARNING: direct authorize without next-auth — OAuthCallback likely"
        )
        auth_url = _build_chatgpt_web_authorize_url(email, refresher.device_id)

    # 3. authorize（login_hint → 期望直接 email-verification）
    # 已关闭今早 CF challenge pass；直连 GET + 跟 final_url（与改 CF 前一致）
    # fast 路径：not_before 贴近 authorize 时刻，减少吃到上一别名旧 OTP
    email_otp_not_before = time.time() - (5.0 if fast else C.EMAIL_OTP_TIME_SKEW)
    t_auth = _authorize_timeout_s()
    resp, err = _authorize_get_with_cf_pass(
        refresher,
        auth_url,
        referer="https://chatgpt.com/",
        timeout=t_auth,
    )
    if resp is None:
        raise RuntimeError(f"auth authorize open failed: {err}")

    final_url = str(getattr(resp, "url", "") or "")
    need_otp = False
    page_type = ""
    payload: dict[str, Any] = {}
    refresher._log(f"authorize final_url: {final_url[:120]}")
    try:
        from chatgpt_register.protocol.gold_path import mark as gold_mark

        gold_mark(refresher, "authorize", note=final_url[:80])
    except Exception:
        pass

    if "email-verification" in final_url or "email_otp" in final_url:
        if password:
            need_otp = _force_passwordless_otp(refresher, email, password)
            refresher._log("signup password submitted from default OTP page")
        else:
            need_otp = True
            send_st = None
            for _send_try in range(2):
                send_resp, send_err = request_with_retry(
                    refresher.session,
                    "get",
                    f"{C.AUTH_BASE}/api/accounts/email-otp/send",
                    headers=refresher._navigate_headers(f"{C.AUTH_BASE}/email-verification"),
                    allow_redirects=True,
                    verify=False,
                    timeout=20,
                )
                send_st = getattr(send_resp, "status_code", None) if send_resp is not None else None
                if send_st == 200:
                    break
                time.sleep(1.0)
            refresher._log(f"email-verification page: explicit OTP send HTTP={send_st or '?'}")
            email_otp_not_before = time.time() - 2.0
    elif "create-account/password" in final_url or final_url.rstrip("/").endswith("/password"):
        need_otp = _force_passwordless_otp(refresher, email, password)
        email_otp_not_before = time.time() - C.EMAIL_OTP_TIME_SKEW
    elif "create-account" in final_url or "about-you" in final_url:
        refresher._log("reached signup page — prefer browser path then continue if needed")
    elif _authorize_stuck_on_authorize(final_url):
        # 卡在 authorize URL：多为死 state / CF 未过，continue 必 409。
        # 先 recover，勿直接 continue 再硬失败当封号。
        refresher._log(
            "authorize stuck on authorize URL — recover dead state "
            "(not deactivated)"
        )
        if _recover_dead_authorize_state(refresher, email):
            need_otp = True
            email_otp_not_before = time.time() - 5.0
        else:
            raise RuntimeError(
                "authorize stuck (soft env/state fail, NOT deactivated): "
                "could not open email-verification after fresh authorize"
            )
    else:
        refresher._log("unexpected redirect after authorize — soft-nav then continue if needed")

    # ── 更像真人：已自动落到验证页就绝不用 continue ──
    # 速度：authorize 已在 email-verification → 0 额外请求（主路径）。
    # 仅未到 OTP 时：可选一次短 GET soft-nav（不重试、短超时），失败立刻 continue。
    # TOKENREFRESH_SKIP_SOFT_NAV=1 可完全关掉 soft-nav（纯速度）。
    _skip_soft = (os.environ.get("TOKENREFRESH_SKIP_SOFT_NAV") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )
    if not need_otp and not _skip_soft and not fast:
        try:
            ev = f"{C.AUTH_BASE}/email-verification"
            # retry_attempts=1 + 短 timeout：最多多 1 次 RTT，不拖批量
            nav_resp, _nav_err = request_with_retry(
                refresher.session,
                "get",
                ev,
                headers=refresher._navigate_headers(
                    final_url or f"{C.AUTH_BASE}/"
                ),
                allow_redirects=True,
                verify=False,
                timeout=5,
                retry_attempts=1,
            )
            if nav_resp is not None:
                nav_url = str(getattr(nav_resp, "url", "") or "")
                st_nav = int(getattr(nav_resp, "status_code", 0) or 0)
                if _authorize_landed_on_otp(nav_url) or (
                    st_nav == 200 and "email-verification" in (nav_url or ev).lower()
                ):
                    need_otp = True
                    final_url = nav_url or final_url
                    refresher._log(
                        "browser-like email-verification GET ok "
                        f"(skip authorize/continue) url={(nav_url or ev)[:100]}"
                    )
        except Exception as e:
            refresher._log(f"email-verification soft-nav ignore: {e}")

    # 兜底：仍未到 OTP 才 authorize/continue（自动化推进器，非真人必经）
    if not need_otp:
        refresher._log("still not on OTP page — authorize/continue fallback")
        h = refresher._json_headers(f"{C.AUTH_BASE}/create-account")
        try:
            apply_sentinel_headers(
            h, refresher.session, refresher.device_id, "authorize_continue",
            profile=getattr(refresher, "fingerprint_profile", None))
        except Exception as e:
            refresher._log(f"sentinel token failed ({e}), trying without...")
        resp2, err2 = request_with_retry(
            refresher.session, "post",
            f"{C.AUTH_BASE}/api/accounts/authorize/continue",
            json_data={
                "username": {"kind": "email", "value": email},
                "screen_hint": C.CHATGPT_WEB_SCREEN_HINT,
            },
            headers=h, verify=False,
        )
        if resp2 is not None and resp2.status_code == 200:
            payload = response_json(resp2)
            page_type = str(((payload.get("page") or {}).get("type")) or "")
            refresher._log(f"authorize/continue: page_type={page_type}")
            if page_type in (
                "email_otp_verification",
                "email_otp_send",
                "email_otp_verification_registration",
            ):
                need_otp = True
            elif page_type == "create_account_password":
                need_otp = _force_passwordless_otp(refresher, email, password)
                email_otp_not_before = time.time() - C.EMAIL_OTP_TIME_SKEW
            elif page_type in ("login_password", "password"):
                # 已有号密码登录页：有 mail_url 则改 OTP；否则报错
                if mail_url:
                    need_otp = _force_passwordless_otp(refresher, email)
                    email_otp_not_before = time.time() - C.EMAIL_OTP_TIME_SKEW
                elif password:
                    refresher._log("login_password page with password provided (not implemented web password submit)")
                    raise RuntimeError("login_password page; password login not supported in web path")
                else:
                    raise RuntimeError("login_password page without mail_url/password")
            elif page_type != "external_url":
                refresher._log(f"unexpected page: {page_type}")
        else:
            st_cont = getattr(resp2, "status_code", None)
            refresher._log(
                f"authorize/continue failed: HTTP "
                f"{st_cont if st_cont is not None else '?'} {err2}"
            )
            # 403/409 ≠ 封号：死 authorize state 时 fresh authorize，不做 CF form pass
            if is_dead_authorize_continue_status(st_cont):
                refresher._log(
                    f"authorize/continue HTTP {st_cont} — "
                    f"recover dead authorize (not deactivated/banned)"
                )
                if _recover_dead_authorize_state(refresher, email):
                    need_otp = True
                    email_otp_not_before = time.time() - 5.0
                else:
                    raise RuntimeError(
                        f"authorize/continue HTTP {st_cont} after fresh authorize "
                        f"(soft env/state fail, NOT deactivated): {err2 or ''}"
                    )
            elif mail_url:
                refresher._log("trying direct email-otp/send...")
                request_with_retry(
                    refresher.session, "get",
                    f"{C.AUTH_BASE}/api/accounts/email-otp/send",
                    headers=refresher._navigate_headers(f"{C.AUTH_BASE}/email-verification"),
                    allow_redirects=True, verify=False, timeout=20,
                )
                need_otp = True

    # 7. Email OTP（如果需要）
    if need_otp:
        # P0-4: 页面时刻——validate 总间隔 18~28s floor（8-2 实测 ~22s）
        otp_page_t0 = time.time()
        code = None
        seen_codes: set[str] = set()
        base_rounds = max(1, int(getattr(C, "EMAIL_OTP_VALIDATION_ROUNDS", 1) or 1))
        # 401 = authorize state 死了：额外允许 1 次 fresh authorize（不只 resend）
        # 403 = Cloudflare challenge（cf-mitigated: challenge）：刷新 email-verification 后同 code 重试一次
        budget = base_rounds
        auth_401_refresh_used = False
        cf403_refresh_used = False
        last_validate_status: int | None = None
        round_idx = 0
        while round_idx < budget:
            if round_idx > 0:
                if last_validate_status == 401 and not auth_401_refresh_used:
                    auth_401_refresh_used = True
                    ok_re = _reopen_email_otp_challenge(refresher, email)
                    refresher._log(
                        f"Email OTP after 401: re-authorize ok={ok_re}, wait new mail..."
                    )
                    not_before = time.time() - 2
                    time.sleep(max(0.8, float(getattr(C, "EMAIL_RESEND_WAIT_SECONDS", 2.0) or 2.0)))
                    # 保证至少还能再 poll+validate 一轮
                    budget = max(budget, round_idx + 1)
                else:
                    refresher._log("Email OTP timeout/fail, resending...")
                    resend_email_otp(refresher, email)
                    not_before = time.time() - 2
                    time.sleep(C.EMAIL_RESEND_WAIT_SECONDS)
            else:
                not_before = email_otp_not_before

            code = _poll_otp(
                mail_url,
                email,
                not_before=not_before,
                exclude_message_ids=exclude_message_ids,
            )
            if not code:
                last_validate_status = None
                round_idx += 1
                continue

            # OTP 提交 floor：默认 0（飞快，码到即提交）。
            # 若要贴近 8-2 真人 ~22s：TOKENREFRESH_OTP_SUBMIT_MIN_S=18 MAX_S=28
            floor_lo = float(os.environ.get("TOKENREFRESH_OTP_SUBMIT_MIN_S", "0"))
            floor_hi = float(os.environ.get("TOKENREFRESH_OTP_SUBMIT_MAX_S", "0"))
            if floor_hi < floor_lo:
                floor_hi = floor_lo
            if floor_hi > 0:
                elapsed = time.time() - otp_page_t0
                wait = random.uniform(floor_lo, floor_hi) - elapsed
                if wait > 0:
                    time.sleep(wait)
            h = refresher._json_headers(f"{C.AUTH_BASE}/email-verification")
            # Gold path: re-bind device_id then sentinel_req flow=email_otp_validate
            # (Bit 289: authorize → sentinel → email_otp_validate)
            try:
                from chatgpt_register.protocol.gold_path import (
                    ensure_device_id_bound,
                    gold_path_enabled,
                    mark as gold_mark,
                )

                if gold_path_enabled():
                    ensure_device_id_bound(refresher, log=refresher._log)
                    if _birth_device_id:
                        from chatgpt_register.protocol.gold_path import (
                            assert_stable_device_id,
                        )

                        assert_stable_device_id(refresher, _birth_device_id)
            except Exception as _gp_v:
                refresher._log(f"[gold-path] pre-validate bind ignore: {_gp_v}")
            # 8-2 HAR 对齐：validate 必须带 sentinel（flow=email_otp_validate），
            # 8 月起 OpenAI 端对缺失 sentinel 的 validate 直接拒绝/风控
            _apply_required_sentinel_headers(
                h, refresher, "email_otp_validate"
            )
            try:
                from chatgpt_register.protocol.gold_path import mark as gold_mark

                gold_mark(refresher, "sentinel", note="email_otp_validate")
            except Exception:
                pass
            validate_body = {"code": code}
            refresher._log(f"email OTP validating code={code}...")
            try:
                from .humanize import human_pause

                human_pause("pre_otp_submit")
            except Exception:
                pass
            resp, err = request_with_retry(
                refresher.session, "post",
                f"{C.AUTH_BASE}/api/accounts/email-otp/validate",
                json_data=validate_body, headers=h, verify=False, timeout=25,
            )
            st = getattr(resp, "status_code", None)
            last_validate_status = int(st) if st is not None else None
            refresher._log(
                f"email OTP validate done: resp={st if st is not None else 'None'} "
                f"err={err[:100] if err else 'None'}"
            )
            if resp is not None and resp.status_code == 200:
                payload = response_json(resp)
                save_debug(email, "web_email_otp_validation", payload,
                           status_code=str(resp.status_code))
                page_type = str(((payload.get("page") or {}).get("type")) or "")
                refresher._log(f"web email OTP validated: page_type={page_type}")
                _USED_OTP_CODES.add(code)
                try:
                    from chatgpt_register.protocol.gold_path import mark as gold_mark

                    gold_mark(refresher, "email_otp_validate", note=page_type)
                except Exception:
                    pass
                try:
                    from .humanize import human_pause

                    human_pause("otp_ok")
                except Exception:
                    pass
                break
            else:
                body_text = (resp.text or "") if resp else ""
                resp_headers = dict(resp.headers) if resp else {}
                refresher._log(
                    f"web email OTP validate failed: HTTP {st if st is not None else '?'} "
                    f"body={body_text[:500]}"
                )
                refresher._log(f"validate resp headers: {json.dumps(resp_headers)[:500]}")
                # 账号已删/停用等硬失败：立刻抛出真实原因，禁止再伪装成 OTP 收不到
                low_body = body_text.lower()
                hard_account = False
                api_msg = ""
                try:
                    if body_text.strip().startswith("{"):
                        bj = json.loads(body_text)
                        err_obj = bj.get("error") if isinstance(bj, dict) else None
                        if isinstance(err_obj, dict):
                            api_msg = str(err_obj.get("message") or "")
                        elif isinstance(err_obj, str):
                            api_msg = err_obj
                except Exception:
                    api_msg = ""
                combined = f"{api_msg} {body_text}".lower()
                # 8-2 HAR: validate HTTP 403 是 Cloudflare challenge（响应头
                # cf-mitigated: challenge, server: cloudflare, HTML challenge 页），
                # 浏览器刷新 /email-verification 后**同一 code** 重试即 200 —— 不是封号。
                # 仅当 body 含明确硬失败词才判 hard。
                if any(
                    m in combined
                    for m in (
                        "deleted or deactivated",
                        "has been deleted",
                        "do not have an account",
                        "registration_disallowed",
                        "registration is not allowed",
                        "cannot create your account",
                    )
                ):
                    hard_account = True
                if hard_account:
                    detail = (api_msg or body_text or err or "blocked")[:220]
                    raise RuntimeError(
                        f"email OTP validate HTTP {last_validate_status or st or '?'}: {detail}"
                    )
                # 403 = CF challenge：模拟浏览器刷新 email-verification（重新加载
                # sentinel/CF session cookie），用同一 code 立即重试一次。
                if last_validate_status == 403 and not cf403_refresh_used:
                    cf403_refresh_used = True
                    refresher._log(
                        "email OTP validate HTTP 403 (CF challenge) — "
                        "reload email-verification like browser, retry SAME code"
                    )
                    try:
                        request_with_retry(
                            refresher.session,
                            "get",
                            f"{C.AUTH_BASE}/email-verification",
                            headers=refresher._navigate_headers(
                                f"{C.AUTH_BASE}/email-verification"
                            ),
                            allow_redirects=True,
                            verify=False,
                            timeout=15,
                            retry_attempts=1,
                        )
                    except Exception as e:
                        refresher._log(f"403 reload email-verification ignore: {e}")
                    h_retry = refresher._json_headers(
                        f"{C.AUTH_BASE}/email-verification"
                    )
                    _apply_required_sentinel_headers(
                        h_retry, refresher, "email_otp_validate"
                    )
                    resp_retry, err_retry = request_with_retry(
                        refresher.session,
                        "post",
                        f"{C.AUTH_BASE}/api/accounts/email-otp/validate",
                        json_data={"code": code},
                        headers=h_retry,
                        verify=False,
                        timeout=25,
                    )
                    st_retry = (
                        getattr(resp_retry, "status_code", None)
                        if resp_retry is not None
                        else None
                    )
                    refresher._log(
                        f"email OTP validate retry after 403: "
                        f"HTTP={st_retry} err={err_retry[:100] if err_retry else 'None'}"
                    )
                    if resp_retry is not None and resp_retry.status_code == 200:
                        payload = response_json(resp_retry)
                        save_debug(
                            email,
                            "web_email_otp_validation",
                            payload,
                            status_code=str(resp_retry.status_code),
                        )
                        page_type = str(
                            ((payload.get("page") or {}).get("type")) or ""
                        )
                        refresher._log(
                            f"web email OTP validated (after 403): page_type={page_type}"
                        )
                        _USED_OTP_CODES.add(code)
                        try:
                            from .humanize import human_pause

                            human_pause("otp_ok")
                        except Exception:
                            pass
                        break
                    # 重试仍失败：更新状态后走下方 resend / poll 新 code
                    last_validate_status = st_retry or last_validate_status
                seen_codes.add(code)
                _USED_OTP_CODES.add(code)
                smsbower_cfg = _parse_smsbower_mail_url(mail_url)
                if smsbower_cfg.get("mail_id"):
                    refresher._log("SMSBower setStatus(5) for next code")
                    smsbower_set_status(smsbower_cfg["mail_id"], "5")
                # 401：扩展 budget，下轮走 fresh authorize
                if last_validate_status == 401 and not auth_401_refresh_used:
                    budget = max(budget, round_idx + 2)
            code = None
            round_idx += 1

        if not code:
            if last_validate_status:
                raise RuntimeError(
                    f"Could not get web email OTP (last_validate_HTTP={last_validate_status})"
                )
            raise RuntimeError("Could not get web email OTP")

    # 7.5 about_you（新注册账号需要填名字）— 真实端点: POST /api/accounts/create_account
    account_just_created = False
    if page_type == "about_you":
        from .names import random_about_you
        from .humanize import human_pause

        human_pause("pre_create")
        refresher._log("completing about_you (create_account)...")
        # Gold: email_otp_validate → create_account → oauth_callback; re-bind did
        try:
            from chatgpt_register.protocol.gold_path import (
                ensure_device_id_bound,
                gold_path_enabled,
                assert_stable_device_id,
            )

            if gold_path_enabled():
                ensure_device_id_bound(refresher, log=refresher._log)
                if _birth_device_id:
                    assert_stable_device_id(refresher, _birth_device_id)
        except Exception as _gp_ca:
            refresher._log(f"[gold-path] pre-create_account bind ignore: {_gp_ca}")
        name, birthdate = random_about_you(refresher)
        age_ui = int(getattr(refresher, "_about_you_age", 0) or 0)
        refresher._log(
            f"about_you name={name!r} birthdate={birthdate} age={age_ui or '-'}"
        )
        # Body must be only name+birthdate (Bit gold); age is UI-only
        create_body = {"name": name, "birthdate": birthdate}
        try:
            from chatgpt_register.protocol.gold_path import (
                gold_path_enabled,
                validate_create_account_body,
            )

            if gold_path_enabled():
                probs = validate_create_account_body(
                    create_body, age=age_ui or None
                )
                if probs:
                    refresher._log(f"[gold-path] create_account body issues: {probs}")
                    # Repair birthdate from age if misaligned
                    if age_ui > 0 and any("birthdate_not_age" in p for p in probs):
                        from .names import birthdate_from_age

                        birthdate = birthdate_from_age(age_ui)
                        create_body = {"name": name, "birthdate": birthdate}
                        refresher._log(
                            f"[gold-path] repaired birthdate from age={age_ui} → {birthdate}"
                        )
                        try:
                            setattr(refresher, "_about_you_birthdate", birthdate)
                        except Exception:
                            pass
        except Exception as _gp_body:
            refresher._log(f"[gold-path] body validate ignore: {_gp_body}")
        h = refresher._json_headers(f"{C.AUTH_BASE}/about-you")
        # Gold + BrowserParity:
        #   1) prime oauth_create_account on about-you (sentinel_req warm)
        #   2) create_account POST sentinel — always use the browser's
        #      oauth_create_account flow; no legacy label fallback.
        _parity = (os.environ.get("TOKENREFRESH_BROWSER_PARITY") or "1").strip().lower() not in (
            "0", "false", "no", "off",
        )
        _gold = False
        try:
            from chatgpt_register.protocol.gold_path import gold_path_enabled

            _gold = gold_path_enabled()
        except Exception:
            _gold = False
        create_flow = "oauth_create_account"
        try:
            from .formal_frame import formal_frame_enabled

            if formal_frame_enabled() or _parity or _gold:
                try:
                    apply_sentinel_headers(
                        {},
                        refresher.session,
                        refresher.device_id,
                        "oauth_create_account",
                        profile=getattr(refresher, "fingerprint_profile", None),
                    )
                    refresher._log("sentinel prime oauth_create_account (about-you) ok")
                    try:
                        from chatgpt_register.protocol.gold_path import mark as gold_mark

                        gold_mark(refresher, "sentinel", note="prime_oauth_create_account")
                    except Exception:
                        pass
                except Exception as pe:
                    refresher._log(f"sentinel prime oauth_create_account ignore: {pe}")
        except Exception:
            pass
        _apply_required_sentinel_headers(h, refresher, create_flow)
        try:
            from chatgpt_register.protocol.gold_path import mark as gold_mark

            gold_mark(refresher, "sentinel", note=f"create_account:{create_flow}")
        except Exception:
            pass
        human_pause("micro")
        resp, err = request_with_retry(
            refresher.session, "post",
            f"{C.AUTH_BASE}/api/accounts/create_account",
            json_data=create_body,
            headers=h, verify=False, timeout=25, allow_redirects=False,
        )
        status = getattr(resp, 'status_code', '?')
        refresher._log(f"create_account: HTTP {status}")
        if resp is not None and resp.status_code in (200, 302, 303):
            try:
                from chatgpt_register.protocol.gold_path import mark as gold_mark

                gold_mark(refresher, "create_account", note=str(status))
            except Exception:
                pass
            payload = response_json(resp)
            if not isinstance(payload, dict):
                payload = {}
            page_type = str(((payload.get("page") or {}).get("type")) or "")
            cont = str(payload.get("continue_url") or "").strip()
            # some payloads nest continue under page
            if not cont and isinstance(payload.get("page"), dict):
                cont = str(
                    (payload.get("page") or {}).get("continue_url")
                    or (payload.get("page") or {}).get("url")
                    or ""
                ).strip()
                if cont:
                    payload["continue_url"] = cont
            # 302/303 可能直接在 Location header 里有 callback URL
            if not cont and resp.status_code in (302, 303):
                loc = resp.headers.get("Location") or resp.headers.get("location") or ""
                if loc:
                    payload = {"continue_url": loc, "page": {"type": "external_url"}}
                    page_type = "external_url"
                    cont = loc
            # 200 有 continue_url 但 page.type 空 → 当 external_url 处理
            if cont and not page_type:
                page_type = "external_url"
                payload.setdefault("page", {})["type"] = "external_url"
            if cont and page_type not in (
                "external_url",
                "workspace",
                "workspace_select",
                "workspace_selection",
                "select_workspace",
                "workspace_picker",
            ):
                # consent / other pages that still carry continue_url
                refresher._log(
                    f"create_account page_type={page_type or '-'} has continue_url — treat as external"
                )
                page_type = "external_url"
            account_just_created = True
            refresher._log(
                f"create_account done: page_type={page_type or '-'} "
                f"continue_url={(cont[:100] if cont else '-')}"
            )
        elif resp is not None:
            err_body = (resp.text or "")[:500]
            refresher._log(f"create_account failed: HTTP {status} body={err_body}")
            err_l = err_body.lower()
            # plus 别名 / 重跑：OTP 落到 about_you 但账号已存在 → **完整登录拿 AT**
            # （旧逻辑只 warm 空 continue_url，导致 soft fail 且 access_token 永远为空）
            if "user_already_exists" in err_l or "account already exists" in err_l:
                if _skip_post_create_enabled():
                    # 实验臂：不跟 chatgpt.com / callback
                    raise RuntimeError(f"user_already_exists: {err_body[:160]}")
                redir = ""
                try:
                    redir = str(
                        (response_json(resp).get("error") or {}).get("redirect_uri") or ""
                    )
                except Exception:
                    redir = ""
                try:
                    setattr(refresher, "_account_already_exists", True)
                except Exception:
                    pass
                refresher._log(
                    "user_already_exists — switch to login-existing path for accessToken"
                )
                web_at, plan, login_detail = _login_existing_account_for_at(
                    refresher,
                    email,
                    mail_url,
                    exclude_message_ids=exclude_message_ids,
                    redirect_uri=redir,
                    reason="create_account_user_already_exists",
                )
                if web_at:
                    try:
                        refresher.web_access_token = web_at
                        refresher.access_token = web_at
                        refresher.web_plan_type = plan
                    except Exception:
                        pass
                    refresher._log(
                        f"login-existing OK plan={plan} token_len={len(web_at)} "
                        f"detail={str(login_detail)[:80]}"
                    )
                    return {
                        "_chatgpt_access_token": web_at,
                        "_chatgpt_plan": plan,
                        "_login_existing": True,
                    }
                raise RuntimeError(
                    "user_already_exists but login-existing failed to get accessToken: "
                    f"{str(login_detail)[:180]}"
                )
            else:
                for fatal in (
                    "registration_disallowed",
                    "account_creation_failed",
                    "cannot create your account",
                ):
                    if fatal in err_l:
                        raise RuntimeError(f"{fatal}: {err_body[:160]}")
                raise RuntimeError(f"create_account failed HTTP {status}: {err_body[:160]}")

    # 8. Workspace（OTP 后可能是 workspace / workspace_select）
    if page_type in (
        "workspace",
        "workspace_select",
        "workspace_selection",
        "select_workspace",
        "workspace_picker",
    ):
        dump_resp, _ = request_with_retry(
            refresher.session, "get",
            f"{C.AUTH_BASE}/api/accounts/client_auth_session_dump",
            headers={"accept": "application/json",
                     "referer": f"{C.AUTH_BASE}/workspace"},
            verify=False, timeout=20,
        )
        if dump_resp is not None:
            dump_payload = response_json(dump_resp)
            extra = {"page_type_before_workspace": page_type}
            payload = select_web_workspace(refresher, email, account_id, dump_payload)
            save_debug(email, "web_workspace_select_result", payload, extra=extra)
            page_type = str(((payload.get("page") or {}).get("type")) or page_type)
            refresher._log(f"after workspace_select: page_type={page_type}")

    # 8.4 Hard cut after create_account only (not plain re-login):
    #     no OAuth callback / homepage AT /api/auth/session / recover / surface warm.
    if _skip_post_create_enabled() and account_just_created:
        cont_skip = str(payload.get("continue_url") or "").strip()
        refresher._log(
            "SKIP_POST_CREATE=1 — stop after create (no callback, no AT, "
            f"no session); page_type={page_type or '-'} "
            f"continue_url={(cont_skip[:80] if cont_skip else '-')}"
        )
        try:
            refresher.web_access_token = ""
            refresher.access_token = ""
            refresher.web_plan_type = "free"
        except Exception:
            pass
        return {
            "_chatgpt_access_token": "",
            "_chatgpt_plan": "free",
            "_skip_post_create": True,
            "_create_ok": True,
            "_page_type": page_type or "",
            "_continue_url": cont_skip,
        }
    if _skip_post_create_enabled() and not account_just_created:
        refresher._log(
            "SKIP_POST_CREATE set but no create_account this run — "
            "continue normal callback/AT path (login-only)"
        )

    # 8.5 external_url（跟随 OAuth callback 回到 chatgpt.com）
    # about_you / workspace_select 之后都可能落到这里
    callback_url = ""
    oauth_denied = False
    if page_type == "external_url" or str(payload.get("continue_url") or "").strip():
        try:
            from .humanize import human_pause

            human_pause("post_create")
            human_pause("pre_callback")
        except Exception:
            pass
        callback_url = str(payload.get("continue_url") or "").strip()
        if callback_url:
            # Ensure chatgpt.com cookies present before code exchange
            try:
                _warm_chatgpt_home(refresher, "pre-callback")
            except Exception:
                pass
            followed = _follow_oauth_callback(refresher, callback_url)
            try:
                from chatgpt_register.protocol.gold_path import (
                    ensure_device_id_bound,
                    mark as gold_mark,
                )

                gold_mark(refresher, "oauth_callback", note=str(followed)[:60])
                ensure_device_id_bound(refresher, log=refresher._log)
            except Exception:
                pass
            if str(followed).startswith("ERROR:"):
                err_tag = str(followed)[6:]
                refresher._log(f"callback rejected: {followed}")
                # soft: access_denied / OAuthCallback / callback_http_403 …
                # account often already created; CF on callback ≠ deactivated.
                # hard: rare non-retryable codes only.
                if _is_soft_callback_error(err_tag):
                    oauth_denied = True
                    refresher._log(
                        f"callback soft-fail {err_tag} — will recover "
                        "(create_account likely ok; NOT account ban)"
                    )
                    # 预热/高并发：
                    # - FAIL_FAST=1 默认仍跳过长 recover
                    # - CALLBACK_RECOVER_ONCE=1：允许走下方一次 recover（提成功率，仍比无限重试快）
                    _ff = (os.environ.get("TOKENREFRESH_CALLBACK_FAIL_FAST") or "").strip().lower() in (
                        "1",
                        "true",
                        "yes",
                        "on",
                    )
                    _once = (os.environ.get("TOKENREFRESH_CALLBACK_RECOVER_ONCE") or "").strip().lower() in (
                        "1",
                        "true",
                        "yes",
                        "on",
                    )
                    if _ff and not _once:
                        raise RuntimeError(
                            f"OAuth callback soft-fail (fail-fast, no recover): {err_tag}"
                        )
                    if _ff and _once:
                        refresher._log(
                            f"callback soft-fail {err_tag} — recover_once enabled"
                        )
                else:
                    raise RuntimeError(
                        f"OAuth callback failed after create_account: {followed}"
                    )
        else:
            # create_account 200 但无 continue_url：仍热身 chatgpt.com
            refresher._log("external_url without continue_url — warm chatgpt.com only")
            _warm_chatgpt_home(refresher, "no-continue-url")

    # 9. 拿到 web accessToken — 默认与手动 HAR 一致：
    #    callback 后 GET https://chatgpt.com/ 从 HTML 抠 accessToken
    #    （不主动 GET /api/auth/session；可用 TOKENREFRESH_SESSION_FALLBACK=1 恢复）
    # - access_denied：跳过空轮询，直接一次 recover
    # - callback 5xx：上面已 hard-raise，不会进这里
    if oauth_denied:
        web_at, plan, sess_detail = "", "unknown", "oauth_denied_skip_poll"
        refresher._log("oauth_denied — skip home AT fetch, go recover once")
    else:
        try:
            from .humanize import human_pause

            human_pause("micro")
            # Home once for HTML accessToken extract (not full path spine)
            _warm_chatgpt_home(refresher, "pre-session-home")
        except Exception:
            pass
        # callback 后主页 HTML 抠 accessToken（默认不 /api/auth/session）
        web_at, plan, sess_detail = _fetch_web_access_token(
            refresher, tries=2 if fast else 3, base_pause=0.15, fail_fast_net=True
        )

    if (
        not web_at
        and not oauth_denied
        and not _has_nextauth_session_cookie(refresher.session)
    ):
        refresher._log("no next-auth cookie — one relink attempt")
        _try_relink_chatgpt_signin(refresher, email)
        web_at, plan, sess_detail = _fetch_web_access_token(
            refresher, tries=2, base_pause=0.4, fail_fast_net=True
        )

    if not web_at and callback_url and not oauth_denied:
        refresher._log("still no accessToken — retry good callback once")
        followed = _follow_oauth_callback(refresher, callback_url)
        if str(followed).startswith("ERROR:"):
            err_tag = str(followed)[6:]
            if _is_soft_callback_error(err_tag):
                oauth_denied = True
            else:
                raise RuntimeError(
                    f"OAuth callback retry failed after create_account: {followed}"
                )
        else:
            web_at, plan, sess_detail = _fetch_web_access_token(
                refresher, tries=2, base_pause=0.4, fail_fast_net=True
            )

    if not web_at and oauth_denied:
        # soft callback (403/OAuthCallback/access_denied). Recover may re-OTP.
        t_rec0 = time.time()
        web_at, plan, sess_detail = _recover_after_oauth_denied(
            refresher,
            email,
            mail_url,
            exclude_message_ids=exclude_message_ids,
        )
        refresher._log(f"recover finished in {time.time() - t_rec0:.1f}s token_len={len(web_at)}")
    elif not web_at and not _has_nextauth_session_cookie(refresher.session):
        # Only if we already know the account exists. Do NOT run full login-existing
        # for every create/callback miss (that doubled wall time to 110–180s/account).
        already = bool(getattr(refresher, "_account_already_exists", False))
        if already:
            refresher._log(
                "session missing after callback — one lean login-existing "
                "(already_exists=1)"
            )
            try:
                web_at2, plan2, detail2 = _login_existing_account_for_at(
                    refresher,
                    email,
                    mail_url,
                    exclude_message_ids=exclude_message_ids,
                    reason="session_missing_after_callback",
                )
                if web_at2:
                    web_at, plan, sess_detail = web_at2, plan2, detail2
            except Exception as login_exc:
                refresher._log(f"login-existing after session-missing soft: {login_exc}")
        if not web_at:
            # No cookie after create+callback path — fail fast.
            raise RuntimeError(
                "ChatGPT session missing after callback "
                f"(plan={plan}; {sess_detail[:160]}; "
                f"sess_cookie=False; no recover for non-access_denied)"
            )

    cookie_hint = ",".join(_cookie_names(refresher.session)[:12])
    refresher._log(
        f"ChatGPT session check: plan={plan} token_len={len(web_at)} "
        f"sess_cookie={_has_nextauth_session_cookie(refresher.session)} "
        f"oauth_denied={oauth_denied} cookies=[{cookie_hint}] last={sess_detail[:120]}"
    )
    if not web_at:
        raise RuntimeError(
            "ChatGPT session did not return accessToken "
            f"(plan={plan}; oauth_denied={oauth_denied}; {sess_detail[:160]}; "
            f"sess_cookie={_has_nextauth_session_cookie(refresher.session)}; "
            f"cookies={cookie_hint[:120]})"
        )
    # 与 session poll 一致：保证属性可读（register 模块只认属性、不认返回 dict）
    try:
        refresher.web_access_token = web_at
        refresher.access_token = web_at
        refresher.web_plan_type = plan
    except Exception:
        pass
    return {
        "_chatgpt_access_token": web_at,
        "_chatgpt_plan": plan,
        "_password_added": bool(getattr(refresher, "_password_added", False)),
    }


def _clear_auth_login_cookies(session) -> int:
    """清掉 auth.openai.com 上会把 Codex 钉死在 session/select 的登录态 cookie。

    保留 oai-did / CF 等设备与风控 cookie。用于强制走 bindphone.har 的邮箱 OTP 路径。
    """
    drop = {
        "login_session",
        "oai-client-auth-session",
        "oai-client-auth-info",
        "auth-session-minimized",
        "auth-session-minimized-client-checksum",
        "auth_provider",
        "unified_session_manifest",
        "hydra_redirect",
        "oai-sc",
        "rg_context",
        "iss_context",
    }
    n = 0
    jar = getattr(session, "cookies", None)
    if jar is None:
        return 0
    for name in list(drop):
        try:
            if hasattr(jar, "delete"):
                jar.delete(name)
                n += 1
                continue
        except Exception:
            pass
        try:
            if hasattr(jar, "set"):
                jar.set(name, "", domain="auth.openai.com")
                jar.set(name, "", domain=".auth.openai.com")
                jar.set(name, "", domain=".openai.com")
                n += 1
        except Exception:
            pass
    return n


def establish_add_phone_via_email_otp(
    refresher: TokenRefresher,
    email: str,
    *,
    account_id: str = "",
    mail_url: str = "",
    password: str = "",
) -> dict:
    """对齐 bindphone.har：邮箱 OTP 后落到可 send 的 add_phone。

    成功 HAR 路径：
      oauth/authorize → authorize/continue(email) → email-otp/validate
      → page=add_phone → add-phone/send 200

    产线失败路径：
      web SSO → choose-an-account → session/select → page=add_phone
      → add-phone/send 409（cookie 齐全仍 invalid_state）

    本函数清 SSO 登录 cookie 后重走邮箱 OTP，返回
    ``{"_status":"add_phone","_oauth":{code_verifier,...}}`` 或已换到的 tokens。
    """
    import secrets
    from .email_ import (
        has_ms_oauth_credentials,
        poll_email_direct,
        resend_email_otp,
    )

    email = str(email or "").strip()
    if not email:
        raise RuntimeError("establish_add_phone_via_email_otp: empty email")

    if not mail_url:
        try:
            if has_ms_oauth_credentials(email):
                mail_url = f"msoauth://{email.lower()}"
            else:
                mail_url = f"msoauth://{email.lower()}"
        except Exception:
            mail_url = f"msoauth://{email.lower()}"

    cleared = _clear_auth_login_cookies(refresher.session)
    refresher._log(
        f"[oauth] bindphone.har path: clear auth login cookies n={cleared} "
        f"→ authorize + email-otp → add_phone"
    )

    verifier, challenge = generate_pkce()
    state = secrets.token_hex(32)
    har_scope = "openid profile email offline_access"
    params = {
        "client_id": C.CODEX_OAUTH_CLIENT_ID,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "codex_cli_simplified_flow": "true",
        "id_token_add_organizations": "true",
        "redirect_uri": C.CODEX_OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": har_scope,
        "state": state,
        # 尽量逼重新登录（部分环境会忽略）
        "max_age": "0",
    }
    authorize_url = f"{C.AUTH_BASE}/oauth/authorize?{urllib.parse.urlencode(params)}"

    def _oauth_state_local(status: str) -> dict:
        return {
            "_status": status,
            "_oauth": {
                "code_verifier": verifier,
                "redirect_uri": C.CODEX_OAUTH_REDIRECT_URI,
                "client_id": C.CODEX_OAUTH_CLIENT_ID,
                "account_id": account_id,
                "path": "email_otp_add_phone",
            },
            "access_token": "",
            "refresh_token": "",
        }

    def _page_from_payload(payload: dict, resp=None) -> str:
        pt = str(((payload or {}).get("page") or {}).get("type") or "").strip()
        if pt:
            return pt
        if resp is not None:
            url = str(getattr(resp, "url", "") or "").lower()
            if "add-phone" in url:
                return "add_phone"
            if "email-verification" in url or "email_verification" in url:
                return "email_otp_verification"
            if "log-in" in url or "login" in url:
                return "login"
            if "choose-an-account" in url:
                return "choose-an-account"
        cont = str((payload or {}).get("continue_url") or "").lower()
        if "add-phone" in cont:
            return "add_phone"
        if "email-verification" in cont:
            return "email_otp_verification"
        return pt or ""

    resp, err = request_with_retry(
        refresher.session,
        "get",
        authorize_url,
        headers=refresher._navigate_headers(C.CODEX_OAUTH_REDIRECT_URI),
        allow_redirects=True,
        verify=False,
        timeout=30,
    )
    if resp is None:
        raise RuntimeError(f"email-otp add_phone authorize failed: {err}")

    final_url = str(getattr(resp, "url", "") or "")
    refresher._log(
        f"[oauth] email-otp path authorize → url={final_url[:140]}"
    )

    # 若仍落到 choose-an-account：再清一次 cookie 并尝试 /log-in
    if "choose-an-account" in final_url.lower():
        _clear_auth_login_cookies(refresher.session)
        resp2, _ = request_with_retry(
            refresher.session,
            "get",
            f"{C.AUTH_BASE}/log-in",
            headers=refresher._navigate_headers(authorize_url),
            allow_redirects=True,
            verify=False,
            timeout=20,
        )
        if resp2 is not None:
            resp = resp2
            final_url = str(getattr(resp, "url", "") or "")
            refresher._log(
                f"[oauth] force /log-in after choose-an-account → {final_url[:120]}"
            )
        # 再拉一次 authorize（无 SSO 时应进 log-in）
        resp3, _ = request_with_retry(
            refresher.session,
            "get",
            authorize_url,
            headers=refresher._navigate_headers(C.CODEX_OAUTH_REDIRECT_URI),
            allow_redirects=True,
            verify=False,
            timeout=30,
        )
        if resp3 is not None:
            resp = resp3
            final_url = str(getattr(resp, "url", "") or "")
            refresher._log(
                f"[oauth] re-authorize after cookie clear → {final_url[:120]}"
            )

    # authorize/continue (email) — HAR 成功关键步
    email_otp_not_before = time.time() - float(
        getattr(C, "EMAIL_OTP_TIME_SKEW", 5) or 5
    )
    h = refresher._json_headers(f"{C.AUTH_BASE}/log-in")
    try:
        apply_sentinel_headers(
            h, refresher.session, refresher.device_id, "authorize_continue",
            profile=getattr(refresher, "fingerprint_profile", None),
        )
    except Exception as se:
        refresher._log(f"[oauth] sentinel authorize_continue soft-fail: {se}")

    cont_resp, cont_err = request_with_retry(
        refresher.session,
        "post",
        f"{C.AUTH_BASE}/api/accounts/authorize/continue",
        json_data={"username": {"kind": "email", "value": email}},
        headers=h,
        verify=False,
        timeout=30,
    )
    if cont_resp is None:
        raise RuntimeError(f"authorize/continue failed: {cont_err}")
    payload = response_json(cont_resp)
    save_debug(
        email,
        "email_otp_add_phone_continue",
        payload,
        status_code=getattr(cont_resp, "status_code", ""),
    )
    page_type = _page_from_payload(payload, cont_resp)
    st_cont = int(getattr(cont_resp, "status_code", 0) or 0)
    refresher._log(
        f"[oauth] authorize/continue HTTP {st_cont} page={page_type or '-'} "
        f"cont={str(payload.get('continue_url') or '')[:80]}"
    )
    if st_cont != 200:
        # 409 死态：再清 cookie + 一次 authorize 后重试 continue
        if st_cont in (403, 409):
            _clear_auth_login_cookies(refresher.session)
            request_with_retry(
                refresher.session,
                "get",
                authorize_url,
                headers=refresher._navigate_headers(C.CODEX_OAUTH_REDIRECT_URI),
                allow_redirects=True,
                verify=False,
                timeout=30,
            )
            cont_resp, cont_err = request_with_retry(
                refresher.session,
                "post",
                f"{C.AUTH_BASE}/api/accounts/authorize/continue",
                json_data={"username": {"kind": "email", "value": email}},
                headers=refresher._json_headers(f"{C.AUTH_BASE}/log-in"),
                verify=False,
                timeout=30,
            )
            if cont_resp is None or int(getattr(cont_resp, "status_code", 0) or 0) != 200:
                raise RuntimeError(
                    f"authorize/continue HTTP {st_cont} after retry: {cont_err}"
                )
            payload = response_json(cont_resp)
            page_type = _page_from_payload(payload, cont_resp)
            refresher._log(
                f"[oauth] authorize/continue retry ok page={page_type or '-'}"
            )
        else:
            raise RuntimeError(f"authorize/continue HTTP {st_cont}")

    # password 页：有密码则验；否则走 passwordless OTP
    if page_type in ("login_password", "password"):
        if str(password or "").strip():
            hp = refresher._json_headers(f"{C.AUTH_BASE}/log-in/password")
            try:
                apply_sentinel_headers(
                    hp, refresher.session, refresher.device_id, "password_verify",
                    profile=getattr(refresher, "fingerprint_profile", None),
                )
            except Exception:
                pass
            pr, pe = request_with_retry(
                refresher.session,
                "post",
                f"{C.AUTH_BASE}/api/accounts/password/verify",
                json_data={"password": password},
                headers=hp,
                verify=False,
                timeout=30,
            )
            if pr is None or int(getattr(pr, "status_code", 0) or 0) != 200:
                raise RuntimeError(f"password_verify failed: {pe}")
            payload = response_json(pr)
            page_type = _page_from_payload(payload, pr)
            refresher._log(f"[oauth] after password page={page_type or '-'}")
        else:
            hs = refresher._json_headers(f"{C.AUTH_BASE}/email-verification")
            try:
                apply_sentinel_headers(
                    hs, refresher.session, refresher.device_id, "email_otp_resend",
                    profile=getattr(refresher, "fingerprint_profile", None),
                )
            except Exception:
                pass
            sr, se = request_with_retry(
                refresher.session,
                "post",
                f"{C.AUTH_BASE}/api/accounts/email-otp/send",
                json_data={},
                headers=hs,
                verify=False,
                timeout=20,
            )
            if sr is None:
                raise RuntimeError(f"email-otp/send failed: {se}")
            payload = response_json(sr)
            page_type = "email_otp_verification"
            email_otp_not_before = time.time() - 2
            refresher._log(
                f"[oauth] passwordless email-otp/send HTTP="
                f"{getattr(sr, 'status_code', '?')}"
            )

    # 若 continue 已直接到 add_phone（少见）
    if page_type == "add_phone" or "add-phone" in str(
        payload.get("continue_url") or ""
    ).lower():
        refresher._log("[oauth] email path already at add_phone (no otp needed)")
        return _oauth_state_local("add_phone")

    # email OTP validate — HAR: 之后 continue_url=add-phone
    if page_type in (
        "email_otp_verification",
        "email_otp_send",
        "email_verification",
    ) or "email-verification" in str(payload.get("continue_url") or "").lower():
        code = None
        rounds = int(getattr(C, "EMAIL_OTP_VALIDATION_ROUNDS", 2) or 2)
        for round_idx in range(max(1, rounds)):
            if round_idx > 0:
                refresher._log("[oauth] email OTP timeout → resend")
                try:
                    resend_email_otp(refresher, email)
                except Exception as re:
                    refresher._log(f"[oauth] resend soft-fail: {re}")
                not_before = time.time() - 2
                time.sleep(float(getattr(C, "EMAIL_RESEND_WAIT_SECONDS", 3) or 3))
            else:
                not_before = email_otp_not_before
                # 给邮件一点时间
                time.sleep(1.0)

            code = poll_email_direct(
                mail_url,
                email,
                not_before=not_before,
                ignore_codes=None,
            )
            if not code:
                continue
            hv = refresher._json_headers(f"{C.AUTH_BASE}/email-verification")
            try:
                apply_sentinel_headers(
                    hv,
                    refresher.session,
                    refresher.device_id,
                    "email_otp_validate",
                    profile=getattr(refresher, "fingerprint_profile", None),
                )
            except Exception as e:
                refresher._log(f"sentinel for validate failed ({e}), trying without...")
            try:
                hv["oai-device-id"] = refresher.device_id
            except Exception:
                pass
            vr, ve = request_with_retry(
                refresher.session,
                "post",
                f"{C.AUTH_BASE}/api/accounts/email-otp/validate",
                json_data={"code": str(code).strip()},
                headers=hv,
                verify=False,
                timeout=30,
            )
            stv = int(getattr(vr, "status_code", 0) or 0) if vr is not None else 0
            if vr is not None and stv == 200:
                payload = response_json(vr)
                save_debug(
                    email,
                    "email_otp_add_phone_validate",
                    payload,
                    status_code=stv,
                )
                page_type = _page_from_payload(payload, vr)
                cont = str(payload.get("continue_url") or "")
                refresher._log(
                    f"[oauth] email-otp/validate OK page={page_type or '-'} "
                    f"cont={cont[:100]}"
                )
                break
            refresher._log(
                f"[oauth] email-otp/validate fail HTTP={stv} err={ve} — retry"
            )
            code = None

        if not code:
            raise RuntimeError(
                "establish_add_phone_via_email_otp: could not get/validate email OTP"
            )

    page_type = _page_from_payload(payload, None) or page_type
    cont = str(payload.get("continue_url") or "")
    if page_type == "add_phone" or "add-phone" in cont.lower():
        refresher._log(
            "[oauth] email-otp path landed add_phone — ready for phone send "
            "(bindphone.har aligned)"
        )
        try:
            refresher._last_codex_oauth = _oauth_state_local("add_phone")  # type: ignore[attr-defined]
        except Exception:
            pass
        return _oauth_state_local("add_phone")

    # 意外：email OTP 后直接给了 code / consent
    code = extract_code_from_payload(payload)
    if code:
        tokens = _do_exchange(code, verifier, refresher.proxy_url)
        save_debug(email, "codex_token_bundle", tokens)
        return tokens
    if page_type in (
        "sign_in_with_chatgpt_codex_consent",
        "sign_in_with_chatgpt_consent",
        "workspace",
    ) or "consent" in cont.lower():
        seed = dict(payload) if isinstance(payload, dict) else {}
        seed.setdefault("page", {"type": page_type or "sign_in_with_chatgpt_codex_consent"})
        payload2 = select_workspace_and_follow(
            refresher, email, account_id, seed
        )
        code2 = extract_code_from_payload(payload2)
        if code2:
            tokens = _do_exchange(code2, verifier, refresher.proxy_url)
            save_debug(email, "codex_token_bundle", tokens)
            return tokens
        pt2 = str(((payload2 or {}).get("page") or {}).get("type") or "")
        cont2 = str((payload2 or {}).get("continue_url") or "")
        if pt2 == "add_phone" or "add-phone" in cont2.lower():
            return _oauth_state_local("add_phone")

    raise RuntimeError(
        f"email-otp add_phone unexpected page={page_type or '-'} "
        f"cont={cont[:80]}"
    )


def codex_oauth_from_web_session(refresher: TokenRefresher,
                                   email: str, account_id: str = "",
                                   *,
                                   mail_url: str = "",
                                   password: str = "",
                                   force_email_otp_add_phone: bool | None = None) -> dict:
    """
    从已登录的 ChatGPT Web session 走 Codex OAuth，拿 Codex token。

    对齐 HAR「k12完整oauth」/ aitokensale generate-auth-url：
      GET /oauth/authorize
        client_id=app_EMoamEEZ…
        codex_cli_simplified_flow=true
        id_token_add_organizations=true
        redirect_uri=http://localhost:1455/auth/callback
        scope=openid profile email offline_access
      → choose-an-account → session/select
      → sign_in_with_chatgpt_codex_consent → workspace/select
      → localhost:1455?code=… → POST /oauth/token

    如果遇到 add_phone：
      - 默认 **保持 session/select → add_phone**（对齐 2026-07-31 完整 oauth HAR：
        网页已登录后选会话即可发短信；400 换号直至 200）
      - 旧 bindphone.har 邮箱 OTP 重开路径会清 auth cookie，易导致
        Invalid authorization step；仅当 K12_PHONE_EMAIL_OTP_FLOW=1 时启用
    """
    import re
    from urllib.parse import parse_qs, urlparse

    verifier, challenge = generate_pkce()
    state = __import__("secrets").token_hex(32)
    # HAR scope（与平台 generate-auth-url 一致；勿用 api.connectors 扩展 scope）
    har_scope = "openid profile email offline_access"
    params = {
        "client_id": C.CODEX_OAUTH_CLIENT_ID,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "codex_cli_simplified_flow": "true",
        "id_token_add_organizations": "true",
        "redirect_uri": C.CODEX_OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": har_scope,
        "state": state,
    }
    # 关键：/oauth/authorize（不是 /api/accounts/authorize）
    authorize_url = f"{C.AUTH_BASE}/oauth/authorize?{urllib.parse.urlencode(params)}"
    resp, err = request_with_retry(
        refresher.session, "get", authorize_url,
        headers=refresher._navigate_headers(C.CODEX_OAUTH_REDIRECT_URI),
        allow_redirects=True, verify=False, timeout=30,
    )
    if resp is None:
        raise RuntimeError(f"codex authorize failed: {err}")

    def _page_type_from_resp(r) -> str:
        if r is None:
            return ""
        try:
            j = response_json(r)
            pt = str(((j.get("page") or {}).get("type")) or "").strip()
            if pt:
                return pt
        except Exception:
            pass
        url = str(getattr(r, "url", "") or "").lower()
        text = (getattr(r, "text", None) or "")[:8000]
        if "code=" in url and ("localhost:1455" in url or "callback" in url):
            return "oauth_callback"
        if "choose-an-account" in url or "choose-an-account" in text:
            return "choose-an-account"
        if "add-phone" in url or '"type":"add_phone"' in text or '"type": "add_phone"' in text:
            return "add_phone"
        if "codex/consent" in url or "sign_in_with_chatgpt_codex_consent" in text:
            return "sign_in_with_chatgpt_codex_consent"
        if "/workspace" in url and "select" not in url:
            return "workspace"
        if "phone_otp" in url or "existing_phone" in text:
            return "existing_phone_otp"
        return ""

    def _norm_page(pt: str) -> str:
        p = (pt or "").strip().lower().replace("-", "_")
        aliases = {
            "choose_an_account": "choose-an-account",
            "sign_in_with_chatgpt_codex_consent": "sign_in_with_chatgpt_codex_consent",
            "sign_in_with_chatgpt_consent": "sign_in_with_chatgpt_consent",
            "add_phone": "add_phone",
            "workspace": "workspace",
            "workspace_select": "workspace",
            "workspace_selection": "workspace",
            "select_workspace": "workspace",
            "workspace_picker": "workspace",
            "oauth_callback": "oauth_callback",
            "existing_phone_otp": "existing_phone_otp",
            "phone_otp_select_channel": "existing_phone_otp",
        }
        return aliases.get(p, pt or "")

    def _extract_session_ids(html: str, prefer_email: str = "") -> list[str]:
        """HAR: form radio value=\"us_…\" name=\"session_id\" (not JSON)."""
        if not html:
            return []
        found: list[str] = []
        patterns = (
            # HAR button/radio
            r'name=["\']session_id["\'][^>]*value=["\'](us_[^"\']+)["\']',
            r'value=["\'](us_[^"\']+)["\'][^>]*name=["\']session_id["\']',
            r'Select existing session[^>]*value=["\'](us_[^"\']+)["\']',
            r'value=["\'](us_[^"\']+)["\'][^>]*Select existing session',
            r'"session_id"\s*:\s*"(us_[^"]+)"',
            r'"session_id"\s*:\s*"([^"]+)"',
            r'data-session-id=["\']([^"\']+)["\']',
        )
        for pat in patterns:
            for m in re.finditer(pat, html, flags=re.I):
                sid = m.group(1).strip()
                if sid and sid not in ("null", "undefined") and sid not in found:
                    found.append(sid)
        # Prefer session blocks that mention this email
        if prefer_email and found:
            em = prefer_email.lower()
            ranked: list[str] = []
            for sid in found:
                idx = html.find(sid)
                window = html[max(0, idx - 400) : idx + 400].lower()
                if em in window:
                    ranked.insert(0, sid)
                else:
                    ranked.append(sid)
            found = ranked
        return found

    def _oauth_state(status: str) -> dict:
        return {
            "_status": status,
            "_oauth": {
                "code_verifier": verifier,
                "redirect_uri": C.CODEX_OAUTH_REDIRECT_URI,
                "client_id": C.CODEX_OAUTH_CLIENT_ID,
                "account_id": account_id,
            },
            "access_token": "",
            "refresh_token": "",
        }

    def _try_exchange_from_payload(payload: dict) -> dict | None:
        code = extract_code_from_payload(payload)
        if not code:
            return None
        tokens = _do_exchange(code, verifier, refresher.proxy_url)
        save_debug(email, "codex_token_bundle", tokens)
        return tokens

    page_type = _norm_page(_page_type_from_resp(resp))
    final_url = str(getattr(resp, "url", "") or "")
    refresher._log(
        f"codex authorize: page_type={page_type or '-'} url={final_url[:160]}"
    )

    # /oauth/authorize 落到 log-in：SSO cookie 未带上，回退 /api/accounts/authorize
    if (not page_type and "log-in" in final_url.lower()) or page_type in (
        "login",
        "log_in",
        "email_otp_verification",
    ):
        refresher._log("codex authorize hit log-in — fallback api/accounts/authorize")
        params2 = {
            "response_type": "code",
            "client_id": C.CODEX_OAUTH_CLIENT_ID,
            "redirect_uri": C.CODEX_OAUTH_REDIRECT_URI,
            "scope": har_scope,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "codex_cli_simplified_flow": "true",
            "id_token_add_organizations": "true",
        }
        alt = f"{C.AUTH_BASE}/api/accounts/authorize?{urllib.parse.urlencode(params2)}"
        resp2, err2 = request_with_retry(
            refresher.session, "get", alt,
            headers=refresher._navigate_headers(C.CODEX_OAUTH_REDIRECT_URI),
            allow_redirects=True, verify=False, timeout=30,
        )
        if resp2 is not None:
            resp = resp2
            page_type = _norm_page(_page_type_from_resp(resp))
            final_url = str(getattr(resp, "url", "") or "")
            refresher._log(
                f"codex authorize fallback: page_type={page_type or '-'} url={final_url[:160]}"
            )

    # 直接落到 callback（极少见：单 workspace 自动同意）
    if page_type == "oauth_callback" or (
        "code=" in final_url and "localhost:1455" in final_url
    ):
        code = (parse_qs(urlparse(final_url).query).get("code") or [""])[0]
        if code:
            tokens = _do_exchange(code, verifier, refresher.proxy_url)
            save_debug(email, "codex_token_bundle", tokens)
            return tokens

    # choose-an-account → POST session/select（HAR form: name=session_id value=us_…）
    if page_type == "choose-an-account" or "choose-an-account" in final_url:
        html = getattr(resp, "text", None) or ""
        sids = _extract_session_ids(html, prefer_email=email)
        if not sids:
            ca_resp, _ = request_with_retry(
                refresher.session, "get", f"{C.AUTH_BASE}/choose-an-account",
                headers=refresher._navigate_headers(authorize_url),
                allow_redirects=True, verify=False, timeout=20,
            )
            if ca_resp is not None:
                html = ca_resp.text or ""
                sids = _extract_session_ids(html, prefer_email=email)
                resp = ca_resp
        if not sids:
            refresher._log("choose-an-account: session_id missing")
            raise RuntimeError("codex oauth choose-an-account without session_id")
        refresher._log(f"choose-an-account candidates={sids[:4]} n={len(sids)}")
        h = refresher._json_headers(f"{C.AUTH_BASE}/choose-an-account")
        payload: dict = {}
        for session_id in sids[:6]:
            resp, err = request_with_retry(
                refresher.session, "post",
                f"{C.AUTH_BASE}/api/accounts/session/select",
                json_data={"session_id": session_id}, headers=h, verify=False,
            )
            if resp is None:
                refresher._log(f"session/select fail sid={session_id[:16]}: {err}")
                continue
            payload = response_json(resp)
            page_type = _norm_page(
                str(((payload.get("page") or {}).get("type")) or "")
                or _page_type_from_resp(resp)
            )
            cont = str(payload.get("continue_url") or "").strip()
            refresher._log(
                f"session/select sid={session_id[:18]}… page_type={page_type or '-'} "
                f"cont={cont[:100]}"
            )
            # 诊断：bindphone.har 成功 send 依赖 login_session / oai-client-auth-session
            # curl_cffi Cookies 迭代是名字 str，不是 Cookie 对象
            try:
                jar = getattr(refresher.session, "cookies", None)
                cnames: set[str] = set()
                if jar is not None:
                    try:
                        cnames |= {str(k) for k in jar.keys()}  # type: ignore[attr-defined]
                    except Exception:
                        pass
                    try:
                        for c in jar:
                            if isinstance(c, str):
                                cnames.add(c)
                            else:
                                n = str(getattr(c, "name", "") or "").strip()
                                if n:
                                    cnames.add(n)
                    except Exception:
                        pass
                miss = [
                    n
                    for n in (
                        "login_session",
                        "oai-client-auth-session",
                        "auth-session-minimized",
                    )
                    if n not in cnames
                ]
                if miss:
                    refresher._log(
                        f"session/select missing cookies {miss} "
                        f"page={page_type or '-'} jar_n={len(cnames)}"
                    )
                else:
                    refresher._log(
                        f"session/select auth cookies ok page={page_type or '-'} "
                        f"jar_n={len(cnames)}"
                    )
            except Exception:
                pass
            tok = _try_exchange_from_payload(payload)
            if tok:
                return tok
            # 成功离开 choose-an-account
            if page_type not in ("", "choose-an-account") or (
                cont and "choose-an-account" not in cont
            ):
                if cont and "consent" in cont:
                    request_with_retry(
                        refresher.session, "get", cont,
                        headers=refresher._navigate_headers(
                            f"{C.AUTH_BASE}/choose-an-account"
                        ),
                        allow_redirects=True, verify=False, timeout=20,
                    )
                    if not page_type or page_type == "choose-an-account":
                        page_type = "sign_in_with_chatgpt_codex_consent"
                if cont and "add-phone" in cont:
                    page_type = "add_phone"
                    # 默认 **不** document-open：历史最好一轮（~15% send 200）
                    # 仅靠 session/select JSON page_type=add_phone 就 send。
                    # 强制 open continue_url/document 实测把 send 200 打到 0%。
                    # 需要时设 K12_PHONE_OPEN_ADD_PHONE_DOC=1
                    if (os.environ.get("K12_PHONE_OPEN_ADD_PHONE_DOC") or "").strip().lower() in (
                        "1", "true", "yes", "on",
                    ):
                        try:
                            request_with_retry(
                                refresher.session,
                                "get",
                                cont,
                                headers=refresher._navigate_headers(
                                    f"{C.AUTH_BASE}/choose-an-account"
                                ),
                                allow_redirects=True,
                                verify=False,
                                timeout=20,
                            )
                            refresher._log(
                                f"opened add-phone continue_url={cont[:100]}"
                            )
                        except Exception as e:
                            refresher._log(f"open add-phone cont soft-fail: {e}")
                break
        else:
            raise RuntimeError(
                f"codex oauth session/select stuck on choose-an-account "
                f"(tried {len(sids[:6])} sids)"
            )

    if page_type == "add_phone":
        # 默认保持 session/select 落地的 add_phone（用户 31 日完整 oauth HAR）
        # 仅显式 K12_PHONE_EMAIL_OTP_FLOW=1 才改走清 cookie 的邮箱 OTP 路径
        use_email_flow = force_email_otp_add_phone
        if use_email_flow is None:
            use_email_flow = (
                os.environ.get("K12_PHONE_EMAIL_OTP_FLOW") or "0"
            ).strip().lower() in ("1", "true", "yes", "on")
        if use_email_flow:
            try:
                refresher._log(
                    "[oauth] session/select add_phone → switch to "
                    "bindphone.har email-otp path (opt-in)"
                )
                return establish_add_phone_via_email_otp(
                    refresher,
                    email,
                    account_id=account_id or "",
                    mail_url=mail_url or "",
                    password=password or "",
                )
            except Exception as e:
                refresher._log(
                    f"[oauth] email-otp add_phone path failed, "
                    f"fallback weak add_phone state: {e}"
                )
        else:
            refresher._log(
                "[oauth] session/select → add_phone kept "
                "(HAR path; no cookie clear / no re-email-otp)"
            )
        if (os.environ.get("K12_PHONE_OPEN_ADD_PHONE_DOC") or "").strip().lower() in (
            "1", "true", "yes", "on",
        ):
            try:
                nav, _ne = request_with_retry(
                    refresher.session,
                    "get",
                    f"{C.AUTH_BASE}/add-phone",
                    headers=refresher._navigate_headers(f"{C.AUTH_BASE}/"),
                    allow_redirects=True,
                    verify=False,
                    timeout=15,
                )
                if nav is not None:
                    refresher._log(
                        f"add-phone document GET HTTP "
                        f"{getattr(nav, 'status_code', '?')} "
                        f"url={str(getattr(nav, 'url', '') or '')[:100]}"
                    )
            except Exception as e:
                refresher._log(f"add-phone document GET soft-fail: {e}")
        return _oauth_state("add_phone")

    if page_type in ("existing_phone_otp",):
        return _oauth_state("existing_phone_otp_required")

    # Workspace / Consent → workspace/select → code
    if page_type in (
        "workspace",
        "sign_in_with_chatgpt_codex_consent",
        "sign_in_with_chatgpt_consent",
    ) or "consent" in (final_url or "").lower():
        seed = response_json(resp) if resp is not None else {}
        if not isinstance(seed, dict):
            seed = {}
        seed.setdefault(
            "page",
            {"type": page_type or "sign_in_with_chatgpt_codex_consent"},
        )
        payload = select_workspace_and_follow(
            refresher, email, account_id, seed
        )
        tok = _try_exchange_from_payload(payload)
        if tok:
            return tok
        pt2 = _norm_page(str(((payload.get("page") or {}).get("type")) or ""))
        cont2 = str(payload.get("continue_url") or "")
        if pt2 == "add_phone" or "add-phone" in cont2:
            use_email_flow = force_email_otp_add_phone
            if use_email_flow is None:
                use_email_flow = (
                    os.environ.get("K12_PHONE_EMAIL_OTP_FLOW") or "0"
                ).strip().lower() in ("1", "true", "yes", "on")
            if use_email_flow:
                try:
                    refresher._log(
                        "[oauth] workspace→add_phone → switch to "
                        "bindphone.har email-otp path"
                    )
                    return establish_add_phone_via_email_otp(
                        refresher,
                        email,
                        account_id=account_id or "",
                        mail_url=mail_url or "",
                        password=password or "",
                    )
                except Exception as e:
                    refresher._log(
                        f"[oauth] email-otp add_phone (workspace) fail: {e}"
                    )
            if (os.environ.get("K12_PHONE_OPEN_ADD_PHONE_DOC") or "").strip().lower() in (
                "1", "true", "yes", "on",
            ):
                if cont2 and "add-phone" in cont2:
                    try:
                        request_with_retry(
                            refresher.session,
                            "get",
                            cont2,
                            headers=refresher._navigate_headers(f"{C.AUTH_BASE}/"),
                            allow_redirects=True,
                            verify=False,
                            timeout=20,
                        )
                        refresher._log(
                            f"opened add-phone from workspace cont={cont2[:100]}"
                        )
                    except Exception as e:
                        refresher._log(f"open add-phone workspace cont soft-fail: {e}")
                try:
                    request_with_retry(
                        refresher.session,
                        "get",
                        f"{C.AUTH_BASE}/add-phone",
                        headers=refresher._navigate_headers(f"{C.AUTH_BASE}/"),
                        allow_redirects=True,
                        verify=False,
                        timeout=15,
                    )
                except Exception:
                    pass
            return _oauth_state("add_phone")

    # 兜底：final URL 上的 code
    final_url = str(getattr(resp, "url", "") or "")
    code = (parse_qs(urlparse(final_url).query).get("code") or [""])[0]
    if code:
        tokens = _do_exchange(code, verifier, refresher.proxy_url)
        save_debug(email, "codex_token_bundle", tokens)
        return tokens

    raise RuntimeError(f"codex oauth unexpected page: {page_type or '(empty)'}")




def _do_exchange(code, verifier, proxy_url):
    from .utils import exchange_code
    tokens = exchange_code(code=code, code_verifier=verifier,
                           redirect_uri=C.CODEX_OAUTH_REDIRECT_URI,
                           client_id=C.CODEX_OAUTH_CLIENT_ID,
                           proxy_url=proxy_url)
    if not tokens:
        raise RuntimeError("Codex token exchange failed")
    return tokens


def _classify_session_plan(data: dict) -> str:
    acc = data.get("account") or {}
    if isinstance(acc, dict):
        for key in ("planType", "plan_type", "workspace_plan_type"):
            v = str(acc.get(key) or "").strip().lower()
            if v:
                return v
    at = str(data.get("accessToken") or "")
    parts = at.split(".")
    if len(parts) >= 2:
        from .utils import decode_jwt_segment
        claims = decode_jwt_segment(parts[1])
        auth = claims.get("https://api.openai.com/auth") or {}
        return str(auth.get("chatgpt_plan_type", "unknown")).lower()
    return "unknown"
