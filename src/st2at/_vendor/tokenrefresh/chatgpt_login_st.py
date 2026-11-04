"""Login ChatGPT Web (参考 k12 phase_login_only / chatgpt_web_login) 获取 ST。

协议支付 finalize 需要 ``__Secure-next-auth.session-token`` 注入登录态，
才能正确回调到指定账号。本模块：

1. 用邮箱 + mail_url（iCloud 等）走 ChatGPT Web 登录拿 OTP
2. 从会话 Cookie 提取 ST + 附属 cookies
3. 可选写回 accounts.meta_json，供 settle 复用

依赖：vendor/tokenrefresh（自 k12 项目 vendored）。
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, unquote, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parent
VENDOR = ROOT / "vendor"
if str(VENDOR) not in sys.path:
    sys.path.insert(0, str(VENDOR))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SESSION_COOKIE = "__Secure-next-auth.session-token"
SESSION_COOKIE_BASES = (
    "__secure-next-auth.session-token",
    "next-auth.session-token",
    "__secure-authjs.session-token",
    "authjs.session-token",
)


def _default_711_proxy() -> str:
    explicit = os.getenv("PAY153_711_PROXY", "").strip()
    if explicit:
        return explicit
    host = os.getenv("PAY153_711_HOST", "").strip()
    port = os.getenv("PAY153_711_PORT", "").strip()
    user = os.getenv("PAY153_711_USER", "").strip()
    password = os.getenv("PAY153_711_PASS", "").strip()
    if not all((host, port, user, password)):
        return ""
    return f"{host}:{port}:{user}:{password}"


_DEFAULT_711 = _default_711_proxy()
_SID_ROTATE_MARKERS = (
    "403",
    "http=403",
    "callback_http_403",
    "cf_interactive",
    "rotate_proxy",
    "authorize stuck",
    "oauth_denied",
    "soft env",
    "cloudflare",
    "home http",
    "cf-mitigated",
)


def _log_fn(log: Callable[[str], None] | None):
    def _inner(msg: str) -> None:
        try:
            (log or print)(f"[login_st] {msg}")
        except Exception:
            pass

    return _inner


def rotate_proxy_sid(proxy: str, sid: str = "") -> str:
    """在 711 用户名里写入/替换随机 session，分配独立 sticky 出口。"""
    raw = (proxy or "").strip() or _DEFAULT_711
    new_sid = (sid or uuid.uuid4().hex[:12]).strip()

    def _rewrite_user(user: str) -> str:
        user = str(user or "").strip()
        if not user:
            return f"session-{new_sid}-sessTime-180"
        value = re.sub(r"(?i)-sid-[A-Za-z0-9]+", "", user)
        if re.search(r"(?i)-session-[A-Za-z0-9]+", value):
            value = re.sub(r"(?i)(-session-)[A-Za-z0-9]+", rf"\g<1>{new_sid}", value, count=1)
        else:
            value = f"{value}-session-{new_sid}"
        if re.search(r"(?i)-sessTime-\d+", value):
            return re.sub(r"(?i)(-sessTime-)\d+", r"\g<1>180", value, count=1)
        return f"{value}-sessTime-180"

    if "://" in raw:
        parsed = urlsplit(raw)
        user = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if not user:
            return raw
        new_user = _rewrite_user(user)
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        auth = f"{quote(new_user, safe='')}:{quote(password, safe='')}@"
        netloc = f"{auth}{host}"
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))

    parts = raw.split(":")
    if len(parts) >= 4 and parts[1].isdigit():
        parts[2] = _rewrite_user(parts[2])
        return ":".join(parts)
    return raw


def _should_rotate_sid(err: str) -> bool:
    low = str(err or "").lower()
    return any(m in low for m in _SID_ROTATE_MARKERS)


def _st_from_session_json(data: Any) -> str:
    """从 /api/auth/session JSON 抠 session_token（不只 accessToken）。"""
    if not isinstance(data, dict):
        return ""
    keys = (
        "sessionToken",
        "session_token",
        "session-token",
        "nextAuthSessionToken",
        "next_auth_session_token",
    )
    for k in keys:
        v = str(data.get(k) or "").strip()
        if len(v) > 20:
            return v
    for nest_key in ("session", "user", "data"):
        nested = data.get(nest_key)
        if not isinstance(nested, dict):
            continue
        for k in keys + ("token",):
            v = str(nested.get(k) or "").strip()
            if len(v) <= 20:
                continue
            if v.count(".") >= 2 and v.startswith("eyJ"):
                continue
            if "session" in k.lower() or k == "token":
                return v
    return ""


def _st_from_response_headers(resp: Any) -> str:
    headers = getattr(resp, "headers", None)
    if headers is None:
        return ""
    lines: list[str] = []
    for getter in (
        lambda: list(headers.get_list("set-cookie") or []),
        lambda: list(headers.get_list("Set-Cookie") or []),
    ):
        try:
            got = getter()
            if got:
                lines = [str(x) for x in got]
                break
        except Exception:
            continue
    if not lines:
        raw = ""
        try:
            raw = str(headers.get("set-cookie") or headers.get("Set-Cookie") or "")
        except Exception:
            raw = ""
        if raw:
            lines = [raw]
    exact = ""
    chunks: dict[int, str] = {}
    for line in lines:
        for match in re.finditer(
            r"(?i)(?:^|[,\s])((?:__secure-)?(?:next-auth|authjs)\.session-token)(?:\.(\d+))?=([^;,\s]+)",
            line,
        ):
            value = unquote(match.group(3).strip())
            if match.group(2) is None:
                exact = value
            else:
                chunks[int(match.group(2))] = value
    if exact:
        return exact
    return "".join(chunks[index] for index in sorted(chunks))


def fetch_st_from_auth_session(refresher: Any, lg: Callable[[str], None]) -> tuple[str, str, list[dict[str, Any]], str]:
    """登录后打 https://chatgpt.com/api/auth/session，取 ST + AT。

    返回 (st, access_token, cookies, http_status)。必须带 next-auth / oai 头，裸 GET 会被 CF 403。
    """
    st, at = "", ""
    cookies: list[dict[str, Any]] = []
    last_http = ""
    try:
        from tokenrefresh.utils import request_with_retry, response_json
        from tokenrefresh.web import _session_headers
        from tokenrefresh import constants as C
    except Exception as exc:
        lg(f"auth/session import fail: {exc}")
        return "", "", [], ""

    urls = (
        str(getattr(C, "CHATGPT_SESSION_URL", "") or "https://chatgpt.com/api/auth/session"),
        "https://chatgpt.com/api/auth/session?refresh=true",
    )
    headers = _session_headers(refresher)
    last_http = "?"
    last_keys: list[str] = []
    for url in urls:
        resp, err = request_with_retry(
            refresher.session,
            "get",
            url,
            headers=headers,
            allow_redirects=True,
            verify=False,
            timeout=20,
        )
        if resp is None:
            lg(f"auth/session fail url={url.split('?')[0][-24:]} err={err}")
            continue
        last_http = str(getattr(resp, "status_code", "?"))
        hdr_st = _st_from_response_headers(resp)
        if hdr_st:
            st = hdr_st
        data: Any = {}
        if int(getattr(resp, "status_code", 0) or 0) == 200:
            data = response_json(resp)
            if not isinstance(data, dict):
                data = {}
            last_keys = list(data.keys())[:16]
            json_st = _st_from_session_json(data)
            if json_st:
                st = json_st
            if not at:
                at = str(data.get("accessToken") or data.get("access_token") or "").strip()
        jar_st, jar_cookies = extract_st_from_session(refresher.session)
        if jar_st and not st:
            st = jar_st
        if jar_cookies:
            cookies = jar_cookies
        lg(
            f"auth/session HTTP={last_http} keys={last_keys} "
            f"st_len={len(st)} at_len={len(at)} cookies={len(cookies)}"
        )
        if st or int(getattr(resp, "status_code", 0) or 0) == 200:
            break
    return st, at, cookies, last_http


def extract_st_from_session(session) -> tuple[str, list[dict[str, Any]]]:
    """从 curl_cffi/requests session 提取 ST 与 cookies 列表。"""
    st = ""
    cookies: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    exact_tokens: dict[str, str] = {}
    chunked_tokens: dict[str, dict[int, str]] = {}
    jar = getattr(session, "cookies", None)
    if jar is None:
        return "", []

    iterable: list[Any] = []
    for getter in (
        lambda: list(jar),
        lambda: list(getattr(jar, "jar", [])),
    ):
        try:
            iterable = getter()
            if iterable:
                break
        except Exception:
            continue
    if not iterable:
        try:
            raw = jar.get_dict() if hasattr(jar, "get_dict") else {}
            for name, val in (raw or {}).items():
                iterable.append(
                    type("C", (), {"name": name, "value": val, "domain": "chatgpt.com", "path": "/"})()
                )
        except Exception:
            pass

    for c in iterable:
        try:
            if isinstance(c, (tuple, list)) and len(c) >= 2:
                name, value = str(c[0] or ""), str(c[1] or "")
                domain, path = "chatgpt.com", "/"
            else:
                name = str(getattr(c, "name", "") or "")
                value = str(getattr(c, "value", "") or "")
                domain = str(getattr(c, "domain", "") or "chatgpt.com")
                path = str(getattr(c, "path", "/") or "/")
            if not name or not value:
                continue
            key = (name, domain)
            if key in seen:
                continue
            seen.add(key)
            cookies.append(
                {
                    "name": name,
                    "value": value,
                    "domain": domain.lstrip(".") if domain else "chatgpt.com",
                    "path": path or "/",
                }
            )
            low = name.lower()
            for base in SESSION_COOKIE_BASES:
                if low == base:
                    exact_tokens[base] = value
                    break
                match = re.fullmatch(re.escape(base) + r"\.(\d+)", low)
                if match:
                    chunked_tokens.setdefault(base, {})[int(match.group(1))] = value
                    break
        except Exception:
            continue
    for base in SESSION_COOKIE_BASES:
        if exact_tokens.get(base):
            st = exact_tokens[base]
            break
        chunks = chunked_tokens.get(base) or {}
        if chunks:
            st = "".join(chunks[index] for index in sorted(chunks))
            break
    return st, cookies


def login_get_st(
    email: str,
    *,
    mail_url: str = "",
    password: str = "",
    proxy: str = "",
    log: Callable[[str], None] | None = None,
    sid_rotates: int | None = None,
) -> dict[str, Any]:
    """登录 ChatGPT Web，返回 {ok, st, access_token, chatgpt_account_id, cookies, error}。

    参考 k12 ``phase_login_only`` → ``login_member`` → ``chatgpt_web_login``。
    个人 session（account_id=""），不进 workspace。
    遇 403 / CF / authorize stuck 时换 711 sid 重试。
    """
    out: dict[str, Any] = {
        "ok": False,
        "st": "",
        "access_token": "",
        "chatgpt_account_id": "",
        "cookies": [],
        "cookies_json": "",
        "error": "",
        "elapsed_s": 0.0,
        "sid_rotates": 0,
    }
    lg = _log_fn(log)
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        out["error"] = "invalid email"
        return out
    mail_url = (mail_url or "").strip()
    if not mail_url and not (password or "").strip():
        out["error"] = "need mail_url (OTP) or password"
        return out

    if sid_rotates is None:
        try:
            sid_rotates = int(os.environ.get("PAY153_SID_ROTATES") or "3")
        except ValueError:
            sid_rotates = 3
    sid_rotates = max(0, min(int(sid_rotates), 8))

    t0 = time.time()
    # OTP / login 环境：iCloud HTTP 直连；优先 email OTP
    os.environ.setdefault("TOKENREFRESH_FAST_WEB_LOGIN", "1")
    os.environ.setdefault("TOKENREFRESH_EMAIL_POLL_SECONDS", "45")
    os.environ.setdefault("TOKENREFRESH_EMAIL_POLL_INTERVAL", "0.5")
    os.environ.setdefault("TOKENREFRESH_SESSION_FALLBACK", "1")
    # 有 mail_url 时不要强制密码
    if mail_url:
        os.environ.pop("TOKENREFRESH_PREFER_PASSWORD", None)

    try:
        from tokenrefresh.session import TokenRefresher
        from tokenrefresh.web import chatgpt_web_login
    except Exception as exc:
        out["error"] = f"tokenrefresh import failed: {exc}"
        lg(out["error"])
        return out

    proxy_url = (proxy or "").strip()
    # normalize 711 raw → socks5h
    if proxy_url and "://" not in proxy_url:
        parts = proxy_url.split(":")
        if len(parts) >= 4:
            host, port, user, pw = parts[0], parts[1], parts[2], ":".join(parts[3:])
            proxy_url = f"socks5h://{user}:{pw}@{host}:{port}"
        elif len(parts) == 2:
            proxy_url = f"socks5h://{parts[0]}:{parts[1]}"
    if not proxy_url:
        proxy_url = rotate_proxy_sid(_DEFAULT_711)

    last: dict[str, Any] = out
    for attempt in range(sid_rotates + 1):
        if attempt:
            proxy_url = rotate_proxy_sid(proxy_url)
            out["sid_rotates"] = attempt
            lg(f"403/soft → rotate sid attempt={attempt}/{sid_rotates}")
        last = _login_get_st_once(
            email,
            mail_url=mail_url,
            password=password,
            proxy_url=proxy_url,
            TokenRefresher=TokenRefresher,
            chatgpt_web_login=chatgpt_web_login,
            lg=lg,
            t0=t0,
        )
        last["sid_rotates"] = attempt
        if last.get("ok"):
            return last
        if not _should_rotate_sid(str(last.get("error") or "")):
            return last
        lg(f"will rotate sid after: {str(last.get('error') or '')[:160]}")
    return last


def _login_get_st_once(
    email: str,
    *,
    mail_url: str,
    password: str,
    proxy_url: str,
    TokenRefresher: Any,
    chatgpt_web_login: Any,
    lg: Callable[[str], None],
    t0: float,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "ok": False,
        "st": "",
        "access_token": "",
        "chatgpt_account_id": "",
        "cookies": [],
        "cookies_json": "",
        "error": "",
        "elapsed_s": 0.0,
        "sid_rotates": 0,
    }
    refresher = None
    try:
        lg(
            f"login start email={email} mail_url={'yes' if mail_url else 'no'} "
            f"proxy={proxy_url.split('@')[-1] if '@' in proxy_url else (proxy_url[-48:] if proxy_url else 'direct')}"
        )
        refresher = TokenRefresher(
            proxy_url=proxy_url,
            fingerprint_seed=f"{email}|{uuid.uuid4().hex[:8]}",
            log_fn=lambda m: lg(str(m)[:200]),
            locale="auto",
        )
        try:
            from tokenrefresh.client_identity import bind_session_on_refresher

            bind_session_on_refresher(refresher, rotate=True)
        except Exception:
            pass
        chatgpt_web_login(
            refresher,
            email=email,
            password=password or "",
            mail_url=mail_url,
            account_id="",  # personal free session
            fast=True,
        )
        # access token
        at = ""
        for attr in ("web_access_token", "access_token"):
            at = str(getattr(refresher, attr, "") or "")
            if at:
                break
        if not at:
            try:
                from gmail_k12_export import current_access_token  # type: ignore

                at = current_access_token(refresher) or ""
            except Exception:
                pass
        st, cookies = extract_st_from_session(refresher.session)
        api_st, api_at, api_cookies, session_http = fetch_st_from_auth_session(refresher, lg)
        if api_st:
            st = api_st
        if api_at and not at:
            at = api_at
        if api_cookies:
            cookies = api_cookies
        if not st:
            st, cookies = extract_st_from_session(refresher.session)
        aid = ""
        if at and at.count(".") >= 2:
            try:
                import base64

                seg = at.split(".")[1]
                seg += "=" * ((4 - len(seg) % 4) % 4)
                claims = json.loads(base64.urlsafe_b64decode(seg))
                auth = claims.get("https://api.openai.com/auth") or {}
                aid = str(auth.get("chatgpt_account_id") or "")
            except Exception:
                pass

        out["access_token"] = at
        out["chatgpt_account_id"] = aid
        out["st"] = st
        out["cookies"] = cookies
        out["cookies_json"] = json.dumps(cookies, ensure_ascii=False)
        out["elapsed_s"] = round(time.time() - t0, 2)
        if at and not st and str(session_http) == "403":
            out["error"] = "auth/session HTTP=403 after login (rotate sid)"
            lg(out["error"])
            return out
        if at and not st:
            out["error"] = "at_ok_no_st"
            lg(out["error"] + f" session_http={session_http} cookies={len(cookies)} names={[c.get('name') for c in cookies[:12]]}")
            out["ok"] = True
            return out
        if not st:
            out["error"] = "login ok but no session_token from /api/auth/session"
            lg(out["error"] + f" cookies={len(cookies)} at_len={len(at)} session_http={session_http}")
            return out
        out["ok"] = True
        lg(
            f"OK st_len={len(st)} at_len={len(at)} cookies={len(cookies)} "
            f"acct={aid[:12] if aid else '-'} t={out['elapsed_s']}s"
        )
        return out
    except Exception as exc:
        out["error"] = str(exc)[:500]
        out["elapsed_s"] = round(time.time() - t0, 2)
        lg(f"FAIL {out['error'][:200]}")
        return out
    finally:
        if refresher is not None:
            try:
                refresher.close()
            except Exception:
                pass


def load_st_from_account_row(row: dict[str, Any]) -> dict[str, Any]:
    """从 accounts 行 / meta_json 恢复已缓存的 ST。"""
    meta: dict[str, Any] = {}
    raw = row.get("meta_json") or ""
    if isinstance(raw, dict):
        meta = raw
    elif raw:
        try:
            meta = json.loads(raw)
        except Exception:
            meta = {}
    st = str(meta.get("session_token") or meta.get("st") or "").strip()
    cookies_json = str(meta.get("cookies_json") or "").strip()
    if not cookies_json and meta.get("cookies"):
        try:
            cookies_json = json.dumps(meta.get("cookies"), ensure_ascii=False)
        except Exception:
            cookies_json = ""
    aid = str(
        meta.get("chatgpt_account_id")
        or meta.get("openai_chatgpt_account_id")
        or row.get("account_id")
        or ""
    ).strip()
    return {
        "st": st,
        "cookies_json": cookies_json,
        "chatgpt_account_id": aid,
        "access_token": str(row.get("access_token") or meta.get("openai_access_token") or ""),
        "email": str(row.get("email") or ""),
        "mail_url": str(row.get("mail_url") or ""),
    }


def persist_st_to_db(db_account_id: Any, material: dict[str, Any], db_path: str = "") -> None:
    """把 ST 写入 accounts.meta_json（不落盘明文日志）。"""
    if not db_account_id:
        return
    st = str(material.get("st") or "").strip()
    new_at = str(material.get("access_token") or "").strip()
    if not st and not (new_at and len(new_at) > 20):
        return
    import sqlite3

    path = db_path or str(ROOT / "data" / "accounts.db")
    con = sqlite3.connect(path, timeout=30)
    try:
        row = con.execute(
            "SELECT meta_json, access_token FROM accounts WHERE id=?",
            (int(db_account_id),),
        ).fetchone()
        if not row:
            return
        try:
            meta = json.loads(row[0] or "{}")
        except Exception:
            meta = {}
        if not isinstance(meta, dict):
            meta = {}
        if st:
            meta["session_token"] = st
            meta["st_updated_at"] = time.time()
        if material.get("cookies_json"):
            meta["cookies_json"] = material["cookies_json"]
        if material.get("chatgpt_account_id"):
            meta["chatgpt_account_id"] = material["chatgpt_account_id"]
        if new_at and len(new_at) > 20:
            meta["at_updated_at"] = time.time()
        if new_at and len(new_at) > 20:
            con.execute(
                "UPDATE accounts SET meta_json=?, access_token=?, updated_at=? WHERE id=?",
                (json.dumps(meta, ensure_ascii=False), new_at, time.time(), int(db_account_id)),
            )
        else:
            con.execute(
                "UPDATE accounts SET meta_json=?, updated_at=? WHERE id=?",
                (json.dumps(meta, ensure_ascii=False), time.time(), int(db_account_id)),
            )
        con.commit()
    finally:
        con.close()


def ensure_account_st(
    *,
    email: str,
    mail_url: str = "",
    password: str = "",
    proxy: str = "",
    db_account_id: Any = None,
    force_login: bool = False,
    row: dict[str, Any] | None = None,
    log: Callable[[str], None] | None = None,
    sid_rotates: int | None = None,
) -> dict[str, Any]:
    """有缓存 ST 则复用，否则登录获取并可选写库。"""
    lg = _log_fn(log)
    cached = load_st_from_account_row(row or {})
    if not force_login and cached.get("st"):
        lg(f"reuse cached ST len={len(cached['st'])}")
        return {**cached, "ok": True, "source": "cache"}
    res = login_get_st(
        email,
        mail_url=mail_url or cached.get("mail_url") or "",
        password=password,
        proxy=proxy,
        log=log,
        sid_rotates=sid_rotates,
    )
    if res.get("ok") and db_account_id:
        try:
            persist_st_to_db(db_account_id, res)
            lg("ST persisted to accounts.meta_json")
        except Exception as exc:
            lg(f"persist ST warn: {exc}")
    res["source"] = "login"
    return res
