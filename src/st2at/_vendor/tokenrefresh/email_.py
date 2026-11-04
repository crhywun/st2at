"""Email OTP 轮询 — Hotmail API / Microsoft OAuth(RT) / mail_url 直达"""
import json, os, re, time
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

import requests

from . import constants as C
from .utils import log_line

# 货源自带 client_id + refresh_token → 本地 Graph 读信（无需自建 Hotmail 邮件池）
# sticky_region: Outlook/Hotmail 必须固定国家刷 RT / Graph，避免全球乱窜封令牌
_MS_OAUTH_CREDS: dict[str, dict[str, str]] = {}
_MS_OAUTH_ACCESS_CACHE: dict[str, dict[str, Any]] = {}  # email -> {access_token, exp, refresh_token}
_MS_STICKY_REGION: dict[str, str] = {}  # email/base -> ISO2
_REGION_PROXY_LINES: dict[str, list[str]] = {}  # region -> proxy lines cache
DEFAULT_MS_CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"

# ---------------------------------------------------------------------------
# 邮箱 OTP 出口策略
#
# - iCloud HTTP show/：默认直连（无本地 MS RT，不绑国家）
# - Outlook/Hotmail Graph RT：与 **OpenAI 注册代理同国**（禁止按邮箱 hash 随机多国）
#   register 侧会在拿到注册 proxy region 后 set_ms_oauth_sticky_region(email, region)
#   未设置时回落 MAIL_OTP_DEFAULT_REGION（默认 JP），不再 JP/US/TW… 乱跳
# - 注册代理与读信代理仍是 **两条连接**，但 **国家必须一致**
# - MAIL_OTP_USE_PROXY=1：旧 proxy_country+cli 全量代理（非 Graph sticky）
# ---------------------------------------------------------------------------
_DIRECT_PROXIES = {"http": None, "https": None}
_MAIL_OTP_PROXY_URLS: list[str] | None = None
_MAIL_OTP_PROXY_FILE_LOADED: str = ""
_MAIL_OTP_LOGGED_MODE: bool = False
_MAIL_OTP_MODE_LABEL: str = ""


def _mail_otp_use_proxy() -> bool:
    """Legacy global proxy opt-in (proxy_country). Graph sticky is separate."""
    return (os.environ.get("MAIL_OTP_USE_PROXY") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def set_ms_oauth_sticky_region(email: str, region: str) -> None:
    """Pin Outlook/Hotmail Graph+RT traffic to one ISO2 country for mailbox life."""
    em = str(email or "").strip().lower()
    reg = str(region or "").strip().upper()
    if not em or "@" not in em or len(reg) != 2:
        return
    _MS_STICKY_REGION[em] = reg
    base = _microsoft_base_email(em)
    if base:
        _MS_STICKY_REGION[base] = reg
    # also stamp onto creds if present
    for key in (em, base):
        if key and key in _MS_OAUTH_CREDS:
            _MS_OAUTH_CREDS[key]["sticky_region"] = reg


def get_ms_oauth_sticky_region(email: str) -> str:
    em = str(email or "").strip().lower()
    if not em:
        return ""
    if em in _MS_STICKY_REGION:
        return _MS_STICKY_REGION[em]
    base = _microsoft_base_email(em)
    if base and base in _MS_STICKY_REGION:
        return _MS_STICKY_REGION[base]
    creds = get_ms_oauth_credentials(em) if em else None
    if creds:
        return str(creds.get("sticky_region") or "").strip().upper()
    return ""


def _regions_dir_candidates() -> list:
    from pathlib import Path

    here = Path(__file__).resolve()
    repo = here.parents[2] if len(here.parents) > 2 else here.parents[0]
    return [
        Path(os.environ.get("MAIL_OTP_REGIONS_DIR") or ""),
        repo.parent / "cliproxy" / "regions",
        repo / "cliproxy" / "regions",
        Path(r"C:\Users\Administrator\Desktop\GPT项目\cliproxy\regions"),
        Path.cwd() / "cliproxy" / "regions",
    ]


def _proxy_line_to_url(line: str) -> str:
    s = (line or "").strip()
    if not s or s.startswith("#"):
        return ""
    low = s.lower()
    if low.startswith("socks5h://") or low.startswith("http://") or low.startswith("https://"):
        return s
    if low.startswith("socks5://"):
        return "socks5h://" + s.split("://", 1)[1]
    parts = s.split(":", 3)
    if len(parts) == 4:
        host, port, user, pw = parts
        return f"socks5h://{quote(user, safe='')}:{quote(pw, safe='')}@{host}:{port}"
    return ""


def _load_region_proxy_lines(region: str) -> list[str]:
    from pathlib import Path

    reg = (region or "").strip().upper()
    if not reg:
        return []
    if reg in _REGION_PROXY_LINES:
        return _REGION_PROXY_LINES[reg]
    lines: list[str] = []
    for d in _regions_dir_candidates():
        if not d or not Path(d).is_dir():
            continue
        for name in (f"{reg}.txt", f"{reg.lower()}.txt"):
            p = Path(d) / name
            if not p.is_file():
                continue
            for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
                u = _proxy_line_to_url(ln)
                if u:
                    lines.append(u)
            if lines:
                break
        if lines:
            break
    _REGION_PROXY_LINES[reg] = lines
    return lines


def _default_mail_region() -> str:
    """Fallback when register has not pinned mail sticky yet (must match reg default)."""
    reg = (os.environ.get("MAIL_OTP_DEFAULT_REGION") or "JP").strip().upper()
    return reg if len(reg) == 2 else "JP"


def _sticky_proxy_for_ms_email(email: str) -> str:
    """Residential proxy for Graph RT — **same country as OpenAI register**.

    Country source (in order):
      1) set_ms_oauth_sticky_region / creds sticky (register pins this to proxy region)
      2) MAIL_OTP_DEFAULT_REGION (default JP) — **no multi-country hash**
    """
    em = str(email or "").strip().lower()
    reg = get_ms_oauth_sticky_region(em)
    if not reg and _is_microsoft_email(em):
        # Do NOT hash email → random JP/US/TW/… — that desyncs from register country.
        reg = _default_mail_region()
        set_ms_oauth_sticky_region(em, reg)
    if not reg:
        return ""
    urls = _load_region_proxy_lines(reg)
    if not urls:
        return ""
    # stable pick per email so RT always same exit sid family within that country
    import hashlib

    h = int(hashlib.sha256(em.encode("utf-8")).hexdigest()[:8], 16)
    return urls[h % len(urls)]


def _load_mail_otp_proxy_urls() -> list[str]:
    """兼容旧调用：默认空列表 = 直连。"""
    global _MAIL_OTP_PROXY_URLS, _MAIL_OTP_PROXY_FILE_LOADED
    if _MAIL_OTP_PROXY_URLS is not None:
        return _MAIL_OTP_PROXY_URLS
    _MAIL_OTP_PROXY_URLS = []
    _MAIL_OTP_PROXY_FILE_LOADED = (
        "proxy_country+cli" if _mail_otp_use_proxy() else "(direct)"
    )
    return _MAIL_OTP_PROXY_URLS


def _mail_otp_proxy_for_email(email: str = "") -> str:
    """Mail OTP / Graph proxy URL.

    Priority:
      1) MAIL_OTP_PROXY env (forced single URL)
      2) Outlook/Hotmail: **same country as register proxy** (ms-sticky) — default ON
         Disable: MAIL_OTP_MS_STICKY=0
      3) MAIL_OTP_USE_PROXY=1 + proxy_country/cli legacy
      4) direct (iCloud show/, tempmail, etc.)
    """
    global _MAIL_OTP_MODE_LABEL
    em = str(email or "").strip().lower() or "_"
    forced = (os.environ.get("MAIL_OTP_PROXY") or "").strip()
    if forced:
        _MAIL_OTP_MODE_LABEL = "MAIL_OTP_PROXY env"
        return forced

    # Outlook/Hotmail Graph RT: pin country (critical — token geo hopping bans)
    ms_sticky_off = (os.environ.get("MAIL_OTP_MS_STICKY") or "1").strip().lower() in (
        "0",
        "false",
        "no",
        "off",
    )
    if not ms_sticky_off and _is_microsoft_email(em):
        px = _sticky_proxy_for_ms_email(em)
        if px:
            reg = get_ms_oauth_sticky_region(em) or "?"
            _MAIL_OTP_MODE_LABEL = f"ms-sticky country={reg}"
            return px

    if not _mail_otp_use_proxy():
        return ""
    try:
        import sys
        from pathlib import Path

        here = Path(__file__).resolve()
        roots = [
            here.parents[2] if len(here.parents) > 2 else here.parents[0],
            here.parents[1] / "chatgpt-k12-pc2-zubak",
            Path.cwd(),
        ]
        for root in roots:
            try:
                if (root / "proxy_country.py").is_file():
                    s = str(root)
                    if s not in sys.path:
                        sys.path.insert(0, s)
                    from proxy_country import get_cli_proxy_for_email

                    px = (get_cli_proxy_for_email(em, assign_if_missing=True) or "").strip()
                    if px:
                        try:
                            from proxy_country import get_proxy_country

                            cc = get_proxy_country(em, assign_if_missing=False) or "?"
                        except Exception:
                            cc = "?"
                        _MAIL_OTP_MODE_LABEL = f"cli country={cc}"
                        return px
            except Exception:
                continue
    except Exception:
        pass
    return ""


def _mail_exit_label(proxy_url: str) -> str:
    if not proxy_url:
        return "DIRECT"
    # socks5h://user:pass@host:port → host:port
    try:
        if "@" in proxy_url:
            return proxy_url.rsplit("@", 1)[-1]
        return proxy_url.split("://", 1)[-1][:60]
    except Exception:
        return "PROXY"


def _requests_mail(method: str, url: str, email: str = "", **kwargs):
    """邮箱 OAuth/Graph/读信 HTTP。

    默认本机直连（trust_env=False，不继承 HTTP_PROXY）。
    不使用 ChatGPT 注册代理。仅 MAIL_OTP_USE_PROXY=1 时才挂代理。
    """
    global _MAIL_OTP_LOGGED_MODE
    kwargs = dict(kwargs)
    proxy_url = _mail_otp_proxy_for_email(email)
    # 默认短超时：单次 Graph 卡住别吃满 OTP 窗口（可用 MAIL_OTP_HTTP_TIMEOUT 覆盖）
    try:
        _to = float(os.environ.get("MAIL_OTP_HTTP_TIMEOUT") or "12")
    except Exception:
        _to = 12.0
    kwargs.setdefault("timeout", max(4.0, min(_to, 30.0)))
    sess = requests.Session()
    sess.trust_env = False  # never inherit env HTTP(S)_PROXY
    if proxy_url:
        sess.proxies = {"http": proxy_url, "https": proxy_url}
        kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}
    else:
        sess.proxies.clear()
        kwargs["proxies"] = _DIRECT_PROXIES
    if not _MAIL_OTP_LOGGED_MODE:
        _MAIL_OTP_LOGGED_MODE = True
        mode = _MAIL_OTP_MODE_LABEL or (
            "DIRECT"
            if not proxy_url
            else f"cli sticky exit={_mail_exit_label(proxy_url)}"
        )
        log_line(
            f"MAIL OTP exit mode: {mode} "
            f"http_timeout={kwargs.get('timeout')} "
            f"(always separate from reg proxy; default=direct)"
        )
    try:
        return sess.request(method.upper(), url, **kwargs)
    finally:
        sess.close()


# 兼容旧名
def _requests_direct(method: str, url: str, email: str = "", **kwargs):
    return _requests_mail(method, url, email=email, **kwargs)


_MS_TOKEN_URLS = (
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    "https://login.live.com/oauth20_token.srf",
)
# 刷新时：先不传 scope（货源 RT 通常已绑定 outlook.office.com Mail.ReadWrite）
_MS_SCOPES = (
    "",  # omit scope — 货源 RT 标准刷新方式
    "https://outlook.office.com/Mail.ReadWrite offline_access openid profile",
    "https://outlook.office.com/Mail.Read offline_access openid profile",
    "https://graph.microsoft.com/Mail.Read offline_access openid profile",
)


def register_ms_oauth_credentials(
    email: str,
    refresh_token: str,
    client_id: str = "",
    sticky_region: str = "",
) -> None:
    """注册某邮箱的微软 OAuth 读信凭证（进程内）。

    sticky_region: Outlook/Hotmail 刷 RT / Graph 固定国家（与注册 sticky 一致）。
    """
    em = str(email or "").strip().lower()
    rt = str(refresh_token or "").strip()
    cid = str(client_id or "").strip() or DEFAULT_MS_CLIENT_ID
    reg = str(sticky_region or "").strip().upper()
    if not em or "@" not in em or not rt:
        return
    prev = _MS_OAUTH_CREDS.get(em) or {}
    if not reg:
        reg = str(prev.get("sticky_region") or "").strip().upper()
    entry = {"refresh_token": rt, "client_id": cid, "sticky_region": reg}
    _MS_OAUTH_CREDS[em] = entry
    base = _microsoft_base_email(em)
    if base and base != em:
        base_prev = _MS_OAUTH_CREDS.get(base) or {}
        _MS_OAUTH_CREDS.setdefault(
            base,
            {
                "refresh_token": rt,
                "client_id": cid,
                "sticky_region": reg
                or str(base_prev.get("sticky_region") or "").strip().upper(),
            },
        )
    if reg:
        set_ms_oauth_sticky_region(em, reg)


def has_ms_oauth_credentials(email: str) -> bool:
    em = str(email or "").strip().lower()
    if not em:
        return False
    if em in _MS_OAUTH_CREDS:
        return True
    base = _microsoft_base_email(em)
    return bool(base and base in _MS_OAUTH_CREDS)


def get_ms_oauth_credentials(email: str) -> dict[str, str] | None:
    em = str(email or "").strip().lower()
    if em in _MS_OAUTH_CREDS:
        return dict(_MS_OAUTH_CREDS[em])
    base = _microsoft_base_email(em)
    if base in _MS_OAUTH_CREDS:
        return dict(_MS_OAUTH_CREDS[base])
    return None


def _ms_refresh_access_token(email: str) -> str:
    """用 refresh_token 换 Graph access_token。"""
    creds = get_ms_oauth_credentials(email)
    if not creds:
        return ""
    em = str(email or "").strip().lower()
    cache = _MS_OAUTH_ACCESS_CACHE.get(em) or _MS_OAUTH_ACCESS_CACHE.get(
        _microsoft_base_email(em)
    )
    if cache:
        exp = float(cache.get("exp") or 0)
        at = str(cache.get("access_token") or "")
        if at and exp > time.time() + 60:
            return at

    client_id = creds.get("client_id") or DEFAULT_MS_CLIENT_ID
    refresh_token = creds.get("refresh_token") or ""
    if not refresh_token:
        return ""

    last_err = ""
    for token_url in _MS_TOKEN_URLS:
        for scope in _MS_SCOPES:
            data = {
                "client_id": client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }
            if scope:
                data["scope"] = scope
            try:
                # 邮箱专用出口刷新 RT（默认 US-30 池 sticky；勿走注册代理）
                r = _requests_mail(
                    "POST",
                    token_url,
                    email=em,
                    data=data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": getattr(C, "USER_AGENT", "tokenrefresh/1.0"),
                    },
                    timeout=25,
                    verify=False,
                )
                if r.status_code != 200:
                    last_err = f"HTTP {r.status_code} {(r.text or '')[:160]}"
                    continue
                payload = r.json() if r.text else {}
                at = str(payload.get("access_token") or "").strip()
                if not at:
                    last_err = "no access_token"
                    continue
                new_rt = str(payload.get("refresh_token") or "").strip()
                if new_rt:
                    # 刷新后的 RT 写回，避免下次失效
                    register_ms_oauth_credentials(em, new_rt, client_id)
                    refresh_token = new_rt
                expires_in = int(payload.get("expires_in") or 3600)
                entry = {
                    "access_token": at,
                    "exp": time.time() + max(300, expires_in),
                    "refresh_token": refresh_token,
                }
                _MS_OAUTH_ACCESS_CACHE[em] = entry
                base = _microsoft_base_email(em)
                if base:
                    _MS_OAUTH_ACCESS_CACHE[base] = entry
                scope_note = scope.split()[0] if scope else "default-scopes"
                px = _mail_otp_proxy_for_email(em)
                log_line(
                    f"MS OAuth token OK ({em}) via {token_url.split('/')[2]} "
                    f"{scope_note} expires_in={expires_in} exit={_mail_exit_label(px)}"
                )
                return at
            except Exception as e:
                last_err = str(e)[:160]
                continue
    log_line(f"MS OAuth token fail ({em}): {last_err}")
    return ""


def _decode_mail_body(raw: str) -> str:
    """Quoted-printable + soft-break cleanup for MIME bodies."""
    s = str(raw or "")
    if not s:
        return ""
    s = re.sub(r"=\r?\n", "", s)
    try:
        import quopri

        s = quopri.decodestring(s.encode("latin1", errors="ignore")).decode(
            "utf-8", errors="ignore"
        )
    except Exception:
        pass
    return s


def _otp_noise_codes(email: str = "", text: str = "") -> set[str]:
    """Reject domain digits (331023.xyz), CSS colors (#202123), tracking noise."""
    bad: set[str] = {"202123", "353740", "000000", "111111", "123456"}
    em = (email or "").strip().lower()
    if "@" in em:
        local, dom = em.split("@", 1)
        for part in re.findall(r"\d+", local + "@" + dom):
            if len(part) == 6:
                bad.add(part)
            elif len(part) > 6:
                for i in range(0, len(part) - 5):
                    bad.add(part[i : i + 6])
    for m in re.finditer(r"#([0-9a-fA-F]{6})\b", text or ""):
        h = m.group(1)
        if h.isdigit():
            bad.add(h)
    return bad


def _extract_otp_code(text: str, email: str = "") -> str:
    """Extract OpenAI/ChatGPT email OTP; avoid domain/CSS/header false 6-digits."""
    raw = _decode_mail_body(str(text or ""))
    if not raw.strip():
        return ""
    noise = _otp_noise_codes(email, raw)
    local = (email or "").split("@", 1)[0].lower()

    # 1) HTML template: code sits alone between MSO comments / tags
    for pat in (
        r"endif\s*\]\s*-->\s*(\d{6})\s*<!--",
        r">\s*(\d{6})\s*<",
        r"(?:temporary|verification)\s+ChatGPT\s+verification\s+code[^\d]{0,2000}(\d{6})",
        r"(?:ChatGPT|OpenAI|verification code|one-time|login code|验证码)[^\d]{0,80}(\d{6})",
        r"(\d{6})[^\d]{0,40}(?:is your|验证码)",
    ):
        m = re.search(pat, raw, flags=re.I | re.S)
        if not m:
            continue
        code = m.group(1)
        if code and code not in local and code not in noise:
            return code

    plain = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", raw)
    plain = re.sub(r"(?is)<[^>]+>", " ", plain)
    plain = re.sub(r"\s+", " ", plain)
    for pat in (
        r"(?:verification code|one[\s-]?time code|login code)[:\s]+(\d{6})",
        r"(?:code is|code:)\s*(\d{6})",
        r"验证码[^\d]{0,20}(\d{6})",
    ):
        m = re.search(pat, plain, flags=re.I)
        if not m:
            continue
        code = m.group(1)
        if code and code not in local and code not in noise:
            return code
    return ""


def _graph_list_messages(
    access_token: str, top: int = 12, email: str = ""
) -> list[dict]:
    """List recent inbox messages.

    货源 RT（client 9e5f94bc…）刷新后 audience 多为 outlook.office.com，
    应用 **Outlook REST v2**；Graph 会报 JWT not well formed。
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "User-Agent": getattr(C, "USER_AGENT", "tokenrefresh/1.0"),
    }
    n = max(5, min(25, top))
    urls = [
        # 货源主流：Outlook REST v2
        (
            "https://outlook.office.com/api/v2.0/me/mailfolders/inbox/messages"
            f"?$top={n}&$orderby=ReceivedDateTime desc"
            "&$select=Id,Subject,BodyPreview,Body,ReceivedDateTime,From"
        ),
        (
            "https://outlook.office.com/api/v2.0/me/messages"
            f"?$top={n}&$orderby=ReceivedDateTime desc"
            "&$select=Id,Subject,BodyPreview,Body,ReceivedDateTime,From"
        ),
        # 少数 RT 可走 Graph
        (
            "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
            f"?$top={n}&$orderby=receivedDateTime desc"
            "&$select=id,subject,bodyPreview,body,receivedDateTime,from"
        ),
        (
            "https://graph.microsoft.com/v1.0/me/messages"
            f"?$top={n}&$orderby=receivedDateTime desc"
            "&$select=id,subject,bodyPreview,body,receivedDateTime,from"
        ),
    ]
    last = ""
    for url in urls:
        try:
            # 读信走邮箱专用代理池（默认 US-30 sticky by email）
            r = _requests_mail(
                "GET",
                url,
                email=email,
                headers=headers,
                # timeout 走 _requests_mail 默认（短超时多轮询）
                verify=False,
            )
        except Exception as e:
            last = str(e)[:120]
            continue
        if r.status_code != 200:
            last = f"HTTP {r.status_code} {(r.text or '')[:120]}"
            continue
        data = r.json() if r.text else {}
        msgs = data.get("value") if isinstance(data, dict) else None
        if not isinstance(msgs, list):
            last = "no value list"
            continue
        # normalize Outlook REST keys → graph-like
        out: list[dict] = []
        for m in msgs:
            if not isinstance(m, dict):
                continue
            if "id" not in m and "Id" in m:
                m = {
                    "id": m.get("Id"),
                    "subject": m.get("Subject"),
                    "bodyPreview": m.get("BodyPreview"),
                    "body": m.get("Body")
                    if isinstance(m.get("Body"), dict)
                    else {"content": m.get("Body") or ""},
                    "receivedDateTime": m.get("ReceivedDateTime")
                    or m.get("receivedDateTime"),
                    "from": m.get("From") or m.get("from"),
                }
            out.append(m)
        # 200 + value 数组即成功（空收件箱也算 OK，勿再试 Graph 报 401）
        return out
    if last:
        log_line(f"Graph/Outlook mail list fail: {last}")
    return []


def _graph_message_text(msg: dict) -> str:
    parts = [
        str(msg.get("subject") or ""),
        str(msg.get("bodyPreview") or ""),
    ]
    body = msg.get("body")
    if isinstance(body, dict):
        parts.append(str(body.get("content") or ""))
    return "\n".join(parts)


def _graph_received_ts(msg: dict) -> float:
    s = str(msg.get("receivedDateTime") or "").strip()
    if not s:
        return 0.0
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        from datetime import datetime

        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return 0.0


def poll_ms_oauth_otp(
    email: str,
    not_before: float = 0,
    ignore_codes: set[str] | None = None,
    exclude_message_ids: set[str] | None = None,
) -> str | None:
    """用货源 client_id+refresh_token 经 Microsoft Graph 读收件箱取 OTP。"""
    if not has_ms_oauth_credentials(email):
        return None
    deadline = time.time() + max(5, int(getattr(C, "EMAIL_OTP_POLL_SECONDS", 45) or 45))
    round_i = 0
    token_fail = 0
    # 时间窗放宽：邮件 Delayed Delivery 常见 10–40s
    try:
        skew = float(
            os.environ.get("TOKENREFRESH_EMAIL_OTP_TIME_SKEW")
            or getattr(C, "EMAIL_OTP_TIME_SKEW", 45)
            or 45
        )
    except Exception:
        skew = 45.0
    try:
        top_n = int(os.environ.get("MAIL_OTP_GRAPH_TOP") or "25")
    except Exception:
        top_n = 25
    while time.time() < deadline:
        at = _ms_refresh_access_token(email)
        if not at:
            token_fail += 1
            if token_fail >= 2:
                log_line(f"MS OAuth OTP abort: cannot refresh token for {email}")
                return None
            time.sleep(0.6)
            continue
        token_fail = 0
        try:
            messages = _graph_list_messages(at, top=max(10, min(40, top_n)), email=email)
        except Exception as e:
            log_line(f"Graph list err: {e}")
            messages = []
        for msg in messages:
            msg_id = str(msg.get("id") or "").strip()
            if exclude_message_ids and msg_id and msg_id in exclude_message_ids:
                continue
            received_ts = _graph_received_ts(msg)
            if not_before and received_ts and received_ts < not_before - skew:
                continue
            if received_ts and time.time() - received_ts > float(
                getattr(C, "EMAIL_OTP_MAX_AGE_SECONDS", 300) or 300
            ):
                continue
            text = _graph_message_text(msg)
            # 优先 OpenAI 相关邮件
            low = text.lower()
            if not any(
                k in low
                for k in (
                    "openai",
                    "chatgpt",
                    "verification",
                    "verify",
                    "one-time",
                    "验证",
                    "login code",
                    "security code",
                )
            ):
                # 仍允许纯 6 位，但排在后面：先 continue 收集；简化：无关键词也解析
                pass
            code = _extract_otp_code(text, email=email)
            if not code:
                continue
            if ignore_codes and code in ignore_codes and not msg_id:
                continue
            px = _mail_otp_proxy_for_email(email)
            log_line(
                f"Email OTP via MS Graph OAuth ({email}): {code} "
                f"msg_id={(msg_id or '-')[:24]} received_at={msg.get('receivedDateTime') or '-'} "
                f"exit={_mail_exit_label(px)}"
            )
            return code
        if round_i < max(0, int(getattr(C, "EMAIL_OTP_POLL_FAST_ROUNDS", 12))):
            time.sleep(float(getattr(C, "EMAIL_OTP_POLL_FAST_INTERVAL", 0.2)))
        else:
            time.sleep(min(float(getattr(C, "EMAIL_OTP_POLL_INTERVAL", 0.5)), 0.5))
        round_i += 1
    return None


def ms_oauth_baseline_message_ids(email: str) -> set[str]:
    """Graph 基线 message id（排除旧信）。"""
    ids: set[str] = set()
    if not has_ms_oauth_credentials(email):
        return ids
    at = _ms_refresh_access_token(email)
    if not at:
        return ids
    try:
        for msg in _graph_list_messages(at, top=20, email=email):
            mid = str(msg.get("id") or "").strip()
            if mid:
                ids.add(mid)
    except Exception:
        pass
    return ids


def _expand_mail_url(mail_url: str, email: str) -> str:
    """Expand simple placeholders for shared inbox APIs.

    icloud-api.top 默认只回最新 1 封；OTP 有时被「新套餐」通知压住。
    自动补 n=10 拉多封卡片，便于按时间窗筛验证码信。
    """
    if not mail_url:
        return ""
    url = (
        mail_url.replace("{email}", email)
        .replace("{email_enc}", quote(email, safe=""))
        .replace("{email_url}", quote(email, safe=""))
    )
    low = url.lower()
    if "icloud-api.top" in low or "/show/" in low:
        if re.search(r"[?&]n=\d+", url):
            return url
        joiner = "&" if "?" in url else "?"
        url = f"{url}{joiner}n=10"
    return url


def _email_match_candidates(email: str) -> set[str]:
    """Return acceptable recipient strings for Gmail / iCloud aliases.

    实测 CSV 常为 user+tag@icloud.com 注册，但 icloud-api.top /show/ URL
    指向 user@icloud.com（无 +tag）。收件箱 HTML 里也只有基址邮箱。
    若只匹配完整 +tag，会在 poll 阶段永远 continue →
    「Could not get web email OTP」（邮箱其实有验证码）。
    """
    raw = str(email or "").strip().lower()
    if "@" not in raw:
        return {raw} if raw else set()

    local, domain = raw.rsplit("@", 1)
    candidates = {raw}
    if domain in ("gmail.com", "googlemail.com"):
        base_local = local.split("+", 1)[0].replace(".", "")
        for d in ("gmail.com", "googlemail.com"):
            candidates.add(f"{base_local}@{d}")
            if "+" in local:
                tag = local.split("+", 1)[1]
                candidates.add(f"{base_local}+{tag}@{d}")
    # iCloud / me.com / mac.com：+tag 仍进同一邮箱，show 页常用无 + 的基址
    if domain in ("icloud.com", "me.com", "mac.com"):
        base_local = local.split("+", 1)[0]
        candidates.add(f"{base_local}@{domain}")
        if "+" in local:
            candidates.add(raw)
    return {item for item in candidates if item}


def _mail_text_matches_email(text: str, email: str) -> bool:
    if os.environ.get("TOKENREFRESH_MAIL_REQUIRE_EMAIL_MATCH", "1").lower() in ("0", "false", "no"):
        return True
    normalized = str(text or "").lower()
    return any(candidate in normalized for candidate in _email_match_candidates(email))


def _smsbower_api_key(api_key: str = "") -> str:
    return str(api_key or C.SMSBOWER_MAIL_API_KEY or "").strip()


def _smsbower_api_base() -> str:
    return str(C.SMSBOWER_MAIL_API_BASE or "https://smsbower.page").rstrip("/")


def _parse_smsbower_mail_url(mail_url: str) -> dict:
    parsed = urlparse(str(mail_url or ""))
    if parsed.scheme != "smsbower":
        return {}

    from urllib.parse import parse_qs
    params = {k: v[-1] for k, v in parse_qs(parsed.query).items() if v}
    mail_id = (parsed.netloc or parsed.path or "").strip("/")
    return {
        "api_key": params.get("api_key") or params.get("key") or "",
        "mail_id": mail_id,
    }


def smsbower_request(action: str, params: dict | None = None,
                     api_key: str = "") -> dict | str | None:
    """Call SMSBower mail API."""
    key = _smsbower_api_key(api_key)
    if not key:
        return None

    query = {"api_key": key}
    query.update(params or {})
    try:
        r = _requests_mail(
            "get",
            f"{_smsbower_api_base()}/api/mail/{action}",
            email="",
            params=query,
            headers={"accept": "application/json,text/plain,*/*", "user-agent": C.USER_AGENT},
            timeout=30,
            verify=False,
        )
        text = (r.text or "").strip()
        try:
            return r.json()
        except Exception:
            return text
    except Exception:
        return None


def smsbower_get_activation(api_key: str = "", service: str = "",
                            domain: str = "", alias: str = "") -> dict:
    """Buy/request an SMSBower mailbox activation."""
    service = str(service or C.SMSBOWER_MAIL_SERVICE or "").strip()
    domain = str(domain or C.SMSBOWER_MAIL_DOMAIN or "gmail.com").strip()
    alias = str(alias if alias != "" else C.SMSBOWER_MAIL_ALIAS).strip()
    if not service:
        raise RuntimeError("SMSBower mail service is required; set SMSBOWER_MAIL_SERVICE")

    params = {"service": service, "domain": domain}
    if alias:
        params["alias"] = alias
    data = smsbower_request("getActivation", params, api_key=api_key)
    if not isinstance(data, dict):
        raise RuntimeError(f"SMSBower getActivation failed: {data}")

    mail_id = str(data.get("mailId") or data.get("id") or data.get("activationId") or "").strip()
    email = str(data.get("mail") or data.get("email") or data.get("address") or "").strip()
    status = str(data.get("status") or data.get("response") or "").strip()
    if status and status.upper() not in ("SUCCESS", "OK") and not mail_id:
        raise RuntimeError(f"SMSBower getActivation status={status}: {data}")
    if not mail_id or not email:
        raise RuntimeError(f"SMSBower getActivation missing mailId/mail: {data}")

    return {
        "email": email,
        "mail_id": mail_id,
        "mail_url": f"smsbower://{mail_id}",
        "raw": data,
    }


def smsbower_set_status(mail_id: str, status: str, api_key: str = "") -> dict | str | None:
    """Set SMSBower activation status. Status values are provider-defined."""
    if not mail_id:
        return None
    return smsbower_request("setStatus", {"id": mail_id, "status": status}, api_key=api_key)


def poll_smsbower_otp(mail_id: str, email: str = "", api_key: str = "",
                      ignore_codes: set[str] | None = None) -> str | None:
    """Poll SMSBower getCode until a 6-digit email OTP appears."""
    if not mail_id:
        return None

    deadline = time.time() + max(5, C.EMAIL_OTP_POLL_SECONDS)
    while time.time() < deadline:
        data = smsbower_request("getCode", {"mailId": mail_id}, api_key=api_key)
        text = json.dumps(data, ensure_ascii=False) if isinstance(data, dict) else str(data or "")

        if text:
            import re
            codes = re.findall(r'\b(\d{6})\b', text)
            for code in codes:
                if not ignore_codes or code not in ignore_codes:
                    log_line(f"Email OTP via SMSBower mail: {code}")
                    return code

        time.sleep(C.EMAIL_OTP_POLL_INTERVAL)
    return None


def _is_microsoft_email(email: str) -> bool:
    domain = str(email or "").rsplit("@", 1)[-1].lower() if "@" in str(email or "") else ""
    return domain in ("hotmail.com", "outlook.com", "live.com", "msn.com")


def _microsoft_base_email(email: str) -> str:
    raw = str(email or "").strip().lower()
    if "@" not in raw:
        return raw
    local, domain = raw.rsplit("@", 1)
    return f"{local.split('+', 1)[0]}@{domain}"


def _hotmail_lookup_emails(email: str) -> list[str]:
    """Plus 别名登录时 OTP 可能在母邮箱，按 alias → 母号 依次查。"""
    out: list[str] = []
    raw = str(email or "").strip().lower()
    if raw:
        out.append(raw)
    if _is_microsoft_email(raw):
        base = _microsoft_base_email(raw)
        if base and base not in out:
            out.append(base)
    return out


def _normalize_hotmail_mail(data: Any, target_email: str = "") -> dict[str, Any]:
    """归一化 outlook.aitokensale.com /api/mail 响应为统一 mail 结构。"""
    import re

    if not isinstance(data, dict):
        return {}

    messages = data.get("messages")
    if isinstance(messages, list) and messages:
        # 选「最新一封带 6 位 OTP 的信」：按 receivedAt，而不是列表顺序/验证码是否重复
        candidates: list[tuple[float, dict, str]] = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            code = str(msg.get("code") or msg.get("verification_code") or "").strip()
            # OpenAI email OTP is always 6 digits; reject truncated API fields
            if not re.fullmatch(r"\d{6}", code or ""):
                blob = " ".join(
                    str(msg.get(k) or "")
                    for k in ("preview", "subject", "from", "body", "code", "verification_code")
                )
                m = re.search(r"(?<!\d)(\d{6})(?!\d)", blob)
                code = m.group(1) if m else ""
            if not code:
                continue
            ts = 0.0
            rs = str(msg.get("receivedAt") or msg.get("received_at") or "").strip()
            if rs:
                try:
                    if rs.endswith("Z"):
                        rs = rs[:-1] + "+00:00"
                    from datetime import datetime

                    ts = datetime.fromisoformat(rs).timestamp()
                except Exception:
                    ts = 0.0
            candidates.append((ts, msg, code))
        if candidates:
            # 最新优先；无时间戳的放最后
            candidates.sort(key=lambda x: (x[0] > 0, x[0]), reverse=True)
            _, chosen, chosen_code = candidates[0]
        else:
            chosen = messages[0] if isinstance(messages[0], dict) else {}
            chosen_code = ""
        chosen = chosen or {}
        return {
            "message_id": str(chosen.get("id") or chosen.get("message_id") or "").strip(),
            "subject": str(chosen.get("subject") or "").strip(),
            "from": str(chosen.get("from") or "").strip(),
            "received_at": str(
                chosen.get("receivedAt") or chosen.get("received_at") or ""
            ).strip(),
            "preview": str(chosen.get("preview") or "").strip(),
            "verification_code": chosen_code,
            "email_account": target_email or str(data.get("email") or "").strip(),
        }

    # 兼容旧单条 mail 结构
    mail = data.get("mail") if isinstance(data.get("mail"), dict) else data
    if not isinstance(mail, dict):
        return {}
    code = str(mail.get("verification_code") or mail.get("code") or "").strip()
    if not re.fullmatch(r"\d{6}", code or ""):
        blob = " ".join(str(mail.get(k) or "") for k in ("preview", "subject", "body", "code", "verification_code"))
        m = re.search(r"(?<!\d)(\d{6})(?!\d)", blob)
        code = m.group(1) if m else ""
    return {
        "message_id": str(mail.get("message_id") or mail.get("id") or "").strip(),
        "subject": str(mail.get("subject") or "").strip(),
        "from": str(mail.get("from") or "").strip(),
        "received_at": str(mail.get("received_at") or mail.get("receivedAt") or "").strip(),
        "preview": str(mail.get("preview") or "").strip(),
        "verification_code": code,
        "email_account": target_email or str(mail.get("email_account") or data.get("email") or "").strip(),
    }


class HotmailAccountNotFound(RuntimeError):
    """Mail-pool backend has no such mailbox (import missing)."""


def _hotmail_api_fetch_mail(email: str) -> dict[str, Any] | None:
    """POST /api/mail 取件（与线上 outlook.aitokensale.com 一致）。"""
    if not C.HOTMAIL_API_BASE or not C.HOTMAIL_ADMIN_PASSWORD:
        return None
    url = f"{C.HOTMAIL_API_BASE.rstrip('/')}/api/mail"
    headers = {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "user-agent": "email-code-fetcher/1.0",
        "x-admin-password": C.HOTMAIL_ADMIN_PASSWORD,
    }
    try:
        r = _requests_mail(
            "POST",
            url,
            email=str(email or "").strip().lower(),
            headers=headers,
            json={"email": str(email or "").strip().lower()},
            timeout=12,
            verify=False,
        )
        if r.status_code == 404:
            # 未导入邮件池：不必空等满 OTP 窗口
            raise HotmailAccountNotFound(
                f"hotmail mail-pool account not found: {email}"
            )
        if r.status_code != 200:
            return None
        data = r.json()
        if isinstance(data, dict) and data.get("ok") is False:
            err = str(data.get("error") or "").lower()
            if "not found" in err or "no account" in err:
                raise HotmailAccountNotFound(
                    f"hotmail mail-pool account not found: {email}"
                )
        return _normalize_hotmail_mail(data, email)
    except HotmailAccountNotFound:
        raise
    except Exception:
        return None


def _remote_hotmail_api_allowed() -> bool:
    return (os.environ.get("MAIL_ALLOW_REMOTE_HOTMAIL_API") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def hotmail_baseline_message_ids(email: str) -> set[str]:
    """获取邮箱基线 message_id，用于排除旧邮件。

    默认只用货源 RT + Graph；远程邮件池需 MAIL_ALLOW_REMOTE_HOTMAIL_API=1。
    """
    ids: set[str] = set()
    if (
        _remote_hotmail_api_allowed()
        and C.HOTMAIL_API_BASE
        and C.HOTMAIL_ADMIN_PASSWORD
    ):
        for lookup in _hotmail_lookup_emails(email):
            try:
                mail = _hotmail_api_fetch_mail(lookup)
            except Exception:
                mail = None
            if not mail:
                continue
            msg_id = str(mail.get("message_id") or "").strip()
            if msg_id:
                ids.add(msg_id)
        if ids:
            return ids
    ids |= ms_oauth_baseline_message_ids(email)
    return ids


def poll_hotmail_otp(email: str, not_before: float = 0,
                      ignore_codes: set[str] | None = None,
                      exclude_message_ids: set[str] | None = None) -> str | None:
    """通过 Hotmail API 轮询邮箱验证码（POST /api/mail）。

    判定新信优先级（与 OpenAI「连点两次可能同一码、不同到达时间」一致）：
      1) message_id 不在 baseline/exclude 里
      2) received_at >= not_before（收件时间）
      3) 未超过 max_age
    验证码字符串是否与旧信相同 **不是** 拒绝理由：新邮件 + 同码仍可用。
    ignore_codes 仅在无 message_id 且无法区分信件时作兜底（SMSBower 兼容）。
    """
    if not _remote_hotmail_api_allowed():
        return None
    if not C.HOTMAIL_API_BASE or not C.HOTMAIL_ADMIN_PASSWORD:
        return None

    deadline = time.time() + max(5, C.EMAIL_OTP_POLL_SECONDS)
    lookups = _hotmail_lookup_emails(email)
    round_i = 0
    not_found_hits = 0
    while time.time() < deadline:
        for lookup in lookups:
            try:
                mail = _hotmail_api_fetch_mail(lookup)
            except HotmailAccountNotFound as e:
                not_found_hits += 1
                # 连续 2 次 404：账号未进池，立刻失败（省下最多 ~60s 空转）
                if not_found_hits >= 2:
                    log_line(f"Hotmail OTP abort (not in mail-pool): {e}")
                    return None
                continue
            if not mail:
                continue
            not_found_hits = 0

            msg_id = str(mail.get("message_id") or "").strip()
            received_str = str(mail.get("received_at") or "").strip()

            # ① 按邮件身份排除旧信（不是按验证码）
            if exclude_message_ids and msg_id and msg_id in exclude_message_ids:
                continue

            try:
                received_ts = 0.0
                if received_str:
                    rs = received_str
                    if rs.endswith("Z"):
                        rs = rs[:-1] + "+00:00"
                    from datetime import datetime
                    received_ts = datetime.fromisoformat(rs).timestamp()
            except Exception:
                received_ts = 0.0

            # ② 按收件时间：必须在本次申请附近之后
            if not_before and received_ts and received_ts < not_before - C.EMAIL_OTP_TIME_SKEW:
                continue

            if received_ts and time.time() - received_ts > C.EMAIL_OTP_MAX_AGE_SECONDS:
                continue

            code = str(mail.get("verification_code") or "").strip()
            if not code:
                import re
                preview = str(mail.get("preview") or mail.get("subject") or "")
                m = re.search(r"(?<!\d)(\d{6})(?!\d)", preview)
                if m:
                    code = m.group(1)

            # 拒绝邮箱本地部分里的数字（如 katherinerodriguez414399 → 414399 假码）
            local = (lookup or email or "").split("@", 1)[0].lower()
            if code and code in local:
                code = ""
            if not code:
                continue

            # ③ 有 message_id 的新信：同码也接受（连点两次发信常见同码不同到达时间）
            if msg_id:
                log_line(
                    f"Email OTP via Hotmail API ({lookup}): {code} "
                    f"msg_id={msg_id[:24]} received_at={received_str or '-'}"
                )
                return code

            # 无 message_id 时才用 ignore_codes 兜底（无法区分是否同一封）
            if ignore_codes and code in ignore_codes:
                continue
            log_line(f"Email OTP via Hotmail API ({lookup}): {code} (no msg_id)")
            return code

        # 前几轮用更短间隔，尽快吃到新邮件；之后放慢减轻 API 压力
        if round_i < max(0, int(getattr(C, "EMAIL_OTP_POLL_FAST_ROUNDS", 12))):
            time.sleep(float(getattr(C, "EMAIL_OTP_POLL_FAST_INTERVAL", 0.15)))
        else:
            time.sleep(min(C.EMAIL_OTP_POLL_INTERVAL, 0.35))
        round_i += 1

    return None


def _parse_tempmail_mail_url(mail_url: str) -> dict[str, str]:
    """tempmail://user@domain[?jwt=...&base=...]  → 自建域名收码."""
    from urllib.parse import parse_qs, unquote, urlparse

    u = str(mail_url or "").strip()
    if not u:
        return {}
    low = u.lower()
    if not (
        low.startswith("tempmail://")
        or low.startswith("tm3310://")
        or "mail.331023.xyz" in low
    ):
        return {}
    if low.startswith("http://") or low.startswith("https://"):
        # share URL with jwt in query — treat as admin poll by address if provided
        return {}
    parsed = urlparse(u if "://" in u else f"tempmail://{u}")
    # netloc or path may hold email
    host = (parsed.netloc or "").strip()
    path = (parsed.path or "").lstrip("/")
    address = ""
    if "@" in host:
        address = host
    elif "@" in path:
        address = path.split("?")[0]
    else:
        address = unquote(host or path)
    if "@" not in address:
        return {}
    qs = parse_qs(parsed.query or "")
    return {
        "address": address.strip().lower(),
        "jwt": (qs.get("jwt") or [""])[0],
        "base": (qs.get("base") or [""])[0],
    }


def poll_tempmail_otp(
    address: str,
    *,
    jwt: str = "",
    not_before: float = 0,
    ignore_codes: set[str] | None = None,
    exclude_message_ids: set[str] | None = None,
) -> str | None:
    """Poll self-hosted tempmail (mail.331023.xyz) for ChatGPT OTP."""
    import os
    import sys
    from pathlib import Path

    em = (address or "").strip().lower()
    if "@" not in em:
        return None

    # locate client: project root or vendor parent
    client_mod = None
    try:
        import temp_mail_api_client as client_mod  # type: ignore
    except Exception:
        here = Path(__file__).resolve()
        for p in (
            here.parents[2],  # chatgpt-k12-pc2-zubak
            here.parents[3] / "chatgpt-k12-pc2-zubak" if len(here.parents) > 3 else None,
            Path.cwd(),
        ):
            if p is None:
                continue
            if (p / "temp_mail_api_client.py").is_file():
                if str(p) not in sys.path:
                    sys.path.insert(0, str(p))
                try:
                    import temp_mail_api_client as client_mod  # type: ignore
                except Exception:
                    client_mod = None
                break
    if client_mod is None:
        log_line("tempmail client missing (temp_mail_api_client.py)")
        return None

    base = (
        os.environ.get("TEMPMAIL_BASE_URL")
        or getattr(client_mod, "DEFAULT_BASE_URL", "https://mail.331023.xyz")
    ).strip().rstrip("/")
    site = (
        os.environ.get("TEMPMAIL_SITE_PASSWORD")
        or getattr(client_mod, "DEFAULT_SITE_PASSWORD", "")
    )
    admin = (
        os.environ.get("TEMPMAIL_ADMIN_PASSWORD")
        or getattr(client_mod, "DEFAULT_ADMIN_PASSWORD", "")
    )
    client = client_mod.TempMailApiClient(
        base_url=base,
        site_password=site,
        admin_password=admin,
        address_jwt=jwt or "",
        timeout=25.0,
    )

    deadline = time.time() + max(5, int(getattr(C, "EMAIL_OTP_POLL_SECONDS", 90) or 90))
    exclude = set(exclude_message_ids or set())
    round_i = 0
    while time.time() < deadline:
        try:
            mails = []
            if admin:
                data = client.admin_read_mails(address=em, limit=15, offset=0)
                mails = list(data.get("results") or [])
            elif jwt:
                data = client.list_mails(jwt=jwt, limit=15, offset=0)
                mails = list(data.get("results") or [])
            else:
                log_line("tempmail: need admin password or jwt")
                return None
            for mail in mails:
                if not isinstance(mail, dict):
                    continue
                # hard filter: only this mailbox
                to_addr = str(
                    mail.get("address")
                    or mail.get("to")
                    or mail.get("recipient")
                    or ""
                ).lower()
                if to_addr and em not in to_addr and to_addr not in em:
                    # some APIs put full address in address field
                    if em.split("@")[0] not in to_addr:
                        continue
                mid = str(mail.get("id") or mail.get("mail_id") or "")
                if mid and mid in exclude:
                    continue
                subj = str(mail.get("subject") or "")
                raw = str(
                    mail.get("raw")
                    or mail.get("text")
                    or mail.get("preview")
                    or ""
                )
                blob = f"{subj}\n{raw}"
                # must look like OpenAI/ChatGPT mail — avoid random 6-digit noise
                low = blob.lower()
                if not any(
                    k in low
                    for k in (
                        "openai",
                        "chatgpt",
                        "verification code",
                        "one-time",
                        "login code",
                        "verify your",
                        "验证码",
                    )
                ):
                    continue
                code = _extract_otp_code(blob, email=em)
                if not code:
                    continue
                if ignore_codes and code in ignore_codes:
                    continue
                log_line(
                    f"Email OTP via tempmail ({em}): {code} msg_id={mid[:24] or '-'} "
                    f"subj={(subj or '')[:40]}"
                )
                return code
        except Exception as e:
            log_line(f"tempmail poll err: {e}")
        if round_i < max(0, int(getattr(C, "EMAIL_OTP_POLL_FAST_ROUNDS", 40))):
            time.sleep(float(getattr(C, "EMAIL_OTP_POLL_FAST_INTERVAL", 0.15)))
        else:
            time.sleep(min(float(getattr(C, "EMAIL_OTP_POLL_INTERVAL", 0.35)), 0.6))
        round_i += 1
    return None


def _icloudv2_https_url(mail_url: str) -> str:
    """Convert the credential-bearing internal scheme to its HTTPS endpoint."""
    parsed = urlparse(str(mail_url or "").strip())
    if parsed.scheme.lower() != "icloudv2":
        return ""
    query = parse_qs(parsed.query, keep_blank_values=True)
    tokens = query.get("token") or []
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path != "/api/v1/otp"
        or parsed.fragment
        or len(tokens) != 1
        or not str(tokens[0]).strip()
    ):
        raise ValueError("invalid icloudv2 mail URL")
    return parsed._replace(scheme="https").geturl()


def _icloudv2_timestamp(value: Any) -> float:
    raw = str(value or "").strip()
    if not raw:
        return 0.0
    try:
        from datetime import datetime

        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _select_icloudv2_otp(
    payload: Any,
    *,
    not_before: float = 0,
    ignore_codes: set[str] | None = None,
) -> str:
    """Select the newest strict six-digit OTP from one alias-scoped response."""
    if not isinstance(payload, list):
        return ""
    try:
        threshold = float(not_before or 0)
    except (TypeError, ValueError):
        threshold = 0.0
    if threshold > 0:
        threshold -= float(getattr(C, "EMAIL_OTP_TIME_SKEW", 30.0) or 30.0)
    ignored = {str(code) for code in (ignore_codes or set())}
    candidates: list[tuple[float, int, str]] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            continue
        code = str(item.get("otp") or "").strip()
        if len(code) != 6 or not code.isdigit() or code in ignored:
            continue
        received_at = _icloudv2_timestamp(item.get("time"))
        if threshold > 0 and (received_at <= 0 or received_at < threshold):
            continue
        candidates.append((received_at, -index, code))
    if not candidates:
        return ""
    candidates.sort(reverse=True)
    return candidates[0][2]


def poll_icloudv2_otp(
    mail_url: str,
    *,
    not_before: float = 0,
    ignore_codes: set[str] | None = None,
) -> str | None:
    """Poll one iCloud HME alias directly without exposing its URL in logs."""
    endpoint = _icloudv2_https_url(mail_url)
    if not endpoint:
        return None
    from curl_cffi import requests as curl_requests

    session = curl_requests.Session(impersonate="chrome")
    deadline = time.time() + max(5, C.EMAIL_OTP_POLL_SECONDS)
    last_error_log = 0.0
    try:
        while time.time() < deadline:
            try:
                response = session.get(
                    endpoint,
                    headers={"Accept": "application/json"},
                    timeout=20,
                )
                response.raise_for_status()
                code = _select_icloudv2_otp(
                    response.json(),
                    not_before=not_before,
                    ignore_codes=ignore_codes,
                )
                if code:
                    log_line("Email OTP via icloudv2")
                    return code
            except Exception as exc:
                now = time.time()
                if now - last_error_log >= 10:
                    log_line(f"icloudv2 poll err: {type(exc).__name__}")
                    last_error_log = now
            time.sleep(C.EMAIL_OTP_POLL_INTERVAL)
    finally:
        session.close()
    return None


def poll_email_direct(mail_url: str, email: str,
                       not_before: float = 0,
                       ignore_codes: set[str] | None = None,
                       exclude_message_ids: set[str] | None = None) -> str | None:
    """轮询邮箱验证码：货源 RT/Graph 优先 → 邮件池 API → SMSBower → HTTP mail_url。"""
    mail_url_l = str(mail_url or "").lower()

    if mail_url_l.startswith("icloudv2://"):
        return poll_icloudv2_otp(
            mail_url,
            not_before=not_before,
            ignore_codes=ignore_codes,
        )

    # 自建域名 tempmail（mail.331023.xyz）
    tm = _parse_tempmail_mail_url(mail_url)
    if tm:
        return poll_tempmail_otp(
            tm.get("address") or email,
            jwt=tm.get("jwt") or "",
            not_before=not_before,
            ignore_codes=ignore_codes,
            exclude_message_ids=exclude_message_ids,
        )
    # bare self-hosted domain emails with empty scheme + env configured
    if (
        email
        and "@" in email
        and not mail_url_l.startswith("msoauth")
        and not mail_url_l.startswith("smsbower")
        and not mail_url_l.startswith("hotmail")
        and (
            email.lower().endswith(".xyz")
            or email.lower().split("@")[-1]
            in (
                "aitokensale.com",
                "tokenfly.shop",
                "tokensale.shop",
                "token2ai.site",
            )
            or (os.environ.get("TEMPMAIL_FORCE") or "").strip() in ("1", "true", "yes")
        )
        and (os.environ.get("TEMPMAIL_ADMIN_PASSWORD") or "").strip()
    ):
        # only if TEMPMAIL_FORCE or known domains — use tempmail admin poll
        if (os.environ.get("TEMPMAIL_FORCE") or "").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        ) or mail_url_l.startswith("tempmail"):
            return poll_tempmail_otp(
                email,
                not_before=not_before,
                ignore_codes=ignore_codes,
                exclude_message_ids=exclude_message_ids,
            )

    # 货源 refresh_token：本地 Microsoft Graph（显式 msoauth:// 或已 register 凭证时优先，
    # 避免 HOTMAIL_API 已配置但账号未 import 时误走邮件池 abort）
    use_msoauth = (
        mail_url_l.startswith("msoauth://")
        or mail_url_l.startswith("graph://")
        or (
            _is_microsoft_email(email)
            and has_ms_oauth_credentials(email)
        )
    )
    if use_msoauth:
        return poll_ms_oauth_otp(
            email,
            not_before=not_before,
            ignore_codes=ignore_codes,
            exclude_message_ids=exclude_message_ids,
        )

    use_hotmail = (
        _remote_hotmail_api_allowed()
        and bool(C.HOTMAIL_API_BASE and C.HOTMAIL_ADMIN_PASSWORD)
        and (
            _is_microsoft_email(email)
            or "outlook.aitokensale.com" in mail_url_l
            or "your-hotmail-otp-api.example" in mail_url_l
            or mail_url_l.startswith("hotmail://")
        )
    )
    if use_hotmail:
        code = poll_hotmail_otp(
            email,
            not_before=not_before,
            ignore_codes=ignore_codes,
            exclude_message_ids=exclude_message_ids,
        )
        # 微软邮箱只走 API 一轮；失败后不要再扫 mail_url 把等待时间翻倍
        return code

    # 默认：微软邮箱必须本地 RT/Graph，禁止静默走远程池
    if _is_microsoft_email(email) and not has_ms_oauth_credentials(email):
        log_line(
            f"mail OTP skip: no local refresh_token for {email} "
            f"(remote hotmail API disabled; set MAIL_ALLOW_REMOTE_HOTMAIL_API=1 to enable)"
        )
        return None

    smsbower = _parse_smsbower_mail_url(mail_url)
    if smsbower:
        return poll_smsbower_otp(
            smsbower.get("mail_id", ""),
            email=email,
            api_key=smsbower.get("api_key", ""),
            ignore_codes=ignore_codes,
        )

    if not mail_url:
        # 最后兜底：有 RT 仍可试 Graph
        if _is_microsoft_email(email) and has_ms_oauth_credentials(email):
            return poll_ms_oauth_otp(
                email,
                not_before=not_before,
                ignore_codes=ignore_codes,
                exclude_message_ids=exclude_message_ids,
            )
        return None

    # HTTP mail_url (icloud-api.top 等)：本机直连，不走注册代理 / 环境代理
    s = requests.Session()
    s.trust_env = False
    s.proxies = dict(_DIRECT_PROXIES)
    s.verify = False
    deadline = time.time() + max(5, C.EMAIL_OTP_POLL_SECONDS)
    # 拒用占位/CSS 垃圾码。实测 icloud-api.top 卡片 HTML 会带 #202123/#353740
    # 盲扫 \d{6} 会误取 → OpenAI 401 wrong_email_otp_code
    _junk = frozenset(
        {
            "000000",  # New sign-in 模板占位
            "111111",
            "123456",
            "654321",
            "999999",
            "202123",  # OpenAI 邮件 CSS #202123
            "353740",  # OpenAI 邮件 CSS #353740
            "101010",
            "010101",
        }
    )
    ignore_codes = set(ignore_codes or ())
    ignore_codes |= _junk
    ignore_codes |= _otp_noise_codes(email)
    try:
        nb = float(not_before or 0)
    except Exception:
        nb = 0.0
    if nb > 0:
        nb = nb - float(getattr(C, "EMAIL_OTP_TIME_SKEW", 30.0) or 30.0)

    def _strip_noise(html: str) -> str:
        cleaned = re.sub(r"(?is)<(style|script)[^>]*>.*?</\1>", " ", html or "")
        cleaned = re.sub(r"(?i)#[0-9a-f]{3,8}\b", " ", cleaned)
        cleaned = re.sub(r"(?i)rgb\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\)", " ", cleaned)
        return cleaned

    def _parse_card_time(dt_raw: str) -> float:
        raw = (dt_raw or "").strip()
        if not raw:
            return 0.0
        # "Thu, 30 Jul 2026 22:05:49 +0000 (UTC)" → 去掉尾部 (UTC)
        raw = re.sub(r"\s*\([^)]*\)\s*$", "", raw).strip()
        try:
            from email.utils import parsedate_to_datetime

            d = parsedate_to_datetime(raw)
            if d is not None:
                return float(d.timestamp())
        except Exception:
            pass
        try:
            from datetime import datetime

            return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0

    def _codes_from_html(html: str) -> list[str]:
        """icloud-api.top HTML 收件箱：按 .card / .su / .dt / .bd 取最新验证码。

        实测格式：
          <div class="card">
            <div class="su">Your temporary ChatGPT login code</div>
            <div class="dt">Thu, 30 Jul 2026 21:09:39 +0000 (UTC)</div>
            <div class="bd">... Lucida Console ... endif]--> 237709 ...</div>
          </div>
        整页扫 6 位会先命中 CSS #202123/#353740 → 401 wrong_email_otp_code。
        套餐/收据主题含 ChatGPT 但无验证码，禁止当 subj_ok 盲扫（曾误取 206000）。
        """
        if not html:
            return []
        text = str(html)
        cards = re.split(r'(?i)<div class="card"', text)
        if len(cards) <= 1:
            cards = [text]
        else:
            cards = cards[1:]

        max_age = float(getattr(C, "EMAIL_OTP_MAX_AGE_SECONDS", 300) or 300)
        now_ts = time.time()
        candidates: list[tuple[float, int, str]] = []  # (ts, score, code)
        for card in cards:
            su_m = re.search(r'(?is)class="su"[^>]*>([^<]+)', card)
            dt_m = re.search(r'(?is)class="dt"[^>]*>([^<]+)', card)
            subject = (su_m.group(1) if su_m else "").strip().lower()
            ts = _parse_card_time(dt_m.group(1) if dt_m else "")
            if nb > 0 and ts > 0 and ts < nb:
                continue  # 发码前的旧信
            if ts > 0 and max_age > 0 and (now_ts - ts) > max_age:
                continue  # 超过 5 分钟的旧码
            cleaned = _strip_noise(card)
            # 必须是「验证码/临时登录码」类主题；纯 ChatGPT/OpenAI 品牌主题不算
            # 日文实测：ChatGPT 用の一時ログインコード / ChatGPT の一時的な認証コード
            subj_code = any(
                k in subject
                for k in (
                    "verification code",
                    "login code",
                    "temporary",
                    "one-time",
                    "otp",
                    "código",
                    "codigo",
                    "验证码",
                    "認証",
                    "认证",
                    "确认代码",
                    "確認コード",
                    "ログインコード",
                    "認証コード",
                    "一時",
                    "ログイン",
                )
            )
            # 排除套餐/收据/安全通知（主题常带 ChatGPT 但无 OTP）
            if any(
                k in subject
                for k in (
                    "new plan",
                    "new subscription",
                    "subscription",
                    "subscribed",
                    "プラン",
                    "plan",
                    "領収",
                    "receipt",
                    "invoice",
                    "payment",
                    "お支払い",
                    "new sign-in",
                    "new login",
                    "security alert",
                    "signed in",
                )
            ) and not subj_code:
                continue
            body_l = cleaned.lower()
            body_code_hint = any(
                k in body_l
                for k in (
                    "temporary verification code",
                    "verification code",
                    "login code",
                    "one-time code",
                    "enter this temporary",
                    "lucida console",
                )
            )
            if not subj_code and not body_code_hint:
                continue

            codes_found: list[tuple[int, str]] = []
            # 1) OpenAI 模板：Lucida Console / 大字号 / letter-spacing 后的 6 位
            for m in re.finditer(
                r"(?is)(?:Lucida Console|font-size:\s*3[2-9]px|font-size:\s*[4-9]\dpx|"
                r"letter-spacing|endif\s*\]\s*-->)[^0-9]{0,120}?(?<!\d)(\d{6})(?!\d)",
                cleaned,
            ):
                codes_found.append((100, m.group(1)))
            if not codes_found:
                for m in re.finditer(
                    r"(?is)(?:verification code|login code|one-time code|code is|"
                    r"temporary verification code|código|codigo|验证码)"
                    r"[^0-9]{0,80}(?<!\d)(\d{6})(?!\d)",
                    cleaned,
                ):
                    codes_found.append((80, m.group(1)))
            if not codes_found:
                # 仅在明确是验证码主题 + 正文提示时才盲扫卡片内独立 6 位
                if subj_code and body_code_hint:
                    for m in re.finditer(r"(?<!\d)(\d{6})(?!\d)", cleaned):
                        codes_found.append((40, m.group(1)))

            for score, code in codes_found:
                if code in ignore_codes:
                    continue
                # 再挡一轮常见非 OTP 数字（logo 宽高等拼接幻觉）
                if code in _junk or code.startswith("000") or code.endswith("0000"):
                    continue
                use_ts = ts if ts > 0 else time.time()
                if nb > 0 and ts <= 0 and not subj_code:
                    continue
                candidates.append((use_ts, score, code))

        candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
        out: list[str] = []
        seen: set[str] = set()
        for _ts, _sc, code in candidates:
            if code not in seen:
                seen.add(code)
                out.append(code)
        return out

    def _codes_from_payload(data) -> list[str]:
        if isinstance(data, str):
            low = data.lstrip()[:40].lower()
            if (
                "<html" in low
                or "<!doctype" in low
                or 'class="card"' in data
                or "<div" in data[:800].lower()
            ):
                return _codes_from_html(data)
            # plain
            smart = _extract_otp_code(data, email=email)
            if smart and smart not in ignore_codes:
                return [smart]
            codes = re.findall(r"(?<!\d)(\d{6})(?!\d)", data)
            return [c for c in codes if c not in ignore_codes]
        if isinstance(data, dict):
            for k in (
                "code",
                "otp",
                "verification_code",
                "email_code",
                "content",
                "body",
                "text",
                "html",
                "message",
            ):
                v = data.get(k)
                if isinstance(v, str) and v.strip():
                    got = _codes_from_payload(v)
                    if got:
                        return got
            return _codes_from_payload(json.dumps(data, ensure_ascii=False))
        return _codes_from_payload(str(data))

    try:
        while time.time() < deadline:
            try:
                current_mail_url = _expand_mail_url(mail_url, email)
                r = s.get(
                    current_mail_url,
                    headers={
                        "Accept": "text/html,application/json,text/plain,*/*",
                        "User-Agent": C.USER_AGENT,
                    },
                    timeout=20,
                    verify=False,
                    allow_redirects=True,
                )
                raw = r.text or ""
                try:
                    data = r.json()
                except Exception:
                    data = raw

                text = json.dumps(data) if isinstance(data, dict) else str(data)
                if not _mail_text_matches_email(text, email):
                    time.sleep(C.EMAIL_OTP_POLL_INTERVAL)
                    continue

                codes = _codes_from_payload(data)
                for c in codes:
                    log_line(
                        f"Email OTP via mail_url: {c} "
                        f"(not_before={int(nb) if nb else 0} ignore={len(ignore_codes)})"
                    )
                    s.close()
                    return c
                # 诊断：有 HTML 但筛不出码（常见：只剩套餐信 / 新码未到）
                if isinstance(data, str) and len(data) > 200:
                    n_card = len(re.findall(r'(?i)class="card"', data))
                    subjects = re.findall(r'(?is)class="su"[^>]*>([^<]+)', data)
                    subj_brief = ",".join(
                        re.sub(r"\s+", " ", (x or "").strip())[:40] for x in subjects[:4]
                    )
                    if int(time.time()) % 8 == 0:
                        log_line(
                            f"mail_url poll empty cards={n_card} "
                            f"subj=[{subj_brief}] html_len={len(data)} "
                            f"nb={int(nb) if nb else 0}"
                        )

            except Exception as e:
                if int(time.time()) % 10 == 0:
                    log_line(f"mail_url poll err: {type(e).__name__}: {e}")
            time.sleep(C.EMAIL_OTP_POLL_INTERVAL)
    finally:
        s.close()

    return None


def resend_email_otp(refresher, email: str) -> bool:
    """重新发送 email OTP"""
    from .utils import request_with_retry
    h = refresher._json_headers(f"{C.AUTH_BASE}/email-verification")
    resp, err = request_with_retry(
        refresher.session, "post",
        f"{C.AUTH_BASE}/api/accounts/email-otp/send",
        json_data={"device_id": refresher.device_id, "email": email},
        headers=h, verify=False,
    )
    return resp is not None and resp.status_code == 200
