"""Cloudflare managed-challenge detection + recovery helpers (pure + session I/O).

Reverse-engineered from browser HAR (auth.openai.com authorize GET 403
"Just a moment..." → POST authorize form → 302).

Pure functions are unit-testable without network. Session helpers attempt:
  1) classic HTML form POST (legacy CF)
  2) managed challenge soft recovery (warm + cookie clear + re-GET with
     browser impersonation) — full JS VM solve is environment-limited

403/409 from CF/WAF are NEVER account-ban signals by themselves.
"""
from __future__ import annotations

import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, MutableMapping, Optional

# HAR: title + noscript + window._cf_chl_opt + orchestrate script
_JUST_A_MOMENT = re.compile(r"just\s+a\s+moment", re.I)
_CF_CHL_OPT = re.compile(
    r"window\._cf_chl_opt\s*=\s*\{([\s\S]*?)\}\s*;\s*var\s+a\s*=",
    re.I,
)
_CF_CHL_OPT_LOOSE = re.compile(r"window\._cf_chl_opt\s*=\s*\{", re.I)
_CF_RAY_META = re.compile(r"cRay\s*:\s*['\"]([^'\"]+)['\"]", re.I)
_CF_TYPE = re.compile(r"cType\s*:\s*['\"]([^'\"]+)['\"]", re.I)
_CF_ZONE = re.compile(r"cZone\s*:\s*['\"]([^'\"]+)['\"]", re.I)
_CF_FA = re.compile(r"""fa\s*:\s*["']([^"']+)["']""", re.I)
_CF_UPMDTK = re.compile(r"""cUPMDTk\s*:\s*["']([^"']+)["']""", re.I)
_CF_CHL_TK = re.compile(r"__cf_chl_tk=([^&\"'\\s]+)", re.I)
_CLASSIC_FORM = re.compile(
    r'<form[^>]+id=["\']challenge-form["\'][^>]*>([\s\S]*?)</form>',
    re.I,
)
_INPUT = re.compile(
    r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
    re.I,
)
_HEX64_NAME = re.compile(r"^[a-f0-9]{32,64}$", re.I)


@dataclass
class CfChallengeMeta:
    is_challenge: bool = False
    status: int = 0
    c_type: str = ""  # managed | interactive | ...
    c_ray: str = ""
    c_zone: str = ""
    form_action: str = ""  # fa path or absolute
    c_upmdtk: str = ""
    chl_tk: str = ""
    classic_fields: dict[str, str] = field(default_factory=dict)
    server: str = ""
    cf_ray_header: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_challenge": self.is_challenge,
            "status": self.status,
            "c_type": self.c_type,
            "c_ray": self.c_ray,
            "c_zone": self.c_zone,
            "form_action": self.form_action[:200],
            "chl_tk": (self.chl_tk or "")[:80],
            "classic_fields": list(self.classic_fields.keys())[:8],
            "server": self.server,
            "cf_ray_header": self.cf_ray_header,
            "reason": self.reason,
        }


def _header_map(headers: Mapping[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not headers:
        return out
    try:
        items = headers.items()  # type: ignore[attr-defined]
    except Exception:
        try:
            items = list(headers)  # type: ignore[arg-type]
        except Exception:
            return out
    for k, v in items:
        out[str(k).lower()] = str(v or "")
    return out


def is_cf_challenge_response(
    status: int | None,
    headers: Mapping[str, Any] | None = None,
    body: str | None = "",
) -> bool:
    """True if response is Cloudflare interstitial / managed challenge."""
    st = int(status or 0)
    body_s = str(body or "")
    h = _header_map(headers)
    server = (h.get("server") or "").lower()
    cf_ray = h.get("cf-ray") or h.get("cf_ray") or ""

    if _JUST_A_MOMENT.search(body_s) and (
        "challenge" in body_s.lower()
        or _CF_CHL_OPT_LOOSE.search(body_s)
        or "cloudflare" in body_s.lower()
    ):
        return True
    if st == 403 and (_CF_CHL_OPT_LOOSE.search(body_s) or "cdn-cgi/challenge-platform" in body_s):
        return True
    if st == 403 and "cloudflare" in server and (
        "just a moment" in body_s.lower() or "cf-browser-verification" in body_s.lower()
    ):
        return True
    if st == 403 and cf_ray and "enable javascript" in body_s.lower():
        return True
    # soft signal: CF 403 with empty-ish HTML title moment
    if st == 403 and cf_ray and "cloudflare" in server and len(body_s) > 500:
        if "challenge" in body_s.lower() or "cf-" in body_s.lower():
            return True
    return False


def parse_cf_challenge_meta(
    status: int | None,
    headers: Mapping[str, Any] | None = None,
    body: str | None = "",
    *,
    base_url: str = "",
) -> CfChallengeMeta:
    """Extract challenge metadata from a 403 (or challenge) response."""
    st = int(status or 0)
    body_s = str(body or "")
    h = _header_map(headers)
    meta = CfChallengeMeta(
        status=st,
        server=(h.get("server") or ""),
        cf_ray_header=(h.get("cf-ray") or h.get("cf_ray") or ""),
    )
    meta.is_challenge = is_cf_challenge_response(st, headers, body_s)
    if not meta.is_challenge:
        meta.reason = "not_cf_challenge"
        return meta

    m_ray = _CF_RAY_META.search(body_s)
    if m_ray:
        meta.c_ray = m_ray.group(1)
    elif meta.cf_ray_header:
        meta.c_ray = meta.cf_ray_header.split("-")[0]

    m_type = _CF_TYPE.search(body_s)
    if m_type:
        meta.c_type = m_type.group(1)

    m_zone = _CF_ZONE.search(body_s)
    if m_zone:
        meta.c_zone = m_zone.group(1)

    m_fa = _CF_FA.search(body_s)
    if m_fa:
        fa = m_fa.group(1).encode("utf-8").decode("unicode_escape")
        meta.form_action = _abs_url(base_url, fa)

    m_up = _CF_UPMDTK.search(body_s)
    if m_up:
        meta.c_upmdtk = m_up.group(1).encode("utf-8").decode("unicode_escape")

    m_tk = _CF_CHL_TK.search(body_s)
    if m_tk:
        meta.chl_tk = urllib.parse.unquote(m_tk.group(1))

    # classic form fields
    form_m = _CLASSIC_FORM.search(body_s)
    blob = form_m.group(1) if form_m else body_s
    for name, value in _INPUT.findall(blob):
        if name:
            meta.classic_fields[name] = value or ""

    if not meta.form_action and base_url:
        meta.form_action = base_url.split("#")[0]

    meta.reason = f"cf_{meta.c_type or 'challenge'}"
    return meta


def _abs_url(base: str, path: str) -> str:
    path = str(path or "").strip()
    if not path:
        return str(base or "")
    if path.startswith("http://") or path.startswith("https://"):
        return path
    base = str(base or "")
    if not base:
        return path
    return urllib.parse.urljoin(base, path)


def build_classic_challenge_post(
    meta: CfChallengeMeta,
    *,
    extra: Mapping[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    """Build (action_url, form_fields) for classic CF challenge-form POST.

    Managed challenges often have no static fields; then fields may be empty
    and caller should soft-recover instead of POST.
    """
    fields = dict(meta.classic_fields)
    if extra:
        fields.update({str(k): str(v) for k, v in extra.items()})
    action = meta.form_action or ""
    return action, fields


def is_soft_http_env_status(status: int | None, body: str = "") -> bool:
    """403/409 that must not be treated as account ban by status alone."""
    st = int(status or 0)
    if st in (403, 409, 429, 408):
        # if body has explicit deactivation, caller must still check ban markers
        low = (body or "").lower()
        if "deactivated" in low and "account" in low:
            return False
        if "deleted or deactivated" in low:
            return False
        return True
    return False


def is_dead_authorize_continue_status(status: int | None) -> bool:
    """authorize/continue 409 (and CF-like 403) → dead state, recover once."""
    return int(status or 0) in (409, 403)


def should_attempt_cf_pass(meta: CfChallengeMeta) -> bool:
    return bool(meta.is_challenge)


def needs_human_click(meta: CfChallengeMeta | None) -> bool:
    """True when challenge is interactive / managed JS that pure-HTTP can't click through.

    Policy: do NOT keep hammering the same IP — raise soft error and rotate proxy.
    """
    if not meta or not meta.is_challenge:
        return False
    t = (meta.c_type or "").strip().lower()
    # interactive / turnstile always need human or real browser solve
    if t in ("interactive", "turnstile", "managed_turnstile"):
        return True
    # managed without classic form fields = orchestrate JS (often click/auto if good IP)
    if t == "managed" and not meta.classic_fields:
        return True
    # unknown challenge type still blocked after pass attempts → treat as rotate
    if t in ("", "challenge") and not meta.classic_fields:
        return True
    return False


def cf_rotate_proxy_error_message(
    meta: CfChallengeMeta | None = None,
    status: int | None = None,
) -> str:
    """Soft error: caller must release proxy and retry on a new exit (NOT ban)."""
    st = int(status if status is not None else (meta.status if meta else 0))
    ctype = (meta.c_type if meta else "") or "challenge"
    ray = ""
    if meta:
        ray = (meta.c_ray or meta.cf_ray_header or "")[:24]
    return (
        f"cf_interactive_rotate_proxy HTTP {st} type={ctype} ray={ray} "
        f"(needs click/JS; soft env rotate IP, NOT deactivated)"
    )


def is_cf_rotate_proxy_error(err: str) -> bool:
    low = (err or "").lower()
    return (
        "cf_interactive_rotate_proxy" in low
        or ("rotate" in low and "proxy" in low and "cf_" in low)
        or ("needs click" in low and "cf" in low)
    )


def attempt_cf_challenge_on_response(
    session: Any,
    *,
    request_url: str,
    resp: Any,
    navigate_headers: Callable[[str], dict[str, str]] | None = None,
    log: Callable[[str], None] | None = None,
    max_retries: int = 2,
) -> Any | None:
    """If resp is CF challenge, try classic form POST + re-GET recover.

    Returns a follow-up response on success, else None (caller soft-recovers).
    Does not raise for challenge failure — never labels ban.
    """
    _log = log or (lambda _m: None)
    status = getattr(resp, "status_code", None)
    body = ""
    try:
        body = resp.text or ""
    except Exception:
        body = ""
    headers = getattr(resp, "headers", None)
    meta = parse_cf_challenge_meta(status, headers, body, base_url=request_url)
    if not meta.is_challenge:
        return None

    _log(
        f"cf_challenge detected type={meta.c_type or '-'} ray={meta.c_ray or meta.cf_ray_header} "
        f"zone={meta.c_zone or '-'} classic_fields={len(meta.classic_fields)}"
    )

    hdr_fn = navigate_headers or (lambda _r: {})
    action, fields = build_classic_challenge_post(meta)

    # 1) classic form POST when we have a hex field (legacy CF)
    hex_fields = {k: v for k, v in fields.items() if _HEX64_NAME.match(k)}
    if action and hex_fields:
        post_url = action if action.startswith("http") else urllib.parse.urljoin(request_url, action)
        try:
            _log(f"cf_challenge classic POST {post_url[:120]} fields={list(hex_fields)[:2]}")
            r2 = session.request(
                "POST",
                post_url,
                data=fields,
                headers={
                    **hdr_fn(request_url),
                    "content-type": "application/x-www-form-urlencoded",
                    "origin": urllib.parse.urljoin(request_url, "/"),
                    "referer": request_url,
                },
                allow_redirects=True,
                timeout=40,
                verify=False,
            )
            if r2 is not None and not is_cf_challenge_response(
                getattr(r2, "status_code", None),
                getattr(r2, "headers", None),
                getattr(r2, "text", "") or "",
            ):
                _log(
                    f"cf_challenge classic POST ok HTTP={getattr(r2, 'status_code', '?')} "
                    f"url={str(getattr(r2, 'url', ''))[:120]}"
                )
                return r2
        except Exception as e:
            _log(f"cf_challenge classic POST failed: {e}")

    # 2) managed: warm same origin, short wait, re-GET fa / original URL
    for attempt in range(1, max_retries + 1):
        try:
            origin = urllib.parse.urljoin(request_url, "/")
            session.request(
                "GET",
                origin,
                headers=hdr_fn(origin),
                allow_redirects=True,
                timeout=15,
                verify=False,
            )
        except Exception:
            pass
        time.sleep(0.35 * attempt)
        retry_url = meta.form_action or request_url
        if retry_url and not retry_url.startswith("http"):
            retry_url = urllib.parse.urljoin(request_url, retry_url)
        try:
            _log(f"cf_challenge re-GET attempt={attempt} url={str(retry_url)[:120]}")
            r3 = session.request(
                "GET",
                retry_url or request_url,
                headers=hdr_fn(request_url),
                allow_redirects=True,
                timeout=40,
                verify=False,
            )
            if r3 is None:
                continue
            b3 = getattr(r3, "text", "") or ""
            if is_cf_challenge_response(
                getattr(r3, "status_code", None),
                getattr(r3, "headers", None),
                b3,
            ):
                _log(f"cf_challenge still blocked attempt={attempt}")
                continue
            _log(
                f"cf_challenge re-GET ok HTTP={getattr(r3, 'status_code', '?')} "
                f"url={str(getattr(r3, 'url', ''))[:120]}"
            )
            return r3
        except Exception as e:
            _log(f"cf_challenge re-GET failed attempt={attempt}: {e}")
    _log("cf_challenge pass incomplete (soft env — NOT deactivated)")
    return None


def cf_soft_error_message(meta: CfChallengeMeta | None = None, status: int | None = None) -> str:
    """Stable soft error string for classifiers (must not hard-skip).

    Interactive / managed (needs click) → rotate-proxy wording so reg loop
    releases the sticky exit and picks a new IP.
    """
    if meta is not None and needs_human_click(meta):
        return cf_rotate_proxy_error_message(meta, status)
    st = int(status if status is not None else (meta.status if meta else 0))
    ctype = (meta.c_type if meta else "") or "challenge"
    return (
        f"cf_challenge_soft HTTP {st} type={ctype} "
        f"(soft env/state fail, NOT deactivated; retry/rotate proxy ok)"
    )
