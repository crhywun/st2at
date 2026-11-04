"""Enable ChatGPT TOTP MFA (protocol) + persist local authenticator secret.

Source of truth: JP-10 capture
  ``抓包/jp-10/MFA.har`` + ``sentinel_mem_2026-08-04T04-34-11-563Z_3176.jsonl``

Browser-aligned flow (chatgpt.com, Bearer web AT)::

  0. Post-login surface + chat-requirements prepare/finalize
  1. GET  mfa_info (referer home) — probe security state
  2. Rotate oai-session-id; CES page #settings/Security
  3. GET  mfa_info (referer ?action=enable&factor=totp)
  4. POST enroll  body: {"factor_type":"totp"}
        → secret, session_id, factor.id
  5. Local TOTP (RFC 6238, period=30, digits=6, SHA1)
  6. POST activate_enrollment
  7. GET  mfa_info verify

All backend-api calls carry SPA identity headers:
  oai-device-id, oai-session-id, oai-client-version, oai-client-build-number.

Disable surface warm: TOKENREFRESH_MFA_SURFACE=0
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

from . import constants as C
from .client_identity import apply_client_identity_headers, new_session_id
from .utils import request_with_retry

LogFn = Callable[[str], None]

MFA_INFO_URL = "https://chatgpt.com/backend-api/accounts/mfa_info"
MFA_ENROLL_URL = "https://chatgpt.com/backend-api/accounts/mfa/enroll"
MFA_ACTIVATE_URL = "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment"

REFERER_HOME = "https://chatgpt.com/"
REFERER_SECURITY = "https://chatgpt.com/?action=enable&factor=totp"
REFERER_SECURITY_HASH = "https://chatgpt.com/?action=enable&factor=totp#settings/Security"

# Verified against jp-10 secret 24TMF7… → code 104896 at counter for t=1785818025
_TOTP_PERIOD = 30
_TOTP_DIGITS = 6


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log_default(msg: str) -> None:
    print(msg, flush=True)


def b32_decode_secret(secret: str) -> bytes:
    """Decode base32 TOTP secret (padding tolerant)."""
    s = "".join(ch for ch in (secret or "").strip().upper() if ch.isalnum())
    if not s:
        raise ValueError("empty totp secret")
    pad = "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s + pad, casefold=True)


def totp_code(secret: str, *, for_time: float | None = None, period: int = _TOTP_PERIOD, digits: int = _TOTP_DIGITS) -> str:
    """RFC 6238 TOTP (SHA-1). Matches authenticator apps / jp-10 activate body."""
    key = b32_decode_secret(secret)
    t = time.time() if for_time is None else float(for_time)
    counter = int(t // max(1, int(period)))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    mod = 10**int(digits)
    return str(binary % mod).zfill(int(digits))


def otpauth_url(
    secret: str,
    *,
    email: str = "",
    issuer: str = "OpenAI",
    account_name: str = "",
) -> str:
    """Standard otpauth:// URL for importing into authenticator apps."""
    label_user = (account_name or email or "chatgpt").strip() or "chatgpt"
    label = f"{issuer}:{label_user}"
    # secret must remain unpadded base32 for most apps
    sec = "".join(ch for ch in (secret or "").strip().upper() if ch.isalnum())
    q = (
        f"secret={sec}"
        f"&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={_TOTP_DIGITS}&period={_TOTP_PERIOD}"
    )
    return f"otpauth://totp/{quote(label)}?{q}"


@dataclass
class MfaResult:
    email: str = ""
    ok: bool = False
    already_enabled: bool = False
    mfa_enabled: bool = False
    secret: str = ""
    session_id: str = ""
    factor_id: str = ""
    otpauth: str = ""
    code_used: str = ""
    mfa_info: dict[str, Any] = field(default_factory=dict)
    enroll: dict[str, Any] = field(default_factory=dict)
    activate: dict[str, Any] = field(default_factory=dict)
    saved_path: str = ""
    error: str = ""
    elapsed_s: float = 0.0
    http: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def secret_record(self) -> dict[str, Any]:
        """Compact record for local JSONL / per-account files."""
        return {
            "ts": _utc(),
            "email": self.email,
            "ok": self.ok,
            "already_enabled": self.already_enabled,
            "mfa_enabled": self.mfa_enabled,
            "secret": self.secret,
            "factor_id": self.factor_id,
            "session_id": self.session_id,
            "otpauth": self.otpauth,
            "factor_type": "totp",
            "source": "jp-10/mfa_enroll",
        }


def _env_bool(name: str, default: bool = True) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _headers(
    access_token: str,
    *,
    device_id: str = "",
    language: str = "ja-JP",
    user_agent: str = "",
    referer: str = REFERER_SECURITY,
    path: str = "",
    session_id: str = "",
    refresher: Any = None,
) -> dict[str, str]:
    at = (access_token or "").strip()
    if at.lower().startswith("bearer "):
        at = at[7:].strip()
    ua = (user_agent or getattr(C, "USER_AGENT", "") or "").strip()
    fp = getattr(refresher, "fingerprint_profile", None) or {}
    accept_language = str(fp.get("accept_language") or "").strip()
    h: dict[str, str] = {
        "accept": "*/*",
        "accept-language": accept_language or (language if language else "ja-JP"),
        "authorization": f"Bearer {at}",
        "content-type": "application/json",
        "origin": "https://chatgpt.com",
        "referer": referer,
        "user-agent": ua,
        "oai-language": language or "ja-JP",
        "x-oai-is-client-observation": "false",
        "x-oai-is-pending-updates": "false",
    }
    apply_client_identity_headers(
        h,
        device_id=device_id,
        language=language or "ja-JP",
        session_id=session_id,
        refresher=refresher,
    )
    if path:
        h["x-openai-target-path"] = path
        h["x-openai-target-route"] = path
    return h


def _json_body(resp: Any) -> dict[str, Any]:
    if resp is None:
        return {}
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {"_raw": data}
    except Exception:
        text = ""
        try:
            text = (resp.text or "")[:800]
        except Exception:
            pass
        return {"_text": text}


def _req(
    session: Any,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    body: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> tuple[Any, str, dict[str, Any]]:
    kwargs: dict[str, Any] = {
        "headers": headers,
        "timeout": timeout,
        "verify": False,
        "allow_redirects": True,
    }
    if body is not None:
        kwargs["data"] = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    resp, err = request_with_retry(session, method.lower(), url, **kwargs)
    return resp, err or "", _json_body(resp)


def fetch_mfa_info(
    session: Any,
    access_token: str,
    *,
    device_id: str = "",
    language: str = "ja-JP",
    user_agent: str = "",
    referer: str = REFERER_HOME,
    oai_session_id: str = "",
    refresher: Any = None,
) -> tuple[dict[str, Any], int, str]:
    path = "/backend-api/accounts/mfa_info"
    h = _headers(
        access_token,
        device_id=device_id,
        language=language,
        user_agent=user_agent,
        referer=referer,
        path=path,
        session_id=oai_session_id,
        refresher=refresher,
    )
    # GET must not force content-type
    h.pop("content-type", None)
    resp, err, data = _req(session, "GET", MFA_INFO_URL, headers=h, body=None)
    st = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
    return data, st, err


def enroll_totp(
    session: Any,
    access_token: str,
    *,
    device_id: str = "",
    language: str = "ja-JP",
    user_agent: str = "",
    referer: str = REFERER_SECURITY,
    oai_session_id: str = "",
    refresher: Any = None,
) -> tuple[dict[str, Any], int, str]:
    path = "/backend-api/accounts/mfa/enroll"
    h = _headers(
        access_token,
        device_id=device_id,
        language=language,
        user_agent=user_agent,
        referer=referer,
        path=path,
        session_id=oai_session_id,
        refresher=refresher,
    )
    resp, err, data = _req(
        session,
        "POST",
        MFA_ENROLL_URL,
        headers=h,
        body={"factor_type": "totp"},
    )
    st = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
    return data, st, err


def activate_enrollment(
    session: Any,
    access_token: str,
    *,
    code: str,
    session_id: str,
    device_id: str = "",
    language: str = "ja-JP",
    user_agent: str = "",
    factor_type: str = "totp",
    referer: str = REFERER_SECURITY,
    oai_session_id: str = "",
    refresher: Any = None,
) -> tuple[dict[str, Any], int, str]:
    path = "/backend-api/accounts/mfa/user/activate_enrollment"
    h = _headers(
        access_token,
        device_id=device_id,
        language=language,
        user_agent=user_agent,
        referer=referer,
        path=path,
        session_id=oai_session_id,
        refresher=refresher,
    )
    body = {
        "code": str(code).strip(),
        "factor_type": factor_type or "totp",
        "session_id": str(session_id).strip(),
    }
    resp, err, data = _req(session, "POST", MFA_ACTIVATE_URL, headers=h, body=body)
    st = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
    return data, st, err


def warm_mfa_security_surface(
    session: Any,
    access_token: str,
    *,
    device_id: str = "",
    language: str = "ja-JP",
    user_agent: str = "",
    oai_session_id: str = "",
    refresher: Any = None,
    log_fn: LogFn | None = None,
) -> dict[str, Any]:
    """Minimal pre-MFA surface (me / accounts/check / settings) for enroll."""
    log = log_fn or _log_default
    stats: dict[str, Any] = {"steps": []}
    if not _env_bool("TOKENREFRESH_MFA_SURFACE", True):
        stats["skipped"] = "TOKENREFRESH_MFA_SURFACE=0"
        return stats

    # Path warm removed — MFA uses direct API spine below (me/check/settings).

    at = (access_token or "").strip()
    if at.lower().startswith("bearer "):
        at = at[7:].strip()
    sid = oai_session_id or new_session_id()
    fp = getattr(refresher, "fingerprint_profile", None) or {}
    raw_tz_off = fp.get("timezone_offset_minutes")
    if raw_tz_off is None:
        raw_tz_off = C.chrome_timezone_offset_min(str(fp.get("timezone") or ""))
    tz_off = int(raw_tz_off)
    spine: list[tuple[str, str, str]] = [
        ("me", "GET", "https://chatgpt.com/backend-api/me"),
        (
            "accounts_check",
            "GET",
            f"https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27?timezone_offset_min={tz_off}",
        ),
        ("settings_user", "GET", "https://chatgpt.com/backend-api/settings/user"),
        ("models", "GET", "https://chatgpt.com/backend-api/models"),
        (
            "conversations",
            "GET",
            "https://chatgpt.com/backend-api/conversations?offset=0&limit=28",
        ),
        (
            "cr_prepare",
            "POST",
            "https://chatgpt.com/backend-api/sentinel/chat-requirements/prepare",
        ),
        (
            "cr_finalize",
            "POST",
            "https://chatgpt.com/backend-api/sentinel/chat-requirements/finalize",
        ),
    ]
    for tag, method, url in spine:
        path = url.split("chatgpt.com", 1)[-1].split("?", 1)[0]
        h = _headers(
            at,
            device_id=device_id,
            language=language,
            user_agent=user_agent,
            referer=REFERER_HOME,
            path=path,
            session_id=sid,
            refresher=refresher,
        )
        if method == "GET":
            h.pop("content-type", None)
            resp, err, _ = _req(session, "GET", url, headers=h, body=None)
        else:
            resp, err, _ = _req(session, "POST", url, headers=h, body={})
        st = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
        stats["steps"].append({"tag": tag, "http": st, "err": err[:80] if err else ""})
        log(f"[mfa-surface] {tag} HTTP={st}")
    stats["oai_session_id"] = sid
    return stats


def save_mfa_secret_local(
    record: dict[str, Any],
    secrets_dir: str | Path,
    *,
    email: str = "",
) -> str:
    """Persist TOTP secret under secrets_dir (jsonl + per-email json).

    Layout::

      {dir}/mfa_secrets.jsonl          # append-only batch log
      {dir}/mfa_secrets/{email}.json   # latest per account
    """
    root = Path(secrets_dir)
    root.mkdir(parents=True, exist_ok=True)
    em = (email or record.get("email") or "unknown").strip().lower()
    safe = em.replace("@", "_at_").replace("/", "_")
    per_dir = root / "mfa_secrets"
    per_dir.mkdir(parents=True, exist_ok=True)
    per_path = per_dir / f"{safe}.json"
    payload = dict(record)
    payload.setdefault("ts", _utc())
    payload["email"] = em
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    per_path.write_text(text + "\n", encoding="utf-8")

    jsonl = root / "mfa_secrets.jsonl"
    with jsonl.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    # human-friendly one-line secrets.csv
    csv_path = root / "mfa_secrets.csv"
    write_header = not csv_path.is_file() or csv_path.stat().st_size == 0
    with csv_path.open("a", encoding="utf-8-sig", newline="") as f:
        if write_header:
            f.write("email,secret,factor_id,otpauth,mfa_enabled,ts\n")
        # escape commas in otpauth via quotes
        sec = str(payload.get("secret") or "")
        fid = str(payload.get("factor_id") or "")
        otp = str(payload.get("otpauth") or "").replace('"', '""')
        en = str(payload.get("mfa_enabled") or payload.get("ok") or "")
        ts = str(payload.get("ts") or "")
        f.write(f'{em},{sec},{fid},"{otp}",{en},{ts}\n')
    return str(per_path)


def enable_totp_mfa(
    session: Any,
    access_token: str,
    *,
    email: str = "",
    device_id: str = "",
    language: str = "ja-JP",
    user_agent: str = "",
    skip_if_enabled: bool = True,
    secrets_dir: str | Path | None = None,
    log_fn: LogFn | None = None,
    refresher: Any = None,
    warm_surface: bool = True,
) -> MfaResult:
    """Full TOTP MFA enable + optional local secret save.

    ``session``: curl_cffi / requests session (e.g. TokenRefresher.session).
    Pass ``refresher`` for full path-replay pre-MFA surface + identity binding.
    """
    log = log_fn or _log_default
    t0 = time.time()
    out = MfaResult(email=(email or "").strip().lower())
    at = (access_token or "").strip()
    if not at:
        out.error = "missing_access_token"
        out.elapsed_s = time.time() - t0
        return out
    if not device_id:
        device_id = str(
            getattr(refresher, "device_id", "") or ""
        ).strip() or str(uuid.uuid4())

    # Tab session id for SPA headers (rotate when entering security settings)
    home_sid = new_session_id()
    security_sid = new_session_id()
    if refresher is not None:
        try:
            setattr(refresher, "oai_session_id", home_sid)
        except Exception:
            pass

    try:
        # 0) post-login / MFA surface (HAR: me/check/settings/cr before enroll)
        if warm_surface and _env_bool("TOKENREFRESH_MFA_SURFACE", True):
            try:
                surf = warm_mfa_security_surface(
                    session,
                    at,
                    device_id=device_id,
                    language=language,
                    user_agent=user_agent,
                    oai_session_id=home_sid,
                    refresher=refresher,
                    log_fn=log,
                )
                out.http["surface"] = surf
            except Exception as se:
                log(f"[mfa] surface warm skip: {se}")
                out.http["surface_err"] = str(se)[:160]

        # 1) mfa_info with home referer (probe)
        info, st, err = fetch_mfa_info(
            session,
            at,
            device_id=device_id,
            language=language,
            user_agent=user_agent,
            referer=REFERER_HOME,
            oai_session_id=home_sid,
            refresher=refresher,
        )
        out.http["mfa_info_get"] = st
        out.mfa_info = info
        if st in (401, 403):
            out.error = f"mfa_info_http_{st}_need_reauth"
            log(f"[mfa] mfa_info HTTP={st} (token may need step-up reauth)")
            out.elapsed_s = time.time() - t0
            return out
        if err and st == 0:
            out.error = f"mfa_info_err:{err}"
            out.elapsed_s = time.time() - t0
            return out

        enabled = bool(info.get("mfa_enabled") or info.get("mfa_enabled_v2"))
        out.mfa_enabled = enabled
        if enabled and skip_if_enabled:
            factors = (info.get("factors") or {}).get("totp") or []
            if isinstance(factors, list) and factors:
                out.factor_id = str((factors[0] or {}).get("id") or "")
            out.ok = True
            out.already_enabled = True
            log(f"[mfa] already enabled factor_id={out.factor_id or '-'}")
            out.elapsed_s = time.time() - t0
            return out

        # 2) enter security settings — new oai-session-id + security referer
        if refresher is not None:
            try:
                setattr(refresher, "oai_session_id", security_sid)
            except Exception:
                pass
        # 3) mfa_info again with security referer (HAR does this)
        info_sec, st_sec, _ = fetch_mfa_info(
            session,
            at,
            device_id=device_id,
            language=language,
            user_agent=user_agent,
            referer=REFERER_SECURITY,
            oai_session_id=security_sid,
            refresher=refresher,
        )
        out.http["mfa_info_security"] = st_sec
        if info_sec:
            out.mfa_info = info_sec

        # 4) enroll
        enroll, st_e, err_e = enroll_totp(
            session,
            at,
            device_id=device_id,
            language=language,
            user_agent=user_agent,
            referer=REFERER_SECURITY,
            oai_session_id=security_sid,
            refresher=refresher,
        )
        out.http["enroll"] = st_e
        out.enroll = enroll
        if st_e in (401, 403):
            out.error = f"enroll_http_{st_e}_need_reauth"
            log(f"[mfa] enroll HTTP={st_e} need reauth/step-up")
            out.elapsed_s = time.time() - t0
            return out
        if st_e != 200 or not enroll.get("secret"):
            out.error = (
                f"enroll_fail http={st_e} err={err_e} "
                f"body={json.dumps(enroll, ensure_ascii=False)[:240]}"
            )
            log(f"[mfa] enroll fail: {out.error}")
            out.elapsed_s = time.time() - t0
            return out

        secret = str(enroll.get("secret") or "").strip()
        session_id = str(enroll.get("session_id") or "").strip()
        factor = enroll.get("factor") or {}
        factor_id = str(factor.get("id") or "").strip()
        out.secret = secret
        out.session_id = session_id
        out.factor_id = factor_id
        out.otpauth = otpauth_url(secret, email=out.email or email)
        log(
            f"[mfa] enrolled secret_len={len(secret)} session_id={session_id[:12]}… "
            f"factor_id={factor_id[:12]}… oai_sid={security_sid[:12]}…"
        )

        if secrets_dir:
            try:
                out.saved_path = save_mfa_secret_local(
                    {
                        **out.secret_record(),
                        "ok": False,
                        "mfa_enabled": False,
                        "phase": "enrolled_pending_activate",
                        "oai_session_id": security_sid,
                    },
                    secrets_dir,
                    email=out.email or email,
                )
            except Exception as se:
                log(f"[mfa] early secret save fail: {se}")

        code = totp_code(secret)
        out.code_used = code
        rem = _TOTP_PERIOD - (time.time() % _TOTP_PERIOD)
        if rem < 1.5:
            time.sleep(rem + 0.2)
            code = totp_code(secret)
            out.code_used = code

        act, st_a, err_a = activate_enrollment(
            session,
            at,
            code=code,
            session_id=session_id,
            device_id=device_id,
            language=language,
            user_agent=user_agent,
            referer=REFERER_SECURITY,
            oai_session_id=security_sid,
            refresher=refresher,
        )
        out.http["activate"] = st_a
        out.activate = act
        if st_a != 200 or not act.get("success"):
            time.sleep(1.0)
            code2 = totp_code(secret)
            out.code_used = code2
            act, st_a, err_a = activate_enrollment(
                session,
                at,
                code=code2,
                session_id=session_id,
                device_id=device_id,
                language=language,
                user_agent=user_agent,
                referer=REFERER_SECURITY,
                oai_session_id=security_sid,
                refresher=refresher,
            )
            out.http["activate_retry"] = st_a
            out.activate = act
        if st_a != 200 or not act.get("success"):
            out.error = (
                f"activate_fail http={st_a} err={err_a} "
                f"body={json.dumps(act, ensure_ascii=False)[:240]}"
            )
            log(f"[mfa] activate fail: {out.error}")
            out.elapsed_s = time.time() - t0
            return out

        # 7) verify mfa_info
        info2, st2, _ = fetch_mfa_info(
            session,
            at,
            device_id=device_id,
            language=language,
            user_agent=user_agent,
            referer=REFERER_HOME,
            oai_session_id=security_sid,
            refresher=refresher,
        )
        out.http["mfa_info_verify"] = st2
        out.mfa_info = info2 or out.mfa_info
        out.mfa_enabled = bool(
            (info2 or {}).get("mfa_enabled")
            or (info2 or {}).get("mfa_enabled_v2")
            or act.get("success")
        )
        out.ok = True
        log(f"[mfa] OK enabled={out.mfa_enabled} factor_id={out.factor_id[:16]}")

        if secrets_dir:
            try:
                out.saved_path = save_mfa_secret_local(
                    {**out.secret_record(), "oai_session_id": security_sid},
                    secrets_dir,
                    email=out.email or email,
                )
                log(f"[mfa] secret saved → {out.saved_path}")
            except Exception as se:
                log(f"[mfa] secret save fail: {se}")
    except Exception as exc:
        out.error = f"mfa_exception:{exc}"
        log(f"[mfa] exception: {exc}")

    out.elapsed_s = time.time() - t0
    return out


def enable_totp_mfa_on_session(
    session: Any,
    access_token: str,
    *,
    email: str = "",
    device_id: str = "",
    language: str = "ja-JP",
    user_agent: str = "",
    secrets_dir: str | Path | None = None,
    skip_if_enabled: bool = True,
    log_fn: LogFn | None = None,
    refresher: Any = None,
    warm_surface: bool = True,
) -> MfaResult:
    """Enable MFA on an **existing** registration session (same cookies/did/TLS).

    Prefer this right after register — do not open a second TokenRefresher.
    Pass the live ``refresher`` so path-replay + client identity bind correctly.
    """
    return enable_totp_mfa(
        session,
        access_token,
        email=email,
        device_id=device_id,
        language=language,
        user_agent=user_agent,
        skip_if_enabled=skip_if_enabled,
        secrets_dir=secrets_dir,
        log_fn=log_fn,
        refresher=refresher,
        warm_surface=warm_surface,
    )


def enable_totp_mfa_with_proxy(
    access_token: str,
    *,
    email: str = "",
    proxy: str = "",
    device_id: str = "",
    language: str = "ja-JP",
    user_agent: str = "",
    secrets_dir: str | Path | None = None,
    skip_if_enabled: bool = True,
    log_fn: LogFn | None = None,
    warm_surface: bool = True,
) -> MfaResult:
    """Open session for MFA using **registration identity** when provided.

    Continuity contract (must match register):
      - ``device_id`` / oai-did from registration (required for same persona)
      - ``proxy`` sticky exit used at register when possible
      - ``fingerprint_seed=email`` + same did → diversify/gpu same as register

    Without ``device_id``, a new random did is generated (legacy identity break).
    """
    from .session import TokenRefresher

    log = log_fn or _log_default
    did_in = str(device_id or "").strip()
    if not did_in:
        log(
            "[mfa] WARN: no oai_did from registration — new device_id will be "
            "generated (identity break). Prefer same-session MFA or CSV oai_did."
        )
    refresher = TokenRefresher(
        proxy_url=proxy or "",
        fingerprint_seed=email or access_token[:32],
        log_fn=lambda m: log(f"[mfa-session] {m}"),
        device_id=did_in,
    )
    try:
        fp = getattr(refresher, "fingerprint_profile", None) or {}
        lang = (
            (language or "").strip()
            or str(fp.get("language") or "")
            or "ja-JP"
        )
        ua = (
            (user_agent or "").strip()
            or str(fp.get("user_agent") or getattr(C, "USER_AGENT", "") or "")
        )
        did = str(getattr(refresher, "device_id", "") or did_in or "")
        log(
            f"[mfa] persona continuity did={did[:13]}… "
            f"screen={fp.get('screen')} lang={lang} "
            f"proxy={'sticky' if proxy else 'none'}"
        )
        return enable_totp_mfa(
            refresher.session,
            access_token,
            email=email,
            device_id=did,
            language=lang,
            user_agent=ua,
            skip_if_enabled=skip_if_enabled,
            secrets_dir=secrets_dir,
            log_fn=log,
            refresher=refresher,
            warm_surface=warm_surface,
        )
    finally:
        try:
            refresher.close()
        except Exception:
            pass
