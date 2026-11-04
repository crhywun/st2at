"""Optional email + password + TOTP relogin flow.

The protocol implementation is adapted from the account-flow relogin path in
pay153-local and uses the vendored tokenrefresh helpers. It is intentionally
separate from the ST -> AT fast path: use it only when an existing ST can no
longer mint a fresh AT.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

_VENDOR = Path(__file__).resolve().parent.parent / "_vendor"
_LOGIN_DIR = Path(__file__).resolve().parent
for _path in (_LOGIN_DIR, _VENDOR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from st2at.proxy import prepare_proxy  # noqa: E402
from st2at.token import extract_claims  # noqa: E402

from .relogin_auth import login_with_password_totp as _login_with_password_totp  # noqa: E402


@dataclass(frozen=True, slots=True)
class LoginResult:
    ok: bool
    email: str
    access_token: str = ""
    session_token: str = ""
    account_id: str | None = None
    expires_at: datetime | None = None
    error: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "email": self.email,
            "access_token": self.access_token or None,
            "session_token": self.session_token or None,
            "account_id": self.account_id,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "error": self.error or None,
        }


def login_with_password_totp(
    email: str,
    *,
    password: str,
    totp_secret: str,
    proxy: str | None = None,
    region: str = "JP",
    workspace_id: str = "",
    log: Callable[[str], None] | None = None,
) -> LoginResult:
    """Log in with an email password and a base32 TOTP secret.

    A fresh proxy session is created for each call when a 711/BestGo-style
    proxy is supplied. The returned ST is the NextAuth session token; the AT is
    the fresh web access token.
    """

    email = str(email or "").strip().lower()
    if not email or "@" not in email:
        return LoginResult(ok=False, email=email, error="invalid email")
    if not password:
        return LoginResult(ok=False, email=email, error="password is required")
    if not totp_secret:
        return LoginResult(ok=False, email=email, error="totp_secret is required")

    try:
        proxy_uri = prepare_proxy(proxy, region=region) if proxy else None
    except Exception as exc:
        return LoginResult(ok=False, email=email, error=f"proxy: {exc}")

    try:
        raw = _login_with_password_totp(
            email,
            password=password,
            totp_secret=totp_secret,
            proxy=proxy_uri or "",
            log=log,
            profile_region=region,
            workspace_id=workspace_id,
        )
    except Exception as exc:
        return LoginResult(
            ok=False, email=email, error=f"{type(exc).__name__}: {exc}"[:500]
        )

    if not isinstance(raw, dict):
        return LoginResult(ok=False, email=email, error="login returned no result")

    access_token = str(raw.get("access_token") or "").strip()
    session_token = str(raw.get("st") or "").strip()
    ok = bool(raw.get("ok") and (access_token or session_token))
    claims = extract_claims(access_token) if access_token else None
    return LoginResult(
        ok=ok,
        email=email,
        access_token=access_token,
        session_token=session_token,
        account_id=claims.account_id if claims else None,
        expires_at=claims.expires_at if claims else None,
        error=str(raw.get("error") or ""),
    )


__all__ = ["LoginResult", "login_with_password_totp"]
