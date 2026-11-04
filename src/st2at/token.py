"""Cookie normalization and non-verifying JWT claim extraction."""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

from .errors import InvalidSessionTokenError
from .models import TokenClaims

SESSION_COOKIE = "__Secure-next-auth.session-token"
_COOKIE_NAMES = (
    SESSION_COOKIE.lower(),
    "__secure-authjs.session-token",
    "__host-next-auth.session-token",
    "__host-authjs.session-token",
)
_CONTROL_CHARS = re.compile(r"[\r\n\x00]")


def _pairs_from_cookie_header(value: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, raw_value = part.split("=", 1)
        name = name.strip().lower()
        raw_value = raw_value.strip().strip('"')
        if name and name not in pairs:
            pairs[name] = unquote(raw_value)
    return pairs


def normalize_session_token(raw: str) -> str:
    """Accept a raw ST, a ``Cookie:`` header, or a full browser cookie string.

    Chunked NextAuth cookies (``...session-token.0``, ``...session-token.1``)
    are joined in index order. Only the session cookie is kept; other cookies
    are ignored so the request matches the extracted protocol.
    """

    if not isinstance(raw, str):
        raise InvalidSessionTokenError("session_token must be a string")

    value = raw.strip()
    if value.lower().startswith("cookie:"):
        value = value[7:].strip()
    if not value:
        raise InvalidSessionTokenError("session_token is empty")
    if _CONTROL_CHARS.search(value):
        raise InvalidSessionTokenError("session_token contains control characters")

    # A raw token normally has no semicolon. A full Cookie header always does,
    # or it starts with a known cookie name followed by '='.
    looks_like_cookie = ";" in value or value.lower().startswith(
        tuple(name + "=" for name in _COOKIE_NAMES)
    )
    if looks_like_cookie:
        pairs = _pairs_from_cookie_header(value)
        for name in _COOKIE_NAMES:
            token = pairs.get(name, "").strip()
            if token:
                return token

        chunked: dict[str, dict[int, str]] = {}
        for name, token in pairs.items():
            for base in _COOKIE_NAMES:
                match = re.fullmatch(re.escape(base) + r"\.(\d+)", name)
                if match:
                    chunked.setdefault(base, {})[int(match.group(1))] = token
                    break
        for base in _COOKIE_NAMES:
            chunks = chunked.get(base)
            if chunks:
                token = "".join(chunks[index] for index in sorted(chunks)).strip()
                if token:
                    return token

        raise InvalidSessionTokenError(
            "cookie header does not contain a supported session token"
        )

    lowered = value.lower()
    if "=" in value and lowered.startswith(
        ("__secure-", "__host-", "next-auth.", "authjs.")
    ):
        # A single cookie pair without a trailing semicolon.
        pairs = _pairs_from_cookie_header(value)
        for name in _COOKIE_NAMES:
            token = pairs.get(name, "").strip()
            if token:
                return token
        raise InvalidSessionTokenError(
            "cookie header does not contain a supported session token"
        )

    return value.strip().strip('"')


def _b64url_json(segment: str) -> dict[str, Any]:
    padding = "=" * (-len(segment) % 4)
    decoded = base64.urlsafe_b64decode(segment + padding)
    payload = json.loads(decoded.decode("utf-8"))
    return payload if isinstance(payload, dict) else {}


def extract_claims(access_token: str) -> TokenClaims:
    """Decode JWT claims for display.

    Signature verification is intentionally not performed.
    """

    try:
        parts = access_token.split(".")
        if len(parts) < 2:
            return TokenClaims()
        payload = _b64url_json(parts[1])

        profile = payload.get("https://api.openai.com/profile")
        auth = payload.get("https://api.openai.com/auth")
        profile = profile if isinstance(profile, dict) else {}
        auth = auth if isinstance(auth, dict) else {}

        email = profile.get("email") or payload.get("email")
        user_id = auth.get("user_id") or payload.get("user_id")
        account_id = auth.get("chatgpt_account_id") or payload.get("chatgpt_account_id")
        plan_type = auth.get("chatgpt_plan_type") or payload.get("chatgpt_plan_type")

        expires_at = None
        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)

        return TokenClaims(
            email=str(email) if email else None,
            user_id=str(user_id) if user_id else None,
            account_id=str(account_id) if account_id else None,
            plan_type=str(plan_type) if plan_type else None,
            expires_at=expires_at,
        )
    except (
        ValueError,
        TypeError,
        OverflowError,
        OSError,
        UnicodeDecodeError,
        binascii.Error,
    ):
        return TokenClaims()
