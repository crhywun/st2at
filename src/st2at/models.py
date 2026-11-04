"""Small, serializable value objects for the refresh result."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """Useful claims decoded from the new access token without signature checks."""

    email: str | None = None
    user_id: str | None = None
    account_id: str | None = None
    plan_type: str | None = None
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class RefreshResult:
    """Result of one session-token exchange.

    ``session_token`` is the rotated cookie value returned by the upstream
    endpoint. ``None`` means the endpoint did not rotate it, so the caller
    should keep using the original value.
    """

    access_token: str
    session_token: str | None = None
    id_token: str | None = None
    claims: TokenClaims = field(default_factory=TokenClaims)
    upstream_status: int = 200

    def to_dict(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "session_token": self.session_token,
            "id_token": self.id_token,
            "token_type": "Bearer",
            "email": self.claims.email,
            "user_id": self.claims.user_id,
            "account_id": self.claims.account_id,
            "plan_type": self.claims.plan_type,
            "expires_at": (
                self.claims.expires_at.isoformat()
                if self.claims.expires_at is not None
                else None
            ),
        }
