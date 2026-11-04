"""The single protocol operation: ChatGPT ST -> AT."""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

from .errors import (
    InvalidWorkspaceError,
    RateLimitedError,
    SessionRejectedError,
    UpstreamHTTPError,
    UpstreamResponseError,
    UpstreamTransportError,
)
from .models import RefreshResult
from .token import extract_claims, normalize_session_token

DEFAULT_BASE_URL = "https://chatgpt.com"
SESSION_PATH = "/api/auth/session"
DEFAULT_IMPERSONATE = "chrome110"

_WORKSPACE_RE = re.compile(r"^[A-Za-z0-9_-]{1,200}$")
_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,image/apng,*/*;q=0.8"
)

SessionFactory = Callable[..., Any]


def _nonempty_str(value: Any) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _safe_detail(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    detail = payload.get("detail")
    if isinstance(detail, str) and detail.strip():
        return detail.strip()[:300]
    error = payload.get("error")
    if isinstance(error, str) and error.strip():
        return error.strip()[:300]
    if isinstance(error, dict):
        message = error.get("message") or error.get("code")
        if isinstance(message, str) and message.strip():
            return message.strip()[:300]
    return None


class ST2ATClient:
    """Call ``GET /api/auth/session`` with the NextAuth session cookie.

    One client instance is stateless and safe to reuse across requests. Each
    call creates and closes its own curl_cffi session, which avoids sharing a
    browser fingerprint or cookie jar between different STs.
    """

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        proxy: str | None = None,
        impersonate: str = DEFAULT_IMPERSONATE,
        timeout: float = 30.0,
        verify_tls: bool = True,
        session_factory: SessionFactory | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.proxy = proxy or None
        self.impersonate = impersonate
        self.timeout = float(timeout)
        self.verify_tls = bool(verify_tls)
        self._session_factory = session_factory

    def _open_session(self) -> Any:
        if self._session_factory is not None:
            return self._session_factory(
                proxy=self.proxy,
                impersonate=self.impersonate,
                timeout=self.timeout,
                verify=self.verify_tls,
            )

        from curl_cffi.requests import AsyncSession

        proxies = (
            {"all": self.proxy, "http": self.proxy, "https": self.proxy}
            if self.proxy
            else None
        )
        return AsyncSession(
            impersonate=self.impersonate,
            proxies=proxies,
            timeout=self.timeout,
            verify=self.verify_tls,
            trust_env=False,
        )

    async def _close_session(self, session: Any) -> None:
        close = getattr(session, "close", None)
        if close is None:
            return
        try:
            result = close()
            if inspect.isawaitable(result):
                await result
        except Exception:
            # A close failure must not hide a successful token exchange.
            pass

    def build_url(self, workspace_id: str | None = None) -> str:
        url = f"{self.base_url}{SESSION_PATH}"
        if workspace_id:
            query = urlencode(
                [
                    ("exchange_workspace_token", "true"),
                    ("workspace_id", workspace_id),
                    ("reason", "setCurrentAccount"),
                ]
            )
            url = f"{url}?{query}"
        return url

    def build_headers(self, session_token: str) -> dict[str, str]:
        return {
            "Accept": _ACCEPT,
            "Accept-Language": "en-US,en;q=0.9",
            "Cookie": f"__Secure-next-auth.session-token={session_token}",
            "Referer": "https://chatgpt.com/",
            "Connection": "keep-alive",
        }

    async def refresh(
        self,
        session_token: str,
        *,
        workspace_id: str | None = None,
    ) -> RefreshResult:
        """Exchange one session token for a fresh access token.

        Args:
            session_token: Raw ``__Secure-next-auth.session-token`` value, or
                a full ``Cookie:`` header from which the value is extracted.
            workspace_id: Optional workspace/account id. When present the
                request asks ChatGPT to exchange the token for that workspace.
        """

        token = normalize_session_token(session_token)
        if workspace_id is not None:
            workspace_id = workspace_id.strip()
            if not workspace_id:
                workspace_id = None
            elif not _WORKSPACE_RE.fullmatch(workspace_id):
                raise InvalidWorkspaceError(
                    "workspace_id may contain only letters, digits, '_' and '-'"
                )

        url = self.build_url(workspace_id)
        headers = self.build_headers(token)
        try:
            session = self._open_session()
        except Exception as exc:
            raise UpstreamTransportError(
                f"could not create HTTP session: {type(exc).__name__}"
            ) from exc

        try:
            try:
                response = await session.get(url, headers=headers)
            except Exception as exc:
                raise UpstreamTransportError(
                    f"request to ChatGPT failed: {type(exc).__name__}"
                ) from exc

            status = int(getattr(response, "status_code", 0) or 0)
            payload: Any = None
            try:
                payload = response.json()
            except Exception:
                payload = None

            if 200 <= status < 300:
                if not isinstance(payload, dict):
                    raise UpstreamResponseError(
                        "ChatGPT returned a non-JSON response for the session endpoint"
                    )
                access_token = _nonempty_str(
                    payload.get("accessToken") or payload.get("access_token")
                )
                if not access_token:
                    detail = _safe_detail(payload)
                    suffix = f": {detail}" if detail else ""
                    raise UpstreamResponseError(
                        f"ChatGPT response did not include accessToken{suffix}"
                    )

                return RefreshResult(
                    access_token=access_token,
                    session_token=_nonempty_str(
                        payload.get("sessionToken") or payload.get("session_token")
                    ),
                    id_token=_nonempty_str(
                        payload.get("idToken") or payload.get("id_token")
                    ),
                    claims=extract_claims(access_token),
                    upstream_status=status,
                )

            detail = _safe_detail(payload)
            suffix = f": {detail}" if detail else ""
            if status in {401, 403}:
                raise SessionRejectedError(
                    f"ChatGPT rejected the session token (HTTP {status}){suffix}"
                )
            if status == 429:
                raise RateLimitedError(
                    f"ChatGPT rate-limited the exchange (HTTP 429){suffix}"
                )
            raise UpstreamHTTPError(
                f"ChatGPT returned HTTP {status}{suffix}", upstream_status=status
            )
        finally:
            await self._close_session(session)
