import base64
import json
from typing import Any

import pytest

from st2at.client import ST2ATClient
from st2at.errors import (
    ExpiredAccessTokenError,
    InvalidWorkspaceError,
    RateLimitedError,
    SessionRefreshError,
    SessionRejectedError,
    UpstreamHTTPError,
    UpstreamResponseError,
    UpstreamTransportError,
)


def b64(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_at(email: str = "user@example.com") -> str:
    payload = {
        "exp": 2_000_000_000,
        "https://api.openai.com/profile": {"email": email},
        "https://api.openai.com/auth": {
            "chatgpt_account_id": "account-9",
            "chatgpt_plan_type": "team",
        },
    }
    return f"{b64({'alg': 'RS256'})}.{b64(payload)}.signature"


class FakeResponse:
    def __init__(self, status_code: int, payload: Any, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeSession:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.get_calls: list[tuple[str, dict[str, str]]] = []
        self.closed = False

    async def get(self, url: str, headers: dict[str, str]) -> FakeResponse:
        self.get_calls.append((url, headers))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    async def close(self) -> None:
        self.closed = True


class FakeFactory:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.kwargs: dict[str, Any] | None = None
        self.session: FakeSession | None = None

    def __call__(self, **kwargs: Any) -> FakeSession:
        self.kwargs = kwargs
        self.session = FakeSession(self.response)
        return self.session


@pytest.mark.asyncio
async def test_refresh_posts_exact_protocol_and_parses_result():
    at = make_at()
    factory = FakeFactory(
        FakeResponse(
            200,
            {"accessToken": at, "sessionToken": "new-st", "idToken": "new-id"},
        )
    )
    client = ST2ATClient(
        base_url="https://chatgpt.example/",
        proxy="http://proxy.example:8080",
        timeout=12,
        verify_tls=False,
        session_factory=factory,
    )

    result = await client.refresh("old-st", workspace_id="workspace-7")

    assert result.access_token == at
    assert result.session_token == "new-st"
    assert result.id_token == "new-id"
    assert result.claims.email == "user@example.com"
    assert result.claims.account_id == "account-9"
    assert result.claims.plan_type == "team"
    assert result.upstream_status == 200

    assert factory.kwargs == {
        "proxy": "http://proxy.example:8080",
        "impersonate": "chrome150",
        "timeout": 12.0,
        "verify": False,
    }
    assert factory.session is not None and factory.session.closed
    url, headers = factory.session.get_calls[0]
    assert url == (
        "https://chatgpt.example/api/auth/session"
        "?exchange_workspace_token=true&workspace_id=workspace-7&reason=setCurrentAccount"
    )
    assert headers["Cookie"] == "__Secure-next-auth.session-token=old-st"
    assert headers["Referer"] == "https://chatgpt.com/"
    assert "image/avif" in headers["Accept"]


@pytest.mark.asyncio
async def test_without_workspace_uses_plain_endpoint_and_cookie_header_input():
    factory = FakeFactory(FakeResponse(200, {"accessToken": make_at()}))
    client = ST2ATClient(session_factory=factory)

    result = await client.refresh(
        "__Secure-next-auth.session-token=cookie-st; other=ignored"
    )

    assert result.session_token is None
    assert factory.session is not None
    url, headers = factory.session.get_calls[0]
    assert url == "https://chatgpt.com/api/auth/session"
    assert headers["Cookie"] == "__Secure-next-auth.session-token=cookie-st"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "expected", "code"),
    [
        (401, SessionRejectedError, "session_rejected"),
        (403, SessionRejectedError, "session_rejected"),
        (429, RateLimitedError, "upstream_rate_limited"),
        (500, UpstreamHTTPError, "upstream_http_error"),
    ],
)
async def test_maps_upstream_statuses(status, expected, code):
    factory = FakeFactory(FakeResponse(status, {"detail": "nope"}))
    client = ST2ATClient(session_factory=factory)
    with pytest.raises(expected) as caught:
        await client.refresh("st-value")
    assert caught.value.code == code
    assert f"HTTP {status}" in caught.value.message


@pytest.mark.asyncio
async def test_rejects_success_body_without_access_token():
    client = ST2ATClient(
        session_factory=FakeFactory(FakeResponse(200, {"detail": "no token"}))
    )
    with pytest.raises(UpstreamResponseError, match="accessToken"):
        await client.refresh("st-value")


@pytest.mark.asyncio
async def test_rejects_non_json_success_body():
    client = ST2ATClient(
        session_factory=FakeFactory(FakeResponse(200, ValueError("not json")))
    )
    with pytest.raises(UpstreamResponseError, match="non-JSON"):
        await client.refresh("st-value")


@pytest.mark.asyncio
async def test_wraps_transport_failure_and_closes_session():
    factory = FakeFactory(RuntimeError("connection reset"))
    client = ST2ATClient(session_factory=factory)
    with pytest.raises(UpstreamTransportError, match="RuntimeError"):
        await client.refresh("st-value")
    assert factory.session is not None and factory.session.closed


@pytest.mark.asyncio
async def test_rejects_bad_workspace_id_before_opening_session():
    factory = FakeFactory(FakeResponse(200, {"accessToken": make_at()}))
    client = ST2ATClient(session_factory=factory)
    with pytest.raises(InvalidWorkspaceError):
        await client.refresh("st-value", workspace_id="../etc/passwd")
    assert factory.session is None


@pytest.mark.asyncio
async def test_wraps_session_creation_failure():
    def explode(**kwargs):
        raise ValueError("bad impersonate profile")

    client = ST2ATClient(session_factory=explode)
    with pytest.raises(UpstreamTransportError, match="could not create HTTP session"):
        await client.refresh("st-value")


@pytest.mark.asyncio
async def test_rejects_expired_access_token_returned_with_http_200():
    expired = f"{b64({'alg': 'RS256'})}.{b64({'exp': 1})}.signature"
    client = ST2ATClient(
        session_factory=FakeFactory(FakeResponse(200, {"accessToken": expired}))
    )
    with pytest.raises(ExpiredAccessTokenError, match="expired accessToken"):
        await client.refresh("st-value")


@pytest.mark.asyncio
async def test_reports_upstream_refresh_access_token_error():
    client = ST2ATClient(
        session_factory=FakeFactory(
            FakeResponse(
                200,
                {
                    "accessToken": make_at(),
                    "error": "RefreshAccessTokenError",
                },
            )
        )
    )
    with pytest.raises(SessionRefreshError, match="RefreshAccessTokenError"):
        await client.refresh("st-value")
