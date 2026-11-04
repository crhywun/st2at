from datetime import datetime, timezone

from fastapi.testclient import TestClient

from st2at.api import create_app
from st2at.errors import SessionRejectedError
from st2at.models import RefreshResult, TokenClaims


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self.error: Exception | None = None

    async def refresh(self, session_token: str, *, workspace_id=None) -> RefreshResult:
        self.calls.append((session_token, workspace_id))
        if self.error is not None:
            raise self.error
        return RefreshResult(
            access_token="at-value",
            session_token="new-st",
            id_token="id-value",
            claims=TokenClaims(
                email="user@example.com",
                account_id="account-1",
                plan_type="team",
                expires_at=datetime(2033, 5, 18, 3, 33, 20, tzinfo=timezone.utc),
            ),
        )


def test_refresh_endpoint_returns_tokens_and_no_store_header():
    fake = FakeClient()
    app = create_app(fake)
    with TestClient(app) as client:
        response = client.post(
            "/v1/refresh",
            json={"session_token": "st-value", "workspace_id": "ws-1"},
        )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    payload = response.json()
    assert payload["access_token"] == "at-value"
    assert payload["session_token"] == "new-st"
    assert payload["email"] == "user@example.com"
    assert payload["expires_at"].startswith("2033-05-18T03:33:20")
    assert fake.calls == [("st-value", "ws-1")]


def test_refresh_endpoint_maps_typed_error():
    fake = FakeClient()
    fake.error = SessionRejectedError("ChatGPT rejected the session token (HTTP 403)")
    app = create_app(fake)
    with TestClient(app) as client:
        response = client.post("/v1/refresh", json={"session_token": "bad-st"})

    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "session_rejected",
            "message": "ChatGPT rejected the session token (HTTP 403)",
        }
    }


def test_request_schema_rejects_extra_fields():
    app = create_app(FakeClient())
    with TestClient(app) as client:
        response = client.post(
            "/v1/refresh",
            json={"session_token": "st-value", "unexpected": "field"},
        )
    assert response.status_code == 422


def test_index_and_health():
    app = create_app(FakeClient())
    with TestClient(app) as client:
        index = client.get("/")
        health = client.get("/healthz")
    assert index.status_code == 200
    assert "ST 刷新 AT" in index.text
    assert health.json()["status"] == "ok"
