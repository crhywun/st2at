import base64
import json
from datetime import timezone

import pytest

from st2at.errors import InvalidSessionTokenError
from st2at.token import extract_claims, normalize_session_token


def b64(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(payload: dict) -> str:
    return f"{b64({'alg': 'RS256'})}.{b64(payload)}.signature"


def test_accepts_raw_token():
    assert normalize_session_token("  eyJhbGciOiJSUzI1NiJ9.payload.sig  ") == (
        "eyJhbGciOiJSUzI1NiJ9.payload.sig"
    )


def test_extracts_from_full_cookie_header():
    raw = (
        "__Host-next-auth.csrf-token=csrf; "
        "__Secure-next-auth.session-token=session-value; "
        "other=value"
    )
    assert normalize_session_token(raw) == "session-value"


def test_accepts_cookie_prefix():
    raw = "Cookie: __Secure-next-auth.session-token=abc123; foo=bar"
    assert normalize_session_token(raw) == "abc123"


def test_joins_chunked_cookie_in_index_order():
    raw = (
        "__Secure-next-auth.session-token.1=world; "
        "__Secure-next-auth.session-token.0=hello-; "
        "foo=bar"
    )
    assert normalize_session_token(raw) == "hello-world"


def test_url_decodes_cookie_value():
    raw = "__Secure-next-auth.session-token=hello%2Bworld%3D"
    assert normalize_session_token(raw) == "hello+world="


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "__Host-next-auth.csrf-token=only-csrf",
        "bad\ntoken",
    ],
)
def test_rejects_empty_or_unrelated_cookie(value):
    with pytest.raises(InvalidSessionTokenError):
        normalize_session_token(value)


def test_extracts_common_chatgpt_claims():
    token = make_jwt(
        {
            "exp": 2_000_000_000,
            "https://api.openai.com/profile": {"email": "user@example.com"},
            "https://api.openai.com/auth": {
                "user_id": "user-1",
                "chatgpt_account_id": "account-1",
                "chatgpt_plan_type": "plus",
            },
        }
    )
    claims = extract_claims(token)
    assert claims.email == "user@example.com"
    assert claims.user_id == "user-1"
    assert claims.account_id == "account-1"
    assert claims.plan_type == "plus"
    assert claims.expires_at.tzinfo == timezone.utc


def test_bad_jwt_returns_empty_claims():
    assert extract_claims("not-a-jwt").email is None
    assert extract_claims("a.%%%.c").email is None
