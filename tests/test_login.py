import json

from st2at import cli
from st2at import login as login_module
from st2at.login import LoginResult


def test_wrapper_pins_proxy_region_and_maps_tokens(monkeypatch):
    seen = {}

    def fake_login(email, **kwargs):
        seen["email"] = email
        seen.update(kwargs)
        return {"ok": True, "access_token": "a.b.c", "st": "st-value"}

    monkeypatch.setattr(login_module, "_login_with_password_totp", fake_login)
    monkeypatch.setattr(
        login_module,
        "prepare_proxy",
        lambda proxy, region: f"{proxy}|{region}|fresh-session",
    )

    result = login_module.login_with_password_totp(
        "User@Example.com",
        password="pw",
        totp_secret="SECRET",
        proxy="proxy.example:1000:user:pass",
        region="JP",
        workspace_id="workspace-1",
    )

    assert result.ok is True
    assert result.email == "user@example.com"
    assert result.access_token == "a.b.c"
    assert result.session_token == "st-value"
    assert seen["proxy"] == "proxy.example:1000:user:pass|JP|fresh-session"
    assert seen["profile_region"] == "JP"
    assert seen["workspace_id"] == "workspace-1"


def test_wrapper_returns_typed_error(monkeypatch):
    def fake_login(email, **kwargs):
        raise RuntimeError("bad password")

    monkeypatch.setattr(login_module, "_login_with_password_totp", fake_login)
    result = login_module.login_with_password_totp(
        "user@example.com",
        password="pw",
        totp_secret="SECRET",
    )
    assert result.ok is False
    assert "bad password" in result.error


def test_wrapper_rejects_missing_totp():
    result = login_module.login_with_password_totp(
        "user@example.com",
        password="pw",
        totp_secret="",
    )
    assert result.ok is False
    assert "totp_secret" in result.error


def test_cli_login_json(monkeypatch, capsys):
    def fake_login(email, **kwargs):
        return LoginResult(
            ok=True,
            email=email,
            access_token="a.b.c",
            session_token="st-value",
        )

    monkeypatch.setattr("st2at.login.login_with_password_totp", fake_login)
    code = cli.main(
        [
            "login",
            "--email",
            "user@example.com",
            "--password",
            "pw",
            "--totp-secret",
            "SECRET",
            "--json",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["access_token"] == "a.b.c"
    assert payload["session_token"] == "st-value"


def test_cli_login_missing_credentials(capsys):
    code = cli.main(["login", "--email", "user@example.com"])
    assert code == 2
    assert "password is required" in capsys.readouterr().err
