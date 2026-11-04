import json
from typing import ClassVar

from st2at import cli
from st2at.errors import SessionRejectedError
from st2at.models import RefreshResult


class FakeClient:
    result: RefreshResult | None = None
    error: Exception | None = None
    seen: ClassVar[list[tuple[str, str | None]]] = []

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs

    async def refresh(self, token: str, *, workspace_id=None) -> RefreshResult:
        self.seen.append((token, workspace_id))
        if self.error is not None:
            raise self.error
        return self.result


def test_cli_json_output(monkeypatch, capsys):
    FakeClient.result = RefreshResult(access_token="at-value", session_token="st-new")
    FakeClient.error = None
    monkeypatch.setattr(cli, "ST2ATClient", FakeClient)

    code = cli.main(["refresh", "--st", "st-old", "--workspace-id", "ws-1", "--json"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["access_token"] == "at-value"
    assert payload["session_token"] == "st-new"


def test_cli_typed_error_exit_code(monkeypatch, capsys):
    FakeClient.error = SessionRejectedError("rejected")
    monkeypatch.setattr(cli, "ST2ATClient", FakeClient)

    code = cli.main(["refresh", "--st", "bad"])

    assert code == 3
    captured = capsys.readouterr()
    assert "[session_rejected]" in captured.err
