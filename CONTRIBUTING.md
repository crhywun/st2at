# Contributing

Keep changes focused on the single ST -> AT operation.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Tests

```bash
pytest -q
```

The suite uses fake HTTP sessions and never contacts ChatGPT.

## Pull requests

- Add or update a test for every behavior change.
- Keep the public surface small: `ST2ATClient.refresh()`, `st2at refresh`, and `POST /v1/refresh`.
- Do not put real session tokens or access tokens in commits, fixtures, logs, or issue text.
- Update `CHANGELOG.md` for user-visible changes.
