# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-11-04

### Added

- `ST2ATClient.refresh()` for the ChatGPT ST -> AT exchange
- CLI: `st2at refresh`
- HTTP API: `POST /v1/refresh`
- Self-contained single-page interface at `/`
- Cookie-header normalization, including chunked NextAuth cookies
- Optional workspace token exchange
- JWT claim display (email, account id, plan, expiry)
- Offline test suite, Docker image, Compose file, and CI
