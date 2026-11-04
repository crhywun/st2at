# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- Default browser fingerprint is now `chrome150` for the Chrome 146–150 range
- Minimum `curl-cffi` version is now `0.16.3`
- BestGo/711 bare proxy parsing with `-region-XX` and `-session-XXX` markers
- A fresh sticky proxy session is generated for every refresh request
- Reject an upstream 200 response when its `accessToken` is already expired

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
