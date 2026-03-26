# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## 1.0.0 – 2026-03-25

Initial public release.

### Added

- Wodle for 1Password Events API v2 with three event streams: audit events, sign-in attempts, item usage.
- Cursor-based pagination with automatic state tracking.
- Multi-tenant / MSP mode via `OP_TOKENS_FILE`.
- Startup introspect call to validate bearer token and discover authorized features.
- Automatic single-retry on 429 rate limit with `Retry-After` header.
- Wazuh decoder and 45 detection rules (IDs 100700-100799).
- Secure credential chain: systemd > .secrets file > environment variable.
- Configuration, rules reference, and troubleshooting guides.
