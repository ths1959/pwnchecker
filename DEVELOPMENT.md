# Development Guide

## 1. Project Principles
- Local-first by default.
- Privacy is a feature: minimal data collection, minimal network calls, explicit consent.
- Cryptography is done via well-reviewed libraries; no custom crypto.
- Deterministic behavior: runs are stored, reportable, and diffable.

## 2. Project Coding Rules
- Prefer small, testable functions.
- No secrets in logs. Ever.
- No network in unit tests (mock).
- Keep CLI output stable (treat it like an API).
- Fail closed:
  - If decryption fails, do not continue with partial plaintext.
  - If API calls fail, mark results as incomplete and surface reasons.

## 3. Architecture Guidelines
- Layered design:
  1. cli/ command parsing and presentation only
  2. core/ domain logic (accounts, runs, policies)
  3. storage/ DB, migrations, encryption boundaries
  4. providers/ external API clients (HIBP, etc.)
- Encryption boundary:
  - Only storage/crypto.py (or equivalent) handles encrypt/decrypt.
  - Domain models carry decrypted data only in-memory, short-lived.
- Derived-data caching:
  - Implement a dedicated storage module for derived identifier cache entries (per provider, versioned).
  - Cache keys must be stable and non-secret (for example: account_id + provider + algo_version), but cached values must be treated as sensitive and stored in the encrypted DB unless proven non-sensitive.
  - Cache invalidation is part of the core logic (not a UI concern) and must be covered by tests.
- Provider clients return normalized domain objects; do not leak raw JSON into core logic.
- Configuration:
  - core/config.py loads non-sensitive settings
  - sensitive values are retrieved via a vault/secure store abstraction

## 4. Tech Stack Decisions (v1)
- Language: Python.
- Desktop UI: PySide6 (Qt).
- CLI framework: Typer (or Click) with rich prompts.
- HTTP: httpx.
- SQLite access: sqlite3 + thin repository layer (or SQLAlchemy later if needed).
- Crypto:
  - cryptography for AEAD
  - argon2-cffi for Argon2id KDF (preferred)
- Testing: pytest.
- Lint/format:
  - ruff (lint + import sorting)
  - black (or ruff format if adopting fully)
  - mypy (optional but recommended once types stabilize)

## 5. Folder Structure Conventions
- src/pwnchecker/
  - cli.py
  - gui.py
  - providers/
  - storage/
  - ui/
- tests/
  - unit/ (pure logic)
  - integration/ (DB + crypto, but no network)
- docs/ (optional, later)
- scripts/ (dev helpers only)

## 6. Testing/Linting Workflow
- Fast loop:
  - ruff check .
  - ruff format . (or black .)
  - pytest -q
- CI expectations (when added):
  - lint + format check
  - unit tests
  - integration tests (DB + encryption)
- Mock network calls:
  - use respx or pytest-httpx

## 7. Change Discipline
- Before touching code:
  1. Identify the user-facing behavior change.
  2. Add/adjust a test that captures it.
- When editing:
  - Keep changes scoped; avoid drive-by refactors.
  - Prefer adding new modules over growing god-files.
- After editing:
  - Run lint + tests.
  - Update docs if flags/commands/outputs changed.
- If a security-sensitive behavior changes:
  - Add a short "Security Notes" section to the PR/commit message (or to an internal changelog).

## 8. Security Checklist (v1)
- Master password is never stored.
- KDF parameters are stored (salt, time/memory cost) and versioned.
- AEAD nonces are unique and generated via CSPRNG.
- DB fields that are sensitive are encrypted individually (not just "encrypt the whole file").
- Cached derived identifier values are treated as sensitive by default and protected at rest.
- "Reveal" output requires an explicit CLI flag and an unlocked vault.
