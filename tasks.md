# Implementation Tasks (Foundation -> Advanced)

## Phase 0: Repo & Tooling Foundation
- Create src/ package skeleton with importable module.
- Add dependency management (pyproject.toml) and basic CLI entrypoint.
- Add lint/format/test config (ruff, formatter, pytest).
- Add a minimal --help CLI and a smoke test.

## Phase 1: Vault + Storage
- Define domain models: Account, Run, Result.
- Implement SQLite schema + migrations strategy (even if v1 uses auto-create).
- Implement master password setup:
  - KDF derivation
  - key material handling
  - vault unlock
- Implement encryption helpers and field-level encryption for identifiers.
- Add tests:
  - encrypt/decrypt round-trip
  - wrong password fails
  - DB CRUD for accounts

## Phase 2: Core Account Management Commands
- Implement init.
- Implement add/list/show/remove.
- Redaction defaults:
  - list/show redact identifier unless --reveal.
- Add tests for CLI parsing and repository behavior.

## Phase 3: Check Runs + Result Persistence
- Implement run table + per-account result table.
- Implement check that:
  - unlocks vault
  - iterates accounts
  - records skipped/failed states
- Implement history and report (latest run summary).
- Add delta logic between runs and tests for diff correctness.

## Phase 4: Provider Integration (k-anonymity Password Checks)
- Implement provider client for password range API:
  - local SHA-1
  - prefix query
  - suffix match and count extraction
- Implement CLI UX for password input per account (secure prompt, skip).
- Store only what is needed for reporting (counts, timestamps), not secrets.
- Add unit tests for parsing and matching; integration tests with mocked HTTP.

## Phase 5: Optional Email Breach Lookup (Explicit Opt-In)
- Add config flag email_lookup_enabled default OFF.
- Add API key storage strategy (encrypted).
- Implement provider client for email breach endpoint (only when enabled).
- Add UX copy that clearly states "full email is sent".
- Add tests ensuring disabled mode never calls network.

## Phase 6: Reporting Polish
- Improve report formatting (stable columns, sorting).
- Add filters: --only-new, --tag, --service.
- Add exit codes:
  - 0 no new issues
  - 1 new issues found
  - 2 run incomplete / errors
- Add snapshot tests for report output stability.

## Phase 7: Hardening & DX
- Add rate limiting + retry/backoff controls.
- Add structured logging and --verbose.
- Add corruption recovery guidance (detect + actionable error messages).
- Add import/export (encrypted) with tests.

## Phase 8: Optional Desktop UI (Future Track)
- Decide UI framework (Tauri/Electron) and shared core library strategy.
- Build minimal screens: Unlock, Accounts, Check, Report.
- Ensure identical encryption/storage behavior via shared core.

