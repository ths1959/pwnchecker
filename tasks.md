# Implementation Tasks (Foundation -> Advanced)

## Status Notes (Current Repo)
- Desktop UI is implemented (not deferred).
- Phase 5 is implemented as domain security posture checks (no key); email breach lookup is not included.

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
- Implement derived identifier hash cache tables and repository:
  - per provider, versioned (normalization + hashing algorithm versions)
  - invalidation on identifier change
- Add tests:
  - encrypt/decrypt round-trip
  - wrong password fails
  - DB CRUD for accounts
  - cache invalidation/version bump recompute behavior

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
- Integrate cache into check pipeline:
  - derive hashes only when missing/invalidated
  - update last_checked_at_by_provider
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

## Phase 5: Domain Security Posture Checks (No-Key)
- Implement DNS-based posture checks for email domains (MX/SPF/DMARC).
- Add intuitive user-facing messages and recommended actions.
- Run posture checks as part of `Check Now` and persist results per run.
- Add tests (mock DNS resolver).

## Phase 6: Reporting Polish
- Improve report formatting (textual report output).
- Add run summary header (OK/Attention/Unknown/Error/Skipped counts).
- Add severity grouping (Error/Unknown/Attention/Skipped/OK).
- Add "Issues only" filter toggle in Reports.
- Add "New since last run" deltas (password exposure count changes; domain posture changes).

## Phase 7: Non-Blocking Checks UX
- Run `Check Now` in a background thread (no UI freeze).
- Show progress in the status bar (`Processing (i/n) - ...`).
- Add `Cancel` to stop an in-progress run (partial results preserved).
- Ensure no cross-thread SQLite connection use (open DB in worker thread).
- Update GUI integration tests to wait for async completion.

## Phase 8: Optional Desktop UI (Future Track)
- Decide UI framework (Tauri/Electron) and shared core library strategy.
- Build minimal screens: Unlock, Accounts, Check, Report.
- Ensure identical encryption/storage behavior via shared core.
