# PwnChecker Developer Guide (Current Implementation)

This guide documents the repo as implemented now. For broader principles and longer-term rules, keep using `DEVELOPMENT.md`.

## Requirements
- Python 3.11+
- Windows/macOS/Linux (primary dev tested on Windows)

## Setup

```powershell
cd C:\Projects\PwnChecker
python -m pip install -e .[dev]
```

## Run

GUI:
```powershell
python -m pwnchecker.gui
```

Use a local data directory:
```powershell
$env:PWNCHECKER_DATA_DIR = "$pwd\.localdata"
python -m pwnchecker.gui
```

CLI:
```powershell
python -m pwnchecker --help
python -m pwnchecker init
```

## Tests and Lint

```powershell
python -m ruff check .
python -m pytest
```

Network calls are mocked in unit tests using `httpx.MockTransport`.

## Repo Layout (Actual)
- `src/pwnchecker/`
  - `cli.py` Typer CLI commands (vault + accounts).
  - `gui.py` Qt entrypoint; applies app stylesheet.
  - `ui/` Qt widgets and dialogs.
  - `storage/` SQLite schema + vault crypto + repositories.
  - `providers/` external check clients and local check modules.
- `tests/`
  - `unit/` provider parsing, vault/settings repos, etc.
  - `integration/` Qt smoke tests.

## Storage Model

SQLite schema is created in `src/pwnchecker/storage/db.py` and includes:
- `vault_meta`: KDF params + verifier.
- `accounts`: encrypted identifier fields; digest for de-duplication; timestamps.
- `runs`: run creation timestamp.
- `results`: per-run, per-account results as JSON.
- `hash_cache`: encrypted derived values (identifier SHA1, password SHA1, etc.), versioned per provider.
- `app_settings`: encrypted settings key/value store.

Sensitive fields are encrypted using AEAD (AES-GCM) with a key derived from the master password using Argon2id.

## Providers (Implemented)

### Pwned Passwords (HIBP, k-anonymity)
- `src/pwnchecker/providers/pwned_passwords.py`
- Computes `SHA1(password)` locally.
- Sends only the first 5 hex chars to the range endpoint and matches suffix locally.

### Domain Security Posture (No-Key)
- `src/pwnchecker/providers/domain_posture.py`
- Uses DNS (dnspython) for MX/TXT (SPF/DMARC).
- Produces a status + user-facing message.

## GUI Behavior Notes
- Vault dialog cancellation closes the application (no main window).
- Accounts batch delete uses checkbox column (not Qt row multi-select).
- Runs batch delete uses checkable items in the run list.
- Reports are rendered as plain text, derived from persisted `results`.
- Settings include:
  - report redaction toggle (applies immediately by re-rendering report)
  - remember password hash toggle (controls whether derived SHA1 is stored/used)
  - unsaved-changes indicator

## Adding a New Check
1. Create a provider module under `src/pwnchecker/providers/`.
2. Add a stable `provider` name string for persisted results.
3. In `MainWindow._on_check_now`, add:
   - result rows via `ResultRepo.add_result`
   - optional cache entries via `HashCacheRepo.upsert` (versioned)
4. Update `_format_result_line` to present an intuitive message.
5. Add unit tests for parsing/network behavior using `httpx.MockTransport` (if networked).

## Data Safety Notes
- Raw passwords are not stored.
- Optional password reuse stores `SHA1(password)` encrypted in `hash_cache`; this is a UX/security tradeoff controlled by a Settings toggle.

