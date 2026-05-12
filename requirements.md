# Personal Breach Checker (Local-First)

## 1. Summary
A local CLI (and optional desktop UI later) that helps you monitor your own accounts for compromise signals while keeping your account list encrypted on disk. The tool supports privacy-preserving checks using k-anonymity where the upstream API supports it (notably Pwned Passwords). Email breach lookups are supported only as an explicit opt-in because common breach APIs require sending the full email address.

## 2. Goals / Non-Goals

### Goals
- Store a personal list of accounts (email/username + optional metadata) in an encrypted local database.
- Run periodic checks and show what changed since the last run.
- Use k-anonymity for checks that support it (for example, password hash range queries).
- Never store raw passwords; only allow optional password hash material necessary for k-anonymity checks.
- Provide clear, actionable results (what is at risk, what to do next).

### Non-Goals (v1)
- Password manager replacement.
- Automatic password rotation.
- Continuous background monitoring (scheduled jobs can be added later).
- Sharing/syncing data between devices.

## 3. Primary Users
- A single user running the tool locally for their own accounts.
- Security-conscious student/practitioner who wants a portfolio-grade privacy-first project.

## 4. Key Concepts
- Account: A record representing a login identity (email or username) and optional notes (service name, URL, tags).
- Check Run: A timestamped execution that produces results and deltas.
- k-anonymity check (Passwords): SHA-1 of a secret (password) is computed locally; only the first 5 hex chars are sent; the API returns suffixes; matching occurs locally.
- Email breach lookup (Opt-in): If enabled, calls a breach API endpoint that requires the full email address (no k-anonymity). This must be explicit and clearly labeled.

## 5. Features (v1)

### 5.1 Data & Security
- Encrypted local database (SQLite + application-layer encryption).
- Master password to unlock; optional OS keychain integration later.
- Account fields:
  - service_name (required)
  - identifier_type = email|username (required)
  - identifier_value (required; encrypted at rest)
  - url (optional)
  - tags (optional)
  - created_at, updated_at
- Local-only export/import (encrypted).

### 5.2 CLI Commands
- init: initialize vault (create DB, set master password).
- add: add an account.
- list: list accounts (redacted by default).
- show <id>: show one account (requires explicit --reveal for identifier).
- remove <id>
- check: run breach checks and store results.
- report: show latest results + diffs from previous run.
- history: list previous runs.
- config: set API key, toggles, rate limits.

### 5.3 Checking Capabilities

1) Pwned Passwords (k-anonymity) (default ON if user provides a "secret to check")
- User can provide per-account a password to check at run-time (interactive prompt) or store a derived token:
  - Preferred: prompt at check time (no secret stored).
  - Optional: store a salted hash for local correlation only, but still compute SHA-1 from provided password at runtime for the API query.
- Output: pwn count (if returned), risk level.

2) Email breach lookup (explicit opt-in) (default OFF)
- Requires API key and consent: "This sends your full email address to the provider."
- Output: breached sites, breach dates (if provided), exposed data classes.

### 5.4 Result Management
- Persist results per run:
  - per account: password-pwned status, email-breached status (if enabled), provider breach identifiers, counts, timestamps.
- Delta detection:
  - new breaches since last run
  - newly pwned password counts increased (if applicable)

## 6. User Flows

### 6.1 First-Time Setup
1. User runs `breach-checker init`
2. Tool prompts for master password (confirm)
3. Tool creates encrypted DB and config file
4. Tool offers to set API key and choose privacy options (email lookup OFF by default)

### 6.2 Add Accounts
1. `breach-checker add`
2. Prompts: service name, identifier type, identifier value, optional URL/tags
3. Saves encrypted record

### 6.3 Monthly Check (Recommended)
1. `breach-checker check`
2. Tool unlocks vault (master password)
3. If password checks enabled: prompts for each account's password (with "skip" option) or allows targeting accounts
4. Runs checks, records results
5. Displays summary: new issues + suggested actions

### 6.4 View Report
1. `breach-checker report`
2. Shows latest run summary and per-account statuses
3. Optionally `--since <date/run_id>` for diffs

## 7. Screens (CLI "Screens")
- Setup screen (init wizard)
- Add account prompt flow
- Check progress + per-account status lines
- Report table:
  - Service | Identifier (redacted) | Password pwned? | Email breached? | New since last | Notes

(Desktop UI later mirrors these views: Vault Unlock, Accounts, Check Run, Report Detail, Settings.)

## 8. Technical Requirements

### 8.1 Platform
- Windows/macOS/Linux.
- Python 3.12+ (or 3.11+ if constraints arise).

### 8.2 Storage
- SQLite database file in a user config directory.
- Application-layer encryption for sensitive fields (identifier_value).
- Config stored separately (non-secret settings). Secrets (API keys) encrypted or stored in OS keychain (future); for v1, encrypt in DB or a dedicated encrypted secrets file.

### 8.3 Crypto Requirements
- Use a modern KDF for master password (Argon2id preferred; PBKDF2 only if necessary).
- Use authenticated encryption (AES-GCM or ChaCha20-Poly1305).
- Use constant-time comparisons where appropriate.
- Never log secrets, identifiers, or full hashes.

### 8.4 Network
- Timeouts, retry policy (bounded), rate limiting.
- Clear user agent string.
- Respect provider terms (API key usage, rate limits).

### 8.5 Observability
- Verbose logging mode that never prints decrypted identifiers unless explicitly requested.
- Structured run results stored locally for auditability.

## 9. Edge Cases & Failure Modes
- Wrong master password / corrupted vault.
- Duplicate accounts (same service + identifier): warn and prevent unless `--force`.
- User cancels password prompt mid-run: partial results still saved as "skipped".
- API unavailable / rate limited: mark run as incomplete, retry guidance.
- Clock changes / timezone issues affecting "since last run" comparisons.
- Large account lists: progress indicator and batching.
- Email breach lookup disabled but user expects it: report must clearly show "Email lookup: OFF".

## 10. Future Improvements
- Desktop UI (Tauri/Electron) with the same local vault.
- OS keychain integration for API key and/or vault unlock token.
- Scheduling:
  - Windows Task Scheduler / cron helpers
- Rich filters:
  - `report --only-new`, `--tag`, `--service`
- Safer password check UX:
  - minimize in-memory time, optional clipboard warnings
- Multiple vault profiles.
- Import from password managers (CSV) with local-only mapping and field redaction.
- Local-only compromise heuristics:
  - detect reused passwords via local hashing (no network), without storing raw passwords.

