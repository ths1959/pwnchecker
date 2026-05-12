# PwnChecker (Local-First)

## 1. Summary
PwnChecker is a local desktop app (with a CLI available for automation later) that monitors an encrypted account list for compromise signals. The app provides local "storage" for a list of emails/usernames plus a single "Check Now" button that runs the full process end-to-end and produces a report. The tool supports privacy-preserving checks using k-anonymity where the upstream API supports it (notably Pwned Passwords). Email breach lookups are supported only as an explicit opt-in because common breach APIs require sending the full email address.

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
- A single user running PwnChecker locally for a personal account list.
- Security-conscious student/practitioner who wants a portfolio-grade privacy-first project.

## 4. Key Concepts
- Account: A record representing a login identity (email or username) and optional notes (service name, URL, tags).
- Check Run: A timestamped execution that produces results and deltas.
- k-anonymity check (Passwords): SHA-1 of a secret (password) is computed locally; only the first 5 hex chars are sent; the API returns suffixes; matching occurs locally.
- Email breach lookup (Opt-in): If enabled, calls a breach API endpoint that requires the full email address (no k-anonymity). This must be explicit and clearly labeled.
- Hash Cache: A local cache that stores derived identifier hashes (and per-provider query material) so repeated runs can skip recomputation and avoid re-sending the same derived values when nothing changed.

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
- Cached derived values (encrypted or non-sensitive by design, depending on value type):
  - identifier_normalized (derived)
  - identifier_hashes_by_provider (derived)
  - last_checked_at_by_provider (derived)
- Local-only export/import (encrypted).

### 5.2 Desktop App (Primary UI)
- Encrypted local storage UI:
  - Add/edit/remove account entries (service + email/username).
  - List view with search/filter and redaction by default.
- Single-action run button:
  - "Check Now" runs all enabled checks against all stored accounts, persists a new run, and refreshes the report view.
  - Uses a local hash cache so identifiers already processed can skip re-hashing and (when supported) skip re-sending derived query material if nothing changed.
- Settings:
  - Configure API key(s), privacy toggles (email lookup off by default), rate limits, and timeouts.
- Report:
  - Latest run summary, per-account details, and "what changed since last run".

### 5.3 CLI Commands (Secondary / Automation-Friendly)
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
- Requires API key and consent: "This sends the full email address to the provider."
- Output: breached sites, breach dates (if provided), exposed data classes.

### 5.4 Caching (Derived Identifier Cache)
- Purpose:
  - Reduce repeated computation (normalization + hashing) across runs.
  - Avoid re-sending derived query material for unchanged identifiers when the provider/query style supports it.
- Scope:
  - Cache stores only derived values (hashes/prefixes) and metadata (provider name, algorithm version, last-checked timestamp).
  - Cache must not enable reconstructing the plaintext identifier without the vault key (store inside the encrypted DB unless clearly non-sensitive).
- Invalidation rules:
  - If identifier_value changes: invalidate all cached entries for that account.
  - If normalization rules change (versioned): invalidate and recompute.
  - If provider algorithm or request format changes (versioned): invalidate and recompute.
  - If user disables a provider: retain cache but do not use it for calls.

### 5.5 Result Management
- Persist results per run:
  - per account: password-pwned status, email-breached status (if enabled), provider breach identifiers, counts, timestamps.
- Delta detection:
  - new breaches since last run
  - newly pwned password counts increased (if applicable)

## 6. User Flows

### 6.1 First-Time Setup (Desktop)
1. User opens the app.
2. App prompts to create/unlock the vault with a master password (confirm on create).
3. App creates encrypted DB and settings.
4. App opens Settings to set API key and choose privacy options (email lookup OFF by default).

### 6.2 Maintain Account Storage (Desktop)
1. User navigates to Accounts.
2. User adds/edits entries: service name, identifier type, identifier value, optional URL/tags.
3. App saves encrypted records and shows them in the list (redacted by default).

### 6.3 Monthly Check (Recommended, One Button)
1. User clicks "Check Now".
2. App unlocks vault if needed (master password).
3. App loads hash cache and determines which identifiers need re-derivation (based on invalidation/version rules).
4. If password checks enabled: app prompts for each account's password (with "skip" option) or allows targeting accounts.
5. App runs checks, records results as a new run, and updates the cache metadata.
5. App displays a summary: new issues + suggested actions.

### 6.4 View Report (Desktop)
1. User navigates to Reports.
2. App shows latest run summary and per-account statuses.
3. User can switch to a previous run to see diffs.

## 7. Screens (Desktop App)
- Vault unlock / create vault
- Accounts (storage):
  - Table/list view with add/edit/remove
  - Redacted identifiers by default; reveal requires explicit action while unlocked
- Check:
  - "Check Now" button
  - Progress and per-account status lines
  - Optional password prompts (skip supported)
- Reports:
  - Run selector (latest by default)
  - Report table: Service | Identifier (redacted) | Password pwned? | Email breached? | New since last | Notes
- Settings:
  - API keys, privacy toggles, rate limits/timeouts

## 7.1 CLI "Screens" (Secondary)
- Setup screen (init wizard)
- Add account prompt flow
- Check progress + per-account status lines
- Report table (same columns as desktop)

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
