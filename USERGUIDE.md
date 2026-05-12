# PwnChecker User Guide

## What PwnChecker Does
PwnChecker is a local desktop application that stores an account list in an encrypted vault and runs local checks:

- Password exposure check (HIBP Pwned Passwords, k-anonymity).
- Email domain security posture check (MX/SPF/DMARC via DNS).

Email breach membership lookup (searching whether a specific email appears in a breach) is not included.

## Install / Run

From the repository root:

```powershell
python -m pip install -e .[dev]
python -m pwnchecker.gui
```

For testing with a vault stored in a local folder:

```powershell
$env:PWNCHECKER_DATA_DIR = "$pwd\.localdata"
python -m pwnchecker.gui
```

`PWNCHECKER_DATA_DIR` controls where `vault.sqlite3` is created.

## Vault (Encrypted Storage)

On startup, PwnChecker prompts for a vault master password:

- If no vault exists: prompts to create a vault (password + confirmation).
- If a vault exists: prompts to unlock the vault.

Closing the vault dialog cancels startup (no main window is shown).

## Accounts

Accounts are stored in the vault and shown on the Accounts tab.

### Add / Edit / Delete
- Add: creates a new entry with `Service` and `Email/Username`.
- Edit: edits the currently selected row.
- Delete: deletes checked rows (batch delete supported).

### Batch Selection (Checkboxes)
The leftmost checkbox column is the batch selection mechanism:

- Check one or more accounts.
- Click `Delete` to remove all checked accounts.

### Filter
The filter box narrows the visible rows. Checkbox selection remains based on the visible rows.

### Optional Password On Add
The Add dialog includes an optional password field.

If provided and `Remember Password Hashes` is ON:
- PwnChecker stores only a derived password hash (encrypted) for future checks.
- Future `Check Now` runs do not prompt for the password for that account.

If omitted:
- PwnChecker prompts for a password during `Check Now` (Skip supported).

## Check Now

`Check Now` creates a new run and writes results per account.

While checks are running, the status bar shows `Processing checks...` and the cursor switches to a busy cursor. The `Check Now` button is disabled until completion.

Checks performed:

1. Password exposure (HIBP Pwned Passwords)
- Uses k-anonymity: only the first 5 characters of `SHA1(password)` are sent to the API.
- Output is the count of appearances in breach corpuses.

2. Domain security posture (no-key)
- Uses DNS lookups for MX/SPF/DMARC on the domain after `@`.
- Output is a status plus an intuitive message with recommended actions.

## Reports

The Reports tab shows:
- Run history (left)
- Textual summary for the selected run (right)

### Status vs Findings
Each account section contains:
- `Status`: a single overall classification (`OK`, `ATTENTION`, `UNKNOWN`, `ERROR`, `SKIPPED`).
- `Findings`: one or more triggered findings (for example: password exposed, domain needs attention).

### Run Serialization
Runs are labeled `Run 1..N` based on the current run history. If all runs are deleted, numbering restarts at `Run 1`.

### Batch Delete Runs
Runs have checkboxes:
- Check one or more runs.
- Click `Delete Run` to delete all checked runs (results are deleted automatically).

## Settings

Settings are stored encrypted in the vault.

- Report Redaction:
  - ON: identifiers are redacted in the Reports summary.
  - OFF: identifiers are shown in plaintext in Reports.
  - Saving applies immediately to the currently selected report.

- Remember Password Hashes:
  - ON: derived password hash may be stored for reuse between runs.
  - OFF: PwnChecker will prompt for a password on each run (unless skipped).

An `Unsaved changes` indicator appears below `Save Settings` whenever the current toggles differ from the last saved state.

## CLI (Secondary)

The CLI is available for vault and account management:

```powershell
python -m pwnchecker init
python -m pwnchecker add --service GitHub --identifier dev@example.com
python -m pwnchecker list
python -m pwnchecker show 1 --reveal
python -m pwnchecker remove 1 --yes
```

## Known Limitations
- No email breach membership lookup (HIBP breached-account search) is included.
- Results are basic; deltas and advanced reporting are not implemented yet.
