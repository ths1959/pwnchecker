from __future__ import annotations

import sys

import typer

from . import __version__
from .storage.accounts import AccountRepo
from .storage.paths import vault_db_path
from .storage.vault import VaultError, VaultLockedError, create_vault, open_vault, vault_exists

app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.callback()
def main() -> None:
    """PwnChecker CLI."""


def _prompt_password(*, confirm: bool) -> str:
    return typer.prompt(
        "Master password",
        hide_input=True,
        confirmation_prompt=confirm,
    )


def _redact_identifier(s: str) -> str:
    s = s.strip()
    if not s:
        return ""
    if "@" in s:
        left, right = s.split("@", 1)
        left_r = (left[:1] + "***") if left else "***"
        right_r = (right[:1] + "***") if right else "***"
        return f"{left_r}@{right_r}"
    if len(s) <= 2:
        return "*" * len(s)
    return s[:2] + "***"


def _open_repo(password: str) -> AccountRepo:
    session = open_vault(vault_db_path(), password)
    return AccountRepo(session)


@app.command("init")
def init() -> None:
    """Create the encrypted local vault."""
    db_path = vault_db_path()
    if vault_exists(db_path):
        typer.echo("Vault already exists.")
        raise typer.Exit(code=1)

    pw = _prompt_password(confirm=True)
    try:
        create_vault(db_path, pw)
    except VaultError as e:
        typer.echo(f"Vault error: {e}")
        raise typer.Exit(code=1) from None

    typer.echo("Vault created.")


@app.command("add")
def add(
    service: str = typer.Option(..., "--service", "-s", help="Service name (example: GitHub)."),
    identifier: str = typer.Option(..., "--identifier", "-i", help="Email/username."),
    identifier_type: str = typer.Option("email", "--type", "-t", help="Identifier type."),
) -> None:
    """Add an account to the vault."""
    if not vault_exists(vault_db_path()):
        typer.echo("Vault does not exist. Run `pwnchecker init` first.")
        raise typer.Exit(code=1)

    pw = _prompt_password(confirm=False)
    try:
        repo = _open_repo(pw)
    except VaultLockedError:
        typer.echo("Invalid master password.")
        raise typer.Exit(code=2) from None

    acct_id = repo.add_account(service, identifier_type, identifier)
    typer.echo(f"Added account id={acct_id}.")


@app.command("list")
def list_accounts(
    reveal: bool = typer.Option(False, "--reveal", help="Print identifiers in plaintext."),
) -> None:
    """List accounts in the vault."""
    if not vault_exists(vault_db_path()):
        typer.echo("Vault does not exist. Run `pwnchecker init` first.")
        raise typer.Exit(code=1)

    pw = _prompt_password(confirm=False)
    try:
        repo = _open_repo(pw)
    except VaultLockedError:
        typer.echo("Invalid master password.")
        raise typer.Exit(code=2) from None

    accts = repo.list_accounts()
    if not accts:
        typer.echo("No accounts.")
        return

    typer.echo("ID\tService\tIdentifier")
    for a in accts:
        ident = a.identifier_value if reveal else _redact_identifier(a.identifier_value)
        typer.echo(f"{a.id}\t{a.service}\t{ident}")


@app.command("show")
def show(
    account_id: int = typer.Argument(..., help="Account id."),
    reveal: bool = typer.Option(False, "--reveal", help="Print identifier in plaintext."),
) -> None:
    """Show one account by id."""
    if not vault_exists(vault_db_path()):
        typer.echo("Vault does not exist. Run `pwnchecker init` first.")
        raise typer.Exit(code=1)

    pw = _prompt_password(confirm=False)
    try:
        repo = _open_repo(pw)
    except VaultLockedError:
        typer.echo("Invalid master password.")
        raise typer.Exit(code=2) from None

    accts = repo.list_accounts()
    match = next((a for a in accts if a.id == account_id), None)
    if match is None:
        typer.echo("Account not found.")
        raise typer.Exit(code=1)

    ident = match.identifier_value if reveal else _redact_identifier(match.identifier_value)
    typer.echo(f"ID: {match.id}")
    typer.echo(f"Service: {match.service}")
    typer.echo(f"Type: {match.identifier_type}")
    typer.echo(f"Identifier: {ident}")


@app.command("remove")
def remove(
    account_id: int = typer.Argument(..., help="Account id."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
) -> None:
    """Remove an account by id."""
    if not vault_exists(vault_db_path()):
        typer.echo("Vault does not exist. Run `pwnchecker init` first.")
        raise typer.Exit(code=1)

    pw = _prompt_password(confirm=False)
    try:
        repo = _open_repo(pw)
    except VaultLockedError:
        typer.echo("Invalid master password.")
        raise typer.Exit(code=2) from None

    accts = repo.list_accounts()
    match = next((a for a in accts if a.id == account_id), None)
    if match is None:
        typer.echo("Account not found.")
        raise typer.Exit(code=1)

    if not yes:
        ok = typer.confirm(f"Remove account id={account_id} service='{match.service}'?")
        if not ok:
            raise typer.Exit(code=0)

    repo.delete_account(account_id)
    typer.echo("Removed.")


@app.command("version")
def version() -> None:
    """Print PwnChecker version."""
    typer.echo(__version__)


if __name__ == "__main__":
    sys.exit(app())
