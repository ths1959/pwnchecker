from __future__ import annotations

import pytest

from pwnchecker.storage.accounts import AccountRepo
from pwnchecker.storage.paths import vault_db_path
from pwnchecker.storage.vault import VaultLockedError, create_vault, open_vault


def test_vault_create_and_open_round_trip(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PWNCHECKER_DATA_DIR", str(tmp_path))
    db_path = vault_db_path()

    create_vault(db_path, "pw123")
    session = open_vault(db_path, "pw123")
    assert session.conn is not None


def test_vault_open_wrong_password_fails(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PWNCHECKER_DATA_DIR", str(tmp_path))
    db_path = vault_db_path()

    create_vault(db_path, "pw123")
    with pytest.raises(VaultLockedError):
        open_vault(db_path, "wrong")


def test_accounts_crud_encrypts_identifier(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PWNCHECKER_DATA_DIR", str(tmp_path))
    session = create_vault(vault_db_path(), "pw123")
    repo = AccountRepo(session)

    acct_id = repo.add_account("GitHub", "email", "Dev@Example.com")
    accts = repo.list_accounts()
    assert len(accts) == 1
    assert accts[0].id == acct_id
    assert accts[0].identifier_value == "Dev@Example.com"

    repo.update_account(acct_id, "GitHub", "email", "dev2@example.com")
    accts = repo.list_accounts()
    assert accts[0].identifier_value == "dev2@example.com"

    # Ensure ciphertext differs from plaintext in DB.
    row = session.conn.execute(
        "SELECT identifier_cipher FROM accounts WHERE id = ?",
        (acct_id,),
    ).fetchone()
    assert row is not None
    assert b"dev2@example.com" not in row["identifier_cipher"]

    repo.delete_account(acct_id)
    assert repo.list_accounts() == []


def test_accounts_batch_delete(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PWNCHECKER_DATA_DIR", str(tmp_path))
    session = create_vault(vault_db_path(), "pw123")
    repo = AccountRepo(session)

    a1 = repo.add_account("Svc1", "email", "a@example.com")
    a2 = repo.add_account("Svc2", "email", "b@example.com")
    assert len(repo.list_accounts()) == 2

    repo.delete_accounts([a1, a2])
    assert repo.list_accounts() == []
