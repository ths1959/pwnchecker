from __future__ import annotations

from pwnchecker.storage.accounts import AccountRepo
from pwnchecker.storage.hash_cache import HashCacheRepo
from pwnchecker.storage.paths import vault_db_path
from pwnchecker.storage.vault import create_vault


def test_hash_cache_upsert_get_and_version_miss(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PWNCHECKER_DATA_DIR", str(tmp_path))
    session = create_vault(vault_db_path(), "pw123")

    accounts = AccountRepo(session)
    acct_id = accounts.add_account("GitHub", "email", "dev@example.com")

    cache = HashCacheRepo(session)
    cache.upsert(acct_id, "hibp-passwords", 1, {"prefix": "ABCDE", "algo": "sha1"})

    hit = cache.get(acct_id, "hibp-passwords", 1)
    assert hit is not None
    assert hit.data["prefix"] == "ABCDE"

    miss = cache.get(acct_id, "hibp-passwords", 2)
    assert miss is None


def test_hash_cache_invalidated_on_identifier_update(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PWNCHECKER_DATA_DIR", str(tmp_path))
    session = create_vault(vault_db_path(), "pw123")

    accounts = AccountRepo(session)
    acct_id = accounts.add_account("GitHub", "email", "dev@example.com")

    cache = HashCacheRepo(session)
    cache.upsert(acct_id, "provider-x", 1, {"k": "v"})
    assert cache.get(acct_id, "provider-x", 1) is not None

    accounts.update_account(acct_id, "GitHub", "email", "dev2@example.com")
    assert cache.get(acct_id, "provider-x", 1) is None

