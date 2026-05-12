from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .crypto import decrypt_aead, encrypt_aead, json_dumps, json_loads
from .vault import VaultSession


@dataclass(frozen=True)
class CacheEntry:
    account_id: int
    provider: str
    algo_version: int
    data: dict[str, Any]


class HashCacheRepo:
    """
    Stores derived (hashed) identifier material per account/provider/version.

    Payloads are encrypted at rest. Cache is versioned so algorithm/normalization
    changes can be handled by bumping algo_version.
    """

    def __init__(self, session: VaultSession) -> None:
        self._s = session

    def get(self, account_id: int, provider: str, algo_version: int) -> CacheEntry | None:
        row = self._s.conn.execute(
            """
            SELECT derived_nonce, derived_cipher
            FROM hash_cache
            WHERE account_id = ? AND provider = ? AND algo_version = ?
            """,
            (account_id, provider, algo_version),
        ).fetchone()
        if row is None:
            return None

        pt = decrypt_aead(
            self._s.key,
            row["derived_nonce"],
            row["derived_cipher"],
            aad=b"hash-cache",
        )
        data = json_loads(pt)
        if not isinstance(data, dict):
            return None
        return CacheEntry(
            account_id=account_id,
            provider=provider,
            algo_version=algo_version,
            data=data,
        )

    def upsert(
        self,
        account_id: int,
        provider: str,
        algo_version: int,
        data: dict[str, Any],
    ) -> None:
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce, cipher = encrypt_aead(self._s.key, json_dumps(data), aad=b"hash-cache")
        self._s.conn.execute(
            """
            INSERT INTO hash_cache (
              account_id, provider, algo_version, derived_nonce, derived_cipher, updated_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(account_id, provider, algo_version)
            DO UPDATE SET
              derived_nonce = excluded.derived_nonce,
              derived_cipher = excluded.derived_cipher,
              updated_at_utc = excluded.updated_at_utc
            """,
            (account_id, provider, algo_version, nonce, cipher, now),
        )
        self._s.conn.commit()

    def delete_for_account(self, account_id: int) -> None:
        self._s.conn.execute("DELETE FROM hash_cache WHERE account_id = ?", (account_id,))
        self._s.conn.commit()
