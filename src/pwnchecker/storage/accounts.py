from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .crypto import (
    decrypt_aead,
    encrypt_aead,
    keyed_identifier_digest,
    normalize_identifier,
)
from .vault import VaultSession


@dataclass(frozen=True)
class Account:
    id: int
    service: str
    identifier_type: str
    identifier_value: str


class AccountRepo:
    def __init__(self, session: VaultSession) -> None:
        self._s = session

    def list_accounts(self) -> list[Account]:
        cur = self._s.conn.execute(
            """
            SELECT id, service, identifier_type, identifier_nonce, identifier_cipher
            FROM accounts
            ORDER BY service, id
            """
        )
        out: list[Account] = []
        for row in cur.fetchall():
            ident = decrypt_aead(
                self._s.key,
                row["identifier_nonce"],
                row["identifier_cipher"],
                aad=b"acct-ident",
            )
            out.append(
                Account(
                    id=int(row["id"]),
                    service=str(row["service"]),
                    identifier_type=str(row["identifier_type"]),
                    identifier_value=ident.decode("utf-8"),
                )
            )
        return out

    def add_account(self, service: str, identifier_type: str, identifier_value: str) -> int:
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        norm = normalize_identifier(identifier_value)
        digest = keyed_identifier_digest(self._s.key, norm)
        nonce, cipher = encrypt_aead(
            self._s.key,
            identifier_value.encode("utf-8"),
            aad=b"acct-ident",
        )
        cur = self._s.conn.execute(
            """
            INSERT INTO accounts
              (
                service,
                identifier_type,
                identifier_nonce,
                identifier_cipher,
                identifier_digest,
                created_at_utc,
                updated_at_utc
              )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (service, identifier_type, nonce, cipher, digest, now, now),
        )
        self._s.conn.commit()
        return int(cur.lastrowid)

    def update_account(
        self,
        account_id: int,
        service: str,
        identifier_type: str,
        identifier_value: str,
    ) -> None:
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        norm = normalize_identifier(identifier_value)
        digest = keyed_identifier_digest(self._s.key, norm)
        nonce, cipher = encrypt_aead(
            self._s.key,
            identifier_value.encode("utf-8"),
            aad=b"acct-ident",
        )
        self._s.conn.execute(
            """
            UPDATE accounts
            SET
              service = ?,
              identifier_type = ?,
              identifier_nonce = ?,
              identifier_cipher = ?,
              identifier_digest = ?,
              updated_at_utc = ?
            WHERE id = ?
            """,
            (service, identifier_type, nonce, cipher, digest, now, account_id),
        )
        # Invalidate derived cache for this account (identifier changed).
        self._s.conn.execute("DELETE FROM hash_cache WHERE account_id = ?", (account_id,))
        self._s.conn.commit()

    def delete_account(self, account_id: int) -> None:
        self._s.conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        self._s.conn.commit()
