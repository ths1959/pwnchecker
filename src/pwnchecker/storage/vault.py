from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .crypto import KdfParams, decrypt_aead, default_kdf_params, derive_master_key, encrypt_aead
from .db import connect, init_schema

_VERIFIER_PLAINTEXT = b"pwnchecker-vault-verifier-v1"


class VaultError(Exception):
    pass


class VaultLockedError(VaultError):
    pass


@dataclass(frozen=True)
class VaultSession:
    db_path: Path
    conn: sqlite3.Connection
    key: bytes


def vault_exists(db_path: Path) -> bool:
    return db_path.exists()


def create_vault(db_path: Path, password: str, *, params: KdfParams | None = None) -> VaultSession:
    if vault_exists(db_path):
        raise VaultError("Vault already exists.")

    p = params or default_kdf_params()
    salt = os_urandom(p.salt_len)
    key = derive_master_key(password, salt, p)
    verifier_nonce, verifier_cipher = encrypt_aead(key, _VERIFIER_PLAINTEXT, aad=b"vault-verifier")

    conn = connect(db_path)
    init_schema(conn)

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        """
        INSERT INTO vault_meta (
          id, kdf_salt, kdf_params_json, verifier_nonce, verifier_cipher, created_at_utc
        )
        VALUES (1, ?, ?, ?, ?, ?)
        """,
        (salt, p.to_json(), verifier_nonce, verifier_cipher, now),
    )
    conn.commit()
    return VaultSession(db_path=db_path, conn=conn, key=key)


def open_vault(db_path: Path, password: str) -> VaultSession:
    if not vault_exists(db_path):
        raise VaultError("Vault does not exist.")

    conn = connect(db_path)
    init_schema(conn)

    row = conn.execute("SELECT * FROM vault_meta WHERE id = 1").fetchone()
    if row is None:
        raise VaultError("Vault metadata missing.")

    params = KdfParams.from_json(row["kdf_params_json"])
    salt = row["kdf_salt"]
    key = derive_master_key(password, salt, params)

    try:
        pt = decrypt_aead(key, row["verifier_nonce"], row["verifier_cipher"], aad=b"vault-verifier")
    except Exception as e:  # cryptography InvalidTag and similar
        raise VaultLockedError("Invalid master password.") from e

    if pt != _VERIFIER_PLAINTEXT:
        raise VaultLockedError("Invalid master password.")

    return VaultSession(db_path=db_path, conn=conn, key=key)


def os_urandom(n: int) -> bytes:
    import os

    return os.urandom(n)
