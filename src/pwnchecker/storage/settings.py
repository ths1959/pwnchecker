from __future__ import annotations

from datetime import UTC, datetime

from .crypto import decrypt_aead, encrypt_aead
from .vault import VaultSession


class SettingsRepo:
    def __init__(self, session: VaultSession) -> None:
        self._s = session

    def set(self, key: str, value: str) -> None:
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce, cipher = encrypt_aead(self._s.key, value.encode("utf-8"), aad=b"app-settings")
        self._s.conn.execute(
            """
            INSERT INTO app_settings (key, value_nonce, value_cipher, updated_at_utc)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key)
            DO UPDATE SET
              value_nonce = excluded.value_nonce,
              value_cipher = excluded.value_cipher,
              updated_at_utc = excluded.updated_at_utc
            """,
            (key, nonce, cipher, now),
        )
        self._s.conn.commit()

    def get(self, key: str) -> str | None:
        row = self._s.conn.execute(
            "SELECT value_nonce, value_cipher FROM app_settings WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        pt = decrypt_aead(self._s.key, row["value_nonce"], row["value_cipher"], aad=b"app-settings")
        return pt.decode("utf-8")

