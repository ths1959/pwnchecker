from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF_VERSION = 1


@dataclass(frozen=True)
class KdfParams:
    time_cost: int
    memory_cost_kib: int
    parallelism: int
    hash_len: int
    salt_len: int
    version: int = KDF_VERSION

    def to_json(self) -> str:
        return json.dumps(
            {
                "time_cost": self.time_cost,
                "memory_cost_kib": self.memory_cost_kib,
                "parallelism": self.parallelism,
                "hash_len": self.hash_len,
                "salt_len": self.salt_len,
                "version": self.version,
            },
            separators=(",", ":"),
        )

    @staticmethod
    def from_json(s: str) -> KdfParams:
        obj = json.loads(s)
        return KdfParams(
            time_cost=int(obj["time_cost"]),
            memory_cost_kib=int(obj["memory_cost_kib"]),
            parallelism=int(obj["parallelism"]),
            hash_len=int(obj["hash_len"]),
            salt_len=int(obj["salt_len"]),
            version=int(obj.get("version", KDF_VERSION)),
        )


def default_kdf_params() -> KdfParams:
    # Balanced for local desktop usage; can be tuned later.
    return KdfParams(
        time_cost=3,
        memory_cost_kib=64 * 1024,
        parallelism=2,
        hash_len=32,
        salt_len=16,
    )


def derive_master_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    pw = password.encode("utf-8")
    return hash_secret_raw(
        secret=pw,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=Type.ID,
    )


def encrypt_aead(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad if aad else None)
    return nonce, ct


def decrypt_aead(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad if aad else None)


def keyed_identifier_digest(key: bytes, normalized_identifier: str) -> bytes:
    # Stable, non-reversible cache key without exposing raw identifier to DB indexing.
    msg = normalized_identifier.encode("utf-8")
    return hmac.new(key, msg, sha256).digest()


def normalize_identifier(identifier: str) -> str:
    # Conservative normalization: trim and lowercase. Avoid provider-specific tricks for now.
    return identifier.strip().lower()


def json_dumps(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def json_loads(b: bytes) -> Any:
    return json.loads(b.decode("utf-8"))
