from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha1

import httpx

HIBP_RANGE_BASE = "https://api.pwnedpasswords.com/range"


@dataclass(frozen=True)
class PwnedPasswordResult:
    sha1: str
    prefix5: str
    count: int


class PwnedPasswordsClient:
    def __init__(self, *, timeout_s: float = 10.0, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(
            timeout=timeout_s,
            headers={"User-Agent": "PwnChecker/0.1"},
        )

    def check_password(self, password: str) -> PwnedPasswordResult:
        digest = sha1(password.encode("utf-8")).hexdigest().upper()
        return self.check_sha1(digest)

    def check_sha1(self, sha1_hex: str) -> PwnedPasswordResult:
        digest = sha1_hex.strip().upper()
        prefix = digest[:5]
        suffix = digest[5:]

        url = f"{HIBP_RANGE_BASE}/{prefix}"
        r = self._client.get(url)
        r.raise_for_status()

        count = _parse_range_response_for_suffix(r.text, suffix)
        return PwnedPasswordResult(sha1=digest, prefix5=prefix, count=count)


def _parse_range_response_for_suffix(body: str, suffix: str) -> int:
    target = suffix.upper()
    for line in body.splitlines():
        if not line:
            continue
        # Format: "ABCDEF...:123"
        parts = line.split(":")
        if len(parts) != 2:
            continue
        suf = parts[0].strip().upper()
        if suf == target:
            try:
                return int(parts[1].strip())
            except ValueError:
                return 0
    return 0
