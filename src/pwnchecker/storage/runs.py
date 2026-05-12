from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .vault import VaultSession


@dataclass(frozen=True)
class Run:
    id: int
    created_at_utc: str


class RunRepo:
    def __init__(self, session: VaultSession) -> None:
        self._s = session

    def create_run(self) -> int:
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        cur = self._s.conn.execute("INSERT INTO runs (created_at_utc) VALUES (?)", (now,))
        self._s.conn.commit()
        return int(cur.lastrowid)

    def list_runs(self) -> list[Run]:
        cur = self._s.conn.execute("SELECT id, created_at_utc FROM runs ORDER BY id DESC")
        out: list[Run] = []
        for r in cur.fetchall():
            out.append(Run(id=int(r["id"]), created_at_utc=str(r["created_at_utc"])))
        return out

    def delete_run(self, run_id: int) -> None:
        # Results are deleted via ON DELETE CASCADE.
        self._s.conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        self._s.conn.commit()
