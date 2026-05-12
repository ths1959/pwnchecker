from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .vault import VaultSession


@dataclass(frozen=True)
class ResultRow:
    run_id: int
    account_id: int
    provider: str
    status: str
    data: dict[str, Any]
    created_at_utc: str


class ResultRepo:
    def __init__(self, session: VaultSession) -> None:
        self._s = session

    def add_result(
        self,
        *,
        run_id: int,
        account_id: int,
        provider: str,
        status: str,
        data: dict[str, Any],
    ) -> None:
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._s.conn.execute(
            """
            INSERT INTO results (run_id, account_id, provider, status, data_json, created_at_utc)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (run_id, account_id, provider, status, json.dumps(data, separators=(",", ":")), now),
        )
        self._s.conn.commit()

    def list_results_for_run(self, run_id: int) -> list[ResultRow]:
        cur = self._s.conn.execute(
            """
            SELECT run_id, account_id, provider, status, data_json, created_at_utc
            FROM results
            WHERE run_id = ?
            ORDER BY id ASC
            """,
            (run_id,),
        )
        out: list[ResultRow] = []
        for r in cur.fetchall():
            data = json.loads(r["data_json"]) if r["data_json"] else {}
            out.append(
                ResultRow(
                    run_id=int(r["run_id"]),
                    account_id=int(r["account_id"]),
                    provider=str(r["provider"]),
                    status=str(r["status"]),
                    data=data if isinstance(data, dict) else {},
                    created_at_utc=str(r["created_at_utc"]),
                )
            )
        return out

