from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha1
from typing import Any

from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal

from ..providers.domain_posture import assess_domain
from ..providers.pwned_passwords import PwnedPasswordsClient
from ..storage.db import connect, init_schema
from ..storage.hash_cache import HashCacheRepo
from ..storage.results import ResultRepo
from ..storage.runs import RunRepo
from ..storage.vault import VaultSession


@dataclass(frozen=True)
class CheckItem:
    account_id: int
    service: str
    identifier: str
    password_sha1: str | None  # If None: skipped or unavailable.


class CheckWorker(QObject):
    progress = Signal(int, int, str)  # i, total, message
    finished = Signal(int, bool, str)  # run_id, cancelled, message

    def __init__(self, session: VaultSession, items: list[CheckItem]) -> None:
        super().__init__()
        # Do not share sqlite3.Connection across threads. Only keep immutable
        # materials needed to open a new connection inside the worker thread.
        self._db_path: Path = session.db_path
        self._key: bytes = session.key
        self._items = items
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        conn = connect(self._db_path)
        try:
            init_schema(conn)
            session = VaultSession(db_path=self._db_path, conn=conn, key=self._key)
            run_repo = RunRepo(session)
            result_repo = ResultRepo(session)
            cache_repo = HashCacheRepo(session)
            pp = PwnedPasswordsClient()

            run_id = run_repo.create_run()
            total = len(self._items)

            for idx, it in enumerate(self._items, start=1):
                if self._cancelled:
                    self.finished.emit(run_id, True, "Cancelled")
                    return

                self.progress.emit(idx, total, f"Checking {it.service}...")

                norm_ident = it.identifier.strip().lower()
                digest_hex = sha1(norm_ident.encode("utf-8")).hexdigest().upper()
                cache_repo.upsert(
                    it.account_id,
                    "identifier-sha1",
                    1,
                    {"identifier_sha1": digest_hex, "prefix5": digest_hex[:5], "algo": "sha1"},
                )
                result_repo.add_result(
                    run_id=run_id,
                    account_id=it.account_id,
                    provider="pwnchecker",
                    status="ok",
                    data={"cache_provider": "identifier-sha1", "cache_version": 1},
                )

                if it.password_sha1 is None:
                    result_repo.add_result(
                        run_id=run_id,
                        account_id=it.account_id,
                        provider="pwned-passwords",
                        status="skipped",
                        data={},
                    )
                else:
                    try:
                        res = pp.check_sha1(it.password_sha1)
                        result_repo.add_result(
                            run_id=run_id,
                            account_id=it.account_id,
                            provider="pwned-passwords",
                            status="ok",
                            data={"count": res.count, "prefix5": res.prefix5},
                        )
                    except Exception as e:
                        result_repo.add_result(
                            run_id=run_id,
                            account_id=it.account_id,
                            provider="pwned-passwords",
                            status="error",
                            data={"error": type(e).__name__},
                        )

                dom = ""
                if "@" in it.identifier:
                    dom = it.identifier.split("@", 1)[1].strip().lower()
                dp = assess_domain(dom)
                result_repo.add_result(
                    run_id=run_id,
                    account_id=it.account_id,
                    provider="domain-posture",
                    status=dp.status,
                    data={"domain": dp.domain, "message": dp.message},
                )

            self.finished.emit(run_id, False, "Completed")
        except Exception as e:
            # Ensure UI is always released even on unexpected failures.
            self.finished.emit(0, True, f"Error: {type(e).__name__}")
        finally:
            try:
                conn.close()
            except Exception:
                pass


class CheckThread(QThread):
    # Convenience wrapper to ensure worker lifetime.
    def __init__(self, worker: CheckWorker) -> None:
        super().__init__()
        self.worker = worker
        self.worker.moveToThread(self)

    def run(self) -> None:
        self.worker.run()
