from __future__ import annotations

from pwnchecker.storage.accounts import AccountRepo
from pwnchecker.storage.paths import vault_db_path
from pwnchecker.storage.results import ResultRepo
from pwnchecker.storage.runs import RunRepo
from pwnchecker.storage.vault import create_vault


def test_runs_and_results_persist(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PWNCHECKER_DATA_DIR", str(tmp_path))
    session = create_vault(vault_db_path(), "pw123")

    runs = RunRepo(session)
    results = ResultRepo(session)
    accounts = AccountRepo(session)

    run_id = runs.create_run()
    assert run_id >= 1

    listed = runs.list_runs()
    assert listed[0].id == run_id

    acct_id = accounts.add_account("GitHub", "email", "dev@example.com")

    results.add_result(
        run_id=run_id,
        account_id=acct_id,
        provider="pwnchecker",
        status="ok",
        data={"k": "v"},
    )
    rows = results.list_results_for_run(run_id)
    assert len(rows) == 1
    assert rows[0].account_id == acct_id
    assert rows[0].data["k"] == "v"

    runs.delete_run(run_id)
    assert runs.list_runs() == []
    assert results.list_results_for_run(run_id) == []
