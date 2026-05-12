from __future__ import annotations

from pwnchecker.storage.paths import vault_db_path
from pwnchecker.storage.settings import SettingsRepo
from pwnchecker.storage.vault import create_vault


def test_settings_round_trip(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PWNCHECKER_DATA_DIR", str(tmp_path))
    session = create_vault(vault_db_path(), "pw123")
    repo = SettingsRepo(session)

    assert repo.get("missing") is None
    repo.set("report_redact", "1")
    assert repo.get("report_redact") == "1"

