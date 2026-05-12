from __future__ import annotations

from PySide6.QtCore import Qt

from pwnchecker.storage.paths import vault_db_path
from pwnchecker.storage.vault import create_vault
from pwnchecker.ui.main_window import AccountRow, MainWindow


def test_gui_launches_and_check_now_creates_run(qtbot, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PWNCHECKER_DATA_DIR", str(tmp_path))
    session = create_vault(vault_db_path(), "test-password")
    win = MainWindow(session=session)
    qtbot.addWidget(win)
    win.show()

    assert win.runs_list.count() == 0

    qtbot.mouseClick(win.check_now_btn, Qt.LeftButton)

    assert win.runs_list.count() == 1


def test_accounts_add_edit_delete_non_ui_helpers(qtbot, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PWNCHECKER_DATA_DIR", str(tmp_path))
    session = create_vault(vault_db_path(), "test-password")
    win = MainWindow(session=session)
    qtbot.addWidget(win)
    win.show()

    initial_rows = win.accounts_table.rowCount()

    win.add_account(AccountRow(service="GitHub", identifier="dev@example.com"))
    assert win.accounts_table.rowCount() == initial_rows + 1

    win.edit_account(0, AccountRow(service="Example2", identifier="user2@example.com"))
    assert win.accounts_table.item(0, 1).text() == "Example2"

    win.delete_account(0)
    assert win.accounts_table.rowCount() == initial_rows
