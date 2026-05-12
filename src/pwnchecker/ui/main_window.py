from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha1
from typing import Any

from PySide6.QtCore import QItemSelectionModel, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..storage.accounts import Account, AccountRepo
from ..storage.hash_cache import HashCacheRepo
from ..storage.paths import vault_db_path
from ..storage.results import ResultRepo
from ..storage.runs import RunRepo
from ..storage.vault import VaultLockedError, VaultSession, create_vault, open_vault, vault_exists
from .vault_dialog import VaultDialog


@dataclass(frozen=True)
class AccountRow:
    service: str
    identifier: str  # Placeholder for v0.1: no encryption/storage yet.


class AccountDialog(QDialog):
    def __init__(self, parent: QWidget, *, title: str, initial: AccountRow | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)

        self.service_edit = QLineEdit()
        self.service_edit.setObjectName("service_edit")
        self.identifier_edit = QLineEdit()
        self.identifier_edit.setObjectName("identifier_edit")

        if initial is not None:
            self.service_edit.setText(initial.service)
            self.identifier_edit.setText(initial.identifier)

        form = QFormLayout()
        form.addRow("Service", self.service_edit)
        form.addRow("Email/Username", self.identifier_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _on_accept(self) -> None:
        service = self.service_edit.text().strip()
        ident = self.identifier_edit.text().strip()
        if not service or not ident:
            QMessageBox.warning(self, "Invalid Input", "Service and Email/Username are required.")
            return
        self.accept()

    def get_value(self) -> AccountRow:
        return AccountRow(
            service=self.service_edit.text().strip(),
            identifier=self.identifier_edit.text().strip(),
        )


class MainWindow(QMainWindow):
    def __init__(self, *, session: VaultSession | None = None) -> None:
        super().__init__()
        self.setWindowTitle("PwnChecker")
        self.setMinimumSize(900, 600)
        self._ready = True

        self._session: VaultSession | None = session
        self._repo: AccountRepo | None = AccountRepo(session) if session else None
        self._accounts: list[Account] = []
        self._run_repo: RunRepo | None = RunRepo(session) if session else None
        self._result_repo: ResultRepo | None = ResultRepo(session) if session else None
        self._cache_repo: HashCacheRepo | None = HashCacheRepo(session) if session else None

        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(14, 14, 14, 10)
        root_layout.setSpacing(10)

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(10)

        title_block = QVBoxLayout()
        title_block.setContentsMargins(0, 0, 0, 0)
        title_block.setSpacing(2)

        title = QLabel("PwnChecker")
        title.setObjectName("app_title")
        title.setTextInteractionFlags(Qt.TextSelectableByMouse)

        subtitle = QLabel("Local-first breach checks | encrypted vault")
        subtitle.setObjectName("app_subtitle")
        subtitle.setTextInteractionFlags(Qt.TextSelectableByMouse)

        title_block.addWidget(title)
        title_block.addWidget(subtitle)

        self.check_now_btn = QPushButton("Check Now")
        self.check_now_btn.setObjectName("check_now_btn")
        self.check_now_btn.clicked.connect(self._on_check_now)

        header.addLayout(title_block)
        header.addStretch(1)
        header.addWidget(self.check_now_btn)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("tabs")

        self.accounts_tab = self._build_accounts_tab()
        self.reports_tab = self._build_reports_tab()
        self.settings_tab = self._build_settings_tab()

        self.tabs.addTab(self.accounts_tab, "Accounts")
        self.tabs.addTab(self.reports_tab, "Reports")
        self.tabs.addTab(self.settings_tab, "Settings")

        root_layout.addLayout(header)
        root_layout.addWidget(self.tabs)

        self.setCentralWidget(root)
        self.statusBar().showMessage("Ready")

        if self._repo is None:
            if not self._ensure_vault_unlocked():
                # User cancelled unlock/create; close the app instead of showing an unusable window.
                self._ready = False
                self.close()
                return
        else:
            self._accounts = self._repo.list_accounts()

        self._refresh_accounts_table()
        self._refresh_runs()
        self._refresh_results()

    def is_ready(self) -> bool:
        return self._ready

    def _build_accounts_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        controls = QHBoxLayout()
        controls.setContentsMargins(0, 0, 0, 0)
        controls.setSpacing(8)
        self.filter_edit = QLineEdit()
        self.filter_edit.setObjectName("accounts_filter")
        self.filter_edit.setPlaceholderText("Filter accounts...")
        self.filter_edit.textChanged.connect(self._refresh_accounts_table)

        self.add_btn = QPushButton("Add")
        self.add_btn.setObjectName("add_account_btn")
        self.add_btn.setIcon(self.style().standardIcon(self.style().StandardPixmap.SP_FileDialogNewFolder))
        self.add_btn.clicked.connect(self._on_add_account)

        self.edit_btn = QPushButton("Edit")
        self.edit_btn.setObjectName("edit_account_btn")
        self.edit_btn.setIcon(self.style().standardIcon(self.style().StandardPixmap.SP_FileDialogDetailedView))
        self.edit_btn.setEnabled(False)
        self.edit_btn.clicked.connect(self._on_edit_account)

        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setObjectName("delete_account_btn")
        self.delete_btn.setIcon(self.style().standardIcon(self.style().StandardPixmap.SP_TrashIcon))
        self.delete_btn.setEnabled(False)
        self.delete_btn.clicked.connect(self._on_delete_account)

        controls.addWidget(self.filter_edit, 1)
        controls.addWidget(self.add_btn)
        controls.addWidget(self.edit_btn)
        controls.addWidget(self.delete_btn)

        self.accounts_table = QTableWidget()
        self.accounts_table.setObjectName("accounts_table")
        self.accounts_table.setColumnCount(5)
        self.accounts_table.setHorizontalHeaderLabels(
            ["No.", "Service", "Identifier", "Created", "Last Updated"]
        )
        self.accounts_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.accounts_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.accounts_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.accounts_table.setAlternatingRowColors(True)
        self.accounts_table.verticalHeader().setVisible(False)
        self.accounts_table.cellClicked.connect(self._select_single_account_row)
        self.accounts_table.itemSelectionChanged.connect(self._on_accounts_selection_changed)
        layout.addLayout(controls)
        layout.addWidget(self.accounts_table)
        return w

    def _build_reports_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        actions = QHBoxLayout()
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(8)

        self.delete_run_btn = QPushButton("Delete Run")
        self.delete_run_btn.setObjectName("delete_run_btn")
        self.delete_run_btn.setEnabled(False)
        self.delete_run_btn.setIcon(self.style().standardIcon(self.style().StandardPixmap.SP_TrashIcon))
        self.delete_run_btn.clicked.connect(self._on_delete_run)

        actions.addStretch(1)
        actions.addWidget(self.delete_run_btn)

        self.runs_list = QListWidget()
        self.runs_list.setObjectName("runs_list")
        self.runs_list.setMinimumWidth(280)
        self.runs_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.runs_list.currentRowChanged.connect(self._on_run_selection_changed)

        self.results_table = QTableWidget()
        self.results_table.setObjectName("results_table")
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(
            ["Service", "Identifier", "Provider", "Status"]
        )
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.cellClicked.connect(self._select_single_result_row)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        row.addWidget(self.runs_list, 0)
        row.addWidget(self.results_table, 1)

        layout.addLayout(actions)
        layout.addLayout(row)
        return w

    def _build_settings_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        layout.addStretch(1)
        return w

    def _refresh_accounts_table(self) -> None:
        flt = (self.filter_edit.text() if hasattr(self, "filter_edit") else "").strip().lower()
        rows = self._accounts
        if flt:
            rows = [
                a
                for a in self._accounts
                if flt in a.service.lower() or flt in a.identifier_value.lower()
            ]

        self.accounts_table.setRowCount(len(rows))
        for i, acct in enumerate(rows):
            # Serial number for display only (stable within the current sorted/filtered view).
            self.accounts_table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            self.accounts_table.setItem(i, 1, QTableWidgetItem(acct.service))
            self.accounts_table.setItem(i, 2, QTableWidgetItem(acct.identifier_value))
            self.accounts_table.setItem(i, 3, QTableWidgetItem(self._fmt_gmt8(acct.created_at_utc)))
            self.accounts_table.setItem(
                i,
                4,
                QTableWidgetItem(self._fmt_gmt8(acct.updated_at_utc)),
            )
        self.accounts_table.resizeColumnsToContents()
        # Avoid Qt defaulting a "current cell" highlight that looks like a selection.
        self.accounts_table.setCurrentCell(-1, -1)
        self._on_accounts_selection_changed()

    @staticmethod
    def _fmt_gmt8(utc_ts: str) -> str:
        """
        Format stored UTC timestamp (YYYY-MM-DDTHH:MM:SSZ) as GMT+8 with time.
        """
        s = (utc_ts or "").strip()
        if not s:
            return ""
        try:
            # Stored format uses trailing 'Z'.
            if s.endswith("Z"):
                dt = datetime.fromisoformat(s[:-1]).replace(tzinfo=UTC)
            else:
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
            gmt8 = timezone(timedelta(hours=8))
            dt2 = dt.astimezone(gmt8)
            return dt2.strftime("%Y-%m-%d %H:%M:%S GMT+8")
        except Exception:
            return s

    def _refresh_runs(self) -> None:
        self.runs_list.clear()
        if self._run_repo is None:
            return
        runs = self._run_repo.list_runs()
        for r in runs:
            self.runs_list.addItem(f"{self._fmt_gmt8(r.created_at_utc)}  |  run #{r.id}")
        if runs:
            self.runs_list.setCurrentRow(0)
        self._sync_run_actions()

    def _selected_run_id(self) -> int | None:
        if self._run_repo is None:
            return None
        row = self.runs_list.currentRow()
        if row < 0:
            return None
        runs = self._run_repo.list_runs()
        if row >= len(runs):
            return None
        return runs[row].id

    def _refresh_results(self) -> None:
        self.results_table.setRowCount(0)
        run_id = self._selected_run_id()
        if run_id is None or self._result_repo is None:
            return
        results = self._result_repo.list_results_for_run(run_id)

        acct_by_id = {a.id: a for a in self._accounts}
        self.results_table.setRowCount(len(results))
        for i, r in enumerate(results):
            acct = acct_by_id.get(r.account_id)
            service = acct.service if acct else f"account:{r.account_id}"
            ident = acct.identifier_value if acct else ""
            self.results_table.setItem(i, 0, QTableWidgetItem(service))
            self.results_table.setItem(i, 1, QTableWidgetItem(ident))
            self.results_table.setItem(i, 2, QTableWidgetItem(r.provider))
            self.results_table.setItem(i, 3, QTableWidgetItem(r.status))
        self.results_table.resizeColumnsToContents()

    def _sync_run_actions(self) -> None:
        has_run = self._selected_run_id() is not None
        self.delete_run_btn.setEnabled(has_run)

    def _on_run_selection_changed(self, _row: int) -> None:
        self._sync_run_actions()
        self._refresh_results()

    def _on_delete_run(self) -> None:
        run_id = self._selected_run_id()
        if run_id is None or self._run_repo is None:
            return

        res = QMessageBox.question(
            self,
            "Delete Run",
            f"Delete run #{run_id} and associated results?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if res != QMessageBox.Yes:
            return

        self._run_repo.delete_run(run_id)
        self._refresh_runs()
        self._refresh_results()
        self.statusBar().showMessage(f"Run #{run_id} deleted", 2500)

    def _on_accounts_selection_changed(self) -> None:
        sel_model = self.accounts_table.selectionModel()
        has_sel = bool(sel_model and sel_model.hasSelection())
        self.edit_btn.setEnabled(has_sel)
        self.delete_btn.setEnabled(has_sel)

    def _select_single_account_row(self, row: int, _col: int) -> None:
        # Enforce single-row selection and clear previous "current" focus outline.
        sel = self.accounts_table.selectionModel()
        if sel is None:
            return
        idx = self.accounts_table.model().index(row, 0)
        sel.select(idx, QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
        self.accounts_table.setCurrentCell(row, 0)

    def _select_single_result_row(self, row: int, _col: int) -> None:
        sel = self.results_table.selectionModel()
        if sel is None:
            return
        idx = self.results_table.model().index(row, 0)
        sel.select(idx, QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
        self.results_table.setCurrentCell(row, 0)

    def _selected_account_index(self) -> int | None:
        sel = self.accounts_table.selectionModel()
        if sel is None or not sel.hasSelection():
            return None

        row = sel.selectedRows()[0].row()
        flt = self.filter_edit.text().strip().lower()
        if not flt:
            return row

        # Map filtered row -> index in _accounts (stable source of truth).
        filtered = [
            (idx, a)
            for idx, a in enumerate(self._accounts)
            if flt in a.service.lower() or flt in a.identifier_value.lower()
        ]
        if row < 0 or row >= len(filtered):
            return None
        return filtered[row][0]

    def _on_add_account(self) -> None:
        dlg = AccountDialog(self, title="Add Account")
        if dlg.exec() != QDialog.Accepted:
            return
        row = dlg.get_value()
        self.add_account(AccountRow(service=row.service, identifier=row.identifier))

    def _on_edit_account(self) -> None:
        idx = self._selected_account_index()
        if idx is None:
            return
        current = self._accounts[idx]
        dlg = AccountDialog(
            self,
            title="Edit Account",
            initial=AccountRow(service=current.service, identifier=current.identifier_value),
        )
        if dlg.exec() != QDialog.Accepted:
            return
        row = dlg.get_value()
        self.edit_account(idx, AccountRow(service=row.service, identifier=row.identifier))

    def _on_delete_account(self) -> None:
        idx = self._selected_account_index()
        if idx is None:
            return
        acct = self._accounts[idx]
        res = QMessageBox.question(
            self,
            "Delete Account",
            f"Delete account for service '{acct.service}'?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if res != QMessageBox.Yes:
            return
        self.delete_account(idx)

    def add_account(self, account: AccountRow) -> None:
        if self._repo is None:
            return
        self._repo.add_account(account.service, "email", account.identifier)
        self._accounts = self._repo.list_accounts()
        self._refresh_accounts_table()
        self.statusBar().showMessage("Account added", 2500)

    def edit_account(self, index: int, account: AccountRow) -> None:
        if self._repo is None:
            return
        acct_id = self._accounts[index].id
        self._repo.update_account(acct_id, account.service, "email", account.identifier)
        self._accounts = self._repo.list_accounts()
        self._refresh_accounts_table()
        self.statusBar().showMessage("Account updated", 2500)

    def delete_account(self, index: int) -> None:
        if self._repo is None:
            return
        acct_id = self._accounts[index].id
        self._repo.delete_account(acct_id)
        self._accounts = self._repo.list_accounts()
        self._refresh_accounts_table()
        self.statusBar().showMessage("Account deleted", 2500)

    def _ensure_vault_unlocked(self) -> bool:
        db_path = vault_db_path()
        if vault_exists(db_path):
            dlg = VaultDialog(self, mode="unlock")
            if dlg.exec() != QDialog.Accepted:
                return False
            try:
                self._session = open_vault(db_path, dlg.get_password())
            except VaultLockedError:
                QMessageBox.warning(self, "Unlock Failed", "Invalid master password.")
                return self._ensure_vault_unlocked()
        else:
            dlg = VaultDialog(self, mode="create")
            if dlg.exec() != QDialog.Accepted:
                return False
            self._session = create_vault(db_path, dlg.get_password())

        self._repo = AccountRepo(self._session)
        self._accounts = self._repo.list_accounts()
        self._run_repo = RunRepo(self._session)
        self._result_repo = ResultRepo(self._session)
        self._cache_repo = HashCacheRepo(self._session)
        return True

    def _on_check_now(self) -> None:
        if self._run_repo is None or self._result_repo is None or self._cache_repo is None:
            return

        self.statusBar().showMessage("Running checks...", 2500)
        run_id = self._run_repo.create_run()

        for acct in self._accounts:
            norm = acct.identifier_value.strip().lower()
            digest_hex = sha1(norm.encode("utf-8")).hexdigest().upper()
            cache_payload: dict[str, Any] = {
                "identifier_sha1": digest_hex,
                "prefix5": digest_hex[:5],
                "algo": "sha1",
            }
            self._cache_repo.upsert(acct.id, "identifier-sha1", 1, cache_payload)

            self._result_repo.add_result(
                run_id=run_id,
                account_id=acct.id,
                provider="pwnchecker",
                status="ok",
                data={"cache_provider": "identifier-sha1", "cache_version": 1},
            )

        self._refresh_runs()
        self._refresh_results()
        self.tabs.setCurrentWidget(self.reports_tab)
        self.statusBar().showMessage(f"Run #{run_id} completed (stub)", 3500)
