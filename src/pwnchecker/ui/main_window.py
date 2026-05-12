from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from PySide6.QtCore import Qt
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
from ..storage.paths import vault_db_path
from ..storage.vault import VaultLockedError, VaultSession, create_vault, open_vault, vault_exists
from .vault_dialog import VaultDialog


@dataclass(frozen=True)
class AccountRow:
    service: str
    identifier: str  # Placeholder for v0.1: no encryption/storage yet.


@dataclass(frozen=True)
class RunSummary:
    created_at_utc: datetime
    accounts_checked: int


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

        self._session: VaultSession | None = session
        self._repo: AccountRepo | None = AccountRepo(session) if session else None
        self._accounts: list[Account] = []
        self._runs: list[RunSummary] = []

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
                # User cancelled unlock/create; keep the window usable but empty.
                self.check_now_btn.setEnabled(False)
                self.add_btn.setEnabled(False)
                self.edit_btn.setEnabled(False)
                self.delete_btn.setEnabled(False)
        else:
            self._accounts = self._repo.list_accounts()

        self._refresh_accounts_table()
        self._refresh_reports()

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
        self.accounts_table.setColumnCount(2)
        self.accounts_table.setHorizontalHeaderLabels(["Service", "Identifier (placeholder)"])
        self.accounts_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.accounts_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.accounts_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.accounts_table.setAlternatingRowColors(True)
        self.accounts_table.verticalHeader().setVisible(False)
        self.accounts_table.itemSelectionChanged.connect(self._on_accounts_selection_changed)

        hint = QLabel("Encrypted account storage is enabled.")
        hint.setStyleSheet("color: #555;")

        layout.addWidget(hint)
        layout.addLayout(controls)
        layout.addWidget(self.accounts_table)
        return w

    def _build_reports_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self.runs_list = QListWidget()
        self.runs_list.setObjectName("runs_list")

        hint = QLabel("Run history is stored locally (checks are stubbed).")
        hint.setStyleSheet("color: #555;")

        layout.addWidget(hint)
        layout.addWidget(self.runs_list)
        return w

    def _build_settings_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        hint = QLabel("Settings UI is placeholder in Phase 0.1.")
        hint.setStyleSheet("color: #555;")
        layout.addWidget(hint)
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
            self.accounts_table.setItem(i, 0, QTableWidgetItem(acct.service))
            self.accounts_table.setItem(i, 1, QTableWidgetItem(acct.identifier_value))
        self.accounts_table.resizeColumnsToContents()
        self._on_accounts_selection_changed()

    def _refresh_reports(self) -> None:
        self.runs_list.clear()
        for run in reversed(self._runs):
            ts = run.created_at_utc.strftime("%Y-%m-%d %H:%M:%SZ")
            self.runs_list.addItem(f"{ts}  |  accounts checked: {run.accounts_checked}")

    def _on_accounts_selection_changed(self) -> None:
        sel_model = self.accounts_table.selectionModel()
        has_sel = bool(sel_model and sel_model.hasSelection())
        self.edit_btn.setEnabled(has_sel)
        self.delete_btn.setEnabled(has_sel)

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
        return True

    def _on_check_now(self) -> None:
        # Phase 0.1 stub: create a new run record and show it in Reports.
        self.statusBar().showMessage("Running checks (stub)...", 2500)
        run = RunSummary(
            created_at_utc=datetime.now(UTC),
            accounts_checked=len(self._accounts),
        )
        self._runs.append(run)
        self._refresh_reports()
        self.tabs.setCurrentWidget(self.reports_tab)
