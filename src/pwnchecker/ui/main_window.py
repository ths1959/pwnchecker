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
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PwnChecker")
        self.setMinimumSize(900, 600)

        self._accounts: list[AccountRow] = [
            AccountRow(service="Example", identifier="user@example.com"),
        ]
        self._runs: list[RunSummary] = []

        root = QWidget()
        root_layout = QVBoxLayout(root)

        header = QHBoxLayout()
        title = QLabel("PwnChecker")
        title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        title.setStyleSheet("font-size: 18px; font-weight: 600;")

        self.check_now_btn = QPushButton("Check Now")
        self.check_now_btn.setObjectName("check_now_btn")
        self.check_now_btn.clicked.connect(self._on_check_now)

        header.addWidget(title)
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

        self._refresh_accounts_table()
        self._refresh_reports()

    def _build_accounts_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        controls = QHBoxLayout()
        self.filter_edit = QLineEdit()
        self.filter_edit.setObjectName("accounts_filter")
        self.filter_edit.setPlaceholderText("Filter accounts...")
        self.filter_edit.textChanged.connect(self._refresh_accounts_table)

        self.add_btn = QPushButton("Add")
        self.add_btn.setObjectName("add_account_btn")
        self.add_btn.clicked.connect(self._on_add_account)

        self.edit_btn = QPushButton("Edit")
        self.edit_btn.setObjectName("edit_account_btn")
        self.edit_btn.setEnabled(False)
        self.edit_btn.clicked.connect(self._on_edit_account)

        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setObjectName("delete_account_btn")
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
        self.accounts_table.itemSelectionChanged.connect(self._on_accounts_selection_changed)

        hint = QLabel("Account storage UI is placeholder in Phase 0.1 (in-memory only).")
        hint.setStyleSheet("color: #555;")

        layout.addWidget(hint)
        layout.addLayout(controls)
        layout.addWidget(self.accounts_table)
        return w

    def _build_reports_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        self.runs_list = QListWidget()
        self.runs_list.setObjectName("runs_list")

        hint = QLabel("Run history is placeholder in Phase 0.1.")
        hint.setStyleSheet("color: #555;")

        layout.addWidget(hint)
        layout.addWidget(self.runs_list)
        return w

    def _build_settings_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
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
                if flt in a.service.lower() or flt in a.identifier.lower()
            ]

        self.accounts_table.setRowCount(len(rows))
        for i, acct in enumerate(rows):
            self.accounts_table.setItem(i, 0, QTableWidgetItem(acct.service))
            self.accounts_table.setItem(i, 1, QTableWidgetItem(acct.identifier))
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
            if flt in a.service.lower() or flt in a.identifier.lower()
        ]
        if row < 0 or row >= len(filtered):
            return None
        return filtered[row][0]

    def _on_add_account(self) -> None:
        dlg = AccountDialog(self, title="Add Account")
        if dlg.exec() != QDialog.Accepted:
            return
        self.add_account(dlg.get_value())

    def _on_edit_account(self) -> None:
        idx = self._selected_account_index()
        if idx is None:
            return
        current = self._accounts[idx]
        dlg = AccountDialog(self, title="Edit Account", initial=current)
        if dlg.exec() != QDialog.Accepted:
            return
        self.edit_account(idx, dlg.get_value())

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
        self._accounts.append(account)
        self._refresh_accounts_table()

    def edit_account(self, index: int, account: AccountRow) -> None:
        self._accounts[index] = account
        self._refresh_accounts_table()

    def delete_account(self, index: int) -> None:
        del self._accounts[index]
        self._refresh_accounts_table()

    def _on_check_now(self) -> None:
        # Phase 0.1 stub: create a new run record and show it in Reports.
        run = RunSummary(
            created_at_utc=datetime.now(UTC),
            accounts_checked=len(self._accounts),
        )
        self._runs.append(run)
        self._refresh_reports()
        self.tabs.setCurrentWidget(self.reports_tab)
