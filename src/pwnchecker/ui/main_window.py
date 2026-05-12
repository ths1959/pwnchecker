from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha1
from typing import Any

from PySide6.QtCore import QItemSelectionModel, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..providers.domain_posture import assess_domain
from ..providers.pwned_passwords import PwnedPasswordsClient
from ..storage.accounts import Account, AccountRepo
from ..storage.hash_cache import HashCacheRepo
from ..storage.paths import vault_db_path
from ..storage.results import ResultRepo
from ..storage.runs import RunRepo
from ..storage.settings import SettingsRepo
from ..storage.vault import VaultLockedError, VaultSession, create_vault, open_vault, vault_exists
from .password_dialog import PasswordDialog
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
        self.password_edit = QLineEdit()
        self.password_edit.setObjectName("account_password")
        self.password_edit.setEchoMode(QLineEdit.Password)

        if initial is not None:
            self.service_edit.setText(initial.service)
            self.identifier_edit.setText(initial.identifier)

        form = QFormLayout()
        form.addRow("Service", self.service_edit)
        form.addRow("Email/Username", self.identifier_edit)
        form.addRow("Password (optional)", self.password_edit)

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

    def get_password_optional(self) -> str:
        return self.password_edit.text()


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
        self._settings_repo: SettingsRepo | None = SettingsRepo(session) if session else None

        # UI selection state for batch actions.
        self._checked_account_ids: set[int] = set()
        self._checked_run_ids: set[int] = set()
        self._run_serial_by_id: dict[int, int] = {}
        self._settings_baseline: dict[str, str] = {}

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

        self._load_settings_into_ui()
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
        self.accounts_table.setColumnCount(6)
        self.accounts_table.setHorizontalHeaderLabels(
            ["", "No.", "Service", "Identifier", "Created", "Last Updated"]
        )
        self.accounts_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.accounts_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.accounts_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.accounts_table.setAlternatingRowColors(True)
        self.accounts_table.verticalHeader().setVisible(False)
        self.accounts_table.itemSelectionChanged.connect(self._on_accounts_selection_changed)
        self.accounts_table.cellClicked.connect(self._on_account_cell_clicked)
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
        self.runs_list.itemChanged.connect(self._on_run_item_changed)

        self.results_table = QTableWidget()
        # Replaced by a textual report view for clarity.
        self.results_table.setObjectName("results_table_deprecated")
        self.results_table.hide()

        self.report_text = QTextEdit()
        self.report_text.setObjectName("report_text")
        self.report_text.setReadOnly(True)
        self.report_text.setLineWrapMode(QTextEdit.NoWrap)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        row.addWidget(self.runs_list, 0)
        row.addWidget(self.report_text, 1)

        layout.addLayout(actions)
        layout.addLayout(row)
        return w

    def _build_settings_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self.unsaved_label = QLabel("Unsaved changes")
        self.unsaved_label.setObjectName("unsaved_label")
        self.unsaved_label.setStyleSheet("color: #79ffe1; font-weight: 700;")
        self.unsaved_label.hide()

        self.redact_chk = QPushButton("Report Redaction: ON")
        self.redact_chk.setObjectName("redact_toggle")
        self.redact_chk.setCheckable(True)
        self.redact_chk.clicked.connect(self._on_settings_changed)

        self.remember_pw_chk = QPushButton("Remember Password Hashes: ON")
        self.remember_pw_chk.setObjectName("remember_pw_toggle")
        self.remember_pw_chk.setCheckable(True)
        self.remember_pw_chk.clicked.connect(self._on_settings_changed)

        self.save_settings_btn = QPushButton("Save Settings")
        self.save_settings_btn.setObjectName("save_settings_btn")
        self.save_settings_btn.clicked.connect(self._on_save_settings)

        layout.addWidget(self.redact_chk)
        layout.addWidget(self.remember_pw_chk)
        layout.addWidget(self.save_settings_btn)
        layout.addWidget(self.unsaved_label)
        layout.addStretch(1)
        return w

    def _sync_settings_labels(self) -> None:
        self.redact_chk.setText(
            "Report Redaction: ON" if self.redact_chk.isChecked() else "Report Redaction: OFF"
        )
        self.remember_pw_chk.setText(
            "Remember Password Hashes: ON"
            if self.remember_pw_chk.isChecked()
            else "Remember Password Hashes: OFF"
        )

    def _on_settings_changed(self) -> None:
        self._sync_settings_labels()
        self._update_unsaved_indicator()

    def _load_settings_into_ui(self) -> None:
        if self._settings_repo is None:
            return
        redact = (self._settings_repo.get("report_redact") or "1").strip() != "0"
        remember = (self._settings_repo.get("remember_pw_hash") or "1").strip() != "0"
        self._settings_baseline = {
            "report_redact": "1" if redact else "0",
            "remember_pw_hash": "1" if remember else "0",
        }
        self.redact_chk.blockSignals(True)
        self.remember_pw_chk.blockSignals(True)
        try:
            self.redact_chk.setChecked(redact)
            self.remember_pw_chk.setChecked(remember)
            self._sync_settings_labels()
            self._update_unsaved_indicator()
        finally:
            self.redact_chk.blockSignals(False)
            self.remember_pw_chk.blockSignals(False)

    def _update_unsaved_indicator(self) -> None:
        current = {
            "report_redact": "1" if self.redact_chk.isChecked() else "0",
            "remember_pw_hash": "1" if self.remember_pw_chk.isChecked() else "0",
        }
        dirty = bool(self._settings_baseline) and current != self._settings_baseline
        self.unsaved_label.setVisible(dirty)

    def _on_save_settings(self) -> None:
        if self._settings_repo is None:
            return
        self._settings_repo.set("report_redact", "1" if self.redact_chk.isChecked() else "0")
        self._settings_repo.set(
            "remember_pw_hash",
            "1" if self.remember_pw_chk.isChecked() else "0",
        )
        self._settings_baseline = {
            "report_redact": "1" if self.redact_chk.isChecked() else "0",
            "remember_pw_hash": "1" if self.remember_pw_chk.isChecked() else "0",
        }
        self._update_unsaved_indicator()
        # Apply immediately to the currently displayed report view.
        self._refresh_results()
        self.statusBar().showMessage("Settings saved", 2500)

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
            cb = QTableWidgetItem("")
            cb.setFlags(Qt.ItemIsEnabled | Qt.ItemIsUserCheckable | Qt.ItemIsSelectable)
            cb.setCheckState(Qt.Checked if acct.id in self._checked_account_ids else Qt.Unchecked)
            self.accounts_table.setItem(i, 0, cb)
            # Serial number for display only (stable within the current sorted/filtered view).
            self.accounts_table.setItem(i, 1, QTableWidgetItem(str(i + 1)))
            self.accounts_table.setItem(i, 2, QTableWidgetItem(acct.service))
            self.accounts_table.setItem(i, 3, QTableWidgetItem(acct.identifier_value))
            self.accounts_table.setItem(i, 4, QTableWidgetItem(self._fmt_gmt8(acct.created_at_utc)))
            self.accounts_table.setItem(
                i,
                5,
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
        asc = self._run_repo.list_runs_asc()
        self._run_serial_by_id = {r.id: i + 1 for i, r in enumerate(asc)}

        runs = self._run_repo.list_runs()
        self.runs_list.blockSignals(True)
        try:
            for r in runs:
                serial = self._run_serial_by_id.get(r.id, 0)
                item = QListWidgetItem(f"Run {serial}  |  {self._fmt_gmt8(r.created_at_utc)}")
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked if r.id in self._checked_run_ids else Qt.Unchecked)
                item.setData(Qt.ItemDataRole.UserRole, r.id)
                self.runs_list.addItem(item)
        finally:
            self.runs_list.blockSignals(False)
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
        self.report_text.setPlainText("")
        run_id = self._selected_run_id()
        if run_id is None or self._result_repo is None:
            return
        results = self._result_repo.list_results_for_run(run_id)

        acct_by_id = {a.id: a for a in self._accounts}
        runs = self._run_repo.list_runs() if self._run_repo is not None else []
        run_ts = next((r.created_at_utc for r in runs if r.id == run_id), "")
        serial = self._run_serial_by_id.get(run_id, 0)
        header = f"Run {serial}  |  {self._fmt_gmt8(run_ts)}"

        by_account: dict[int, list[Any]] = {}
        for r in results:
            by_account.setdefault(r.account_id, []).append(r)

        lines: list[str] = [header, ""]
        for acct_id in sorted(by_account.keys()):
            acct = acct_by_id.get(acct_id)
            service = acct.service if acct else f"account:{acct_id}"
            ident = acct.identifier_value if acct else ""
            if self._is_redaction_enabled():
                ident = self._redact_identifier(ident)
            lines.append(f"{service}  |  {ident}")
            for rr in by_account[acct_id]:
                lines.append(f"  - {self._format_result_line(rr.provider, rr.status, rr.data)}")
            lines.append("")

        self.report_text.setPlainText("\n".join(lines).rstrip())

    @staticmethod
    def _format_result_line(provider: str, status: str, data: dict[str, Any]) -> str:
        if provider == "pwnchecker":
            return "Account record processed"

        if provider == "pwned-passwords":
            if status == "skipped":
                return "Password exposure check skipped"
            if status == "error":
                err = str(data.get("error", "Error"))
                return f"Password exposure check failed ({err})"
            if status == "ok":
                try:
                    count = int(data.get("count", 0))
                except Exception:
                    count = 0
                if count <= 0:
                    return "Password not found in breach corpus"
                return f"Password found in breach corpus ({count} times)"

        if provider == "domain-posture":
            msg = str(data.get("message", "")).strip()
            if msg:
                return msg
            return "Unknown: domain configuration could not be verified"

        return f"{provider}: {status}"

    def _is_redaction_enabled(self) -> bool:
        if self._settings_repo is None:
            return True
        return (self._settings_repo.get("report_redact") or "1").strip() != "0"

    @staticmethod
    def _redact_identifier(s: str) -> str:
        s = (s or "").strip()
        if not s:
            return ""
        if "@" in s:
            left, right = s.split("@", 1)
            left_r = (left[:1] + "***") if left else "***"
            right_r = (right[:1] + "***") if right else "***"
            return f"{left_r}@{right_r}"
        if len(s) <= 2:
            return "*" * len(s)
        return s[:2] + "***"

    def _sync_run_actions(self) -> None:
        has_any = bool(self._checked_run_ids)
        self.delete_run_btn.setEnabled(has_any)

    def _on_run_selection_changed(self, _row: int) -> None:
        self._sync_run_actions()
        self._refresh_results()

    def _on_run_item_changed(self, item: QListWidgetItem) -> None:
        run_id = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(run_id, int):
            return
        if item.checkState() == Qt.Checked:
            self._checked_run_ids.add(run_id)
        else:
            self._checked_run_ids.discard(run_id)
        self._sync_run_actions()

    def _selected_run_ids(self) -> list[int]:
        # Preserve old name for minimal churn: now driven by checked boxes.
        return sorted(self._checked_run_ids)

    def _on_delete_run(self) -> None:
        run_ids = sorted(self._checked_run_ids)
        if not run_ids or self._run_repo is None:
            return

        if len(run_ids) == 1:
            serial = self._run_serial_by_id.get(run_ids[0], 0)
            prompt = f"Delete run {serial} and associated results?"
        else:
            prompt = f"Delete {len(run_ids)} run(s) and associated results?"
        res = QMessageBox.question(
            self,
            "Delete Run",
            prompt,
            QMessageBox.Yes | QMessageBox.No,
        )
        if res != QMessageBox.Yes:
            return

        if len(run_ids) == 1:
            self._run_repo.delete_run(run_ids[0])
        else:
            self._run_repo.delete_runs(run_ids)
        self._checked_run_ids.clear()
        self._refresh_runs()
        self._refresh_results()
        self.statusBar().showMessage("Run(s) deleted", 2500)

    def _on_accounts_selection_changed(self) -> None:
        sel_model = self.accounts_table.selectionModel()
        has_sel = bool(sel_model and sel_model.hasSelection())
        self.edit_btn.setEnabled(has_sel)
        self.delete_btn.setEnabled(bool(self._checked_account_ids))

    def _visible_accounts(self) -> list[Account]:
        flt = self.filter_edit.text().strip().lower()
        if not flt:
            return list(self._accounts)
        return [
            a
            for a in self._accounts
            if flt in a.service.lower() or flt in a.identifier_value.lower()
        ]

    def _on_account_cell_clicked(self, row: int, col: int) -> None:
        # Checkbox column toggles batch-selection state.
        if col != 0:
            return
        visible = self._visible_accounts()
        if not (0 <= row < len(visible)):
            return
        acct_id = visible[row].id
        item = self.accounts_table.item(row, 0)
        if item is None:
            return
        if item.checkState() == Qt.Checked:
            self._checked_account_ids.add(acct_id)
        else:
            self._checked_account_ids.discard(acct_id)
        self._on_accounts_selection_changed()

    def _selected_account_ids(self) -> list[int]:
        # Preserve old name for minimal churn: now driven by checked boxes.
        return sorted(self._checked_account_ids)

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
        pw = dlg.get_password_optional()
        self.add_account(
            AccountRow(service=row.service, identifier=row.identifier),
            password=pw or None,
        )

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
        ids = self._selected_account_ids()
        if not ids:
            return
        if len(ids) == 1:
            acct = next((a for a in self._accounts if a.id == ids[0]), None)
            service = acct.service if acct else str(ids[0])
            prompt = f"Delete account for service '{service}'?"
        else:
            prompt = f"Delete {len(ids)} account(s)?"
        res = QMessageBox.question(
            self,
            "Delete Account",
            prompt,
            QMessageBox.Yes | QMessageBox.No,
        )
        if res != QMessageBox.Yes:
            return
        self.delete_accounts(ids)
        self._checked_account_ids.clear()

    def add_account(self, account: AccountRow, *, password: str | None = None) -> None:
        if self._repo is None:
            return
        acct_id = self._repo.add_account(account.service, "email", account.identifier)
        self._accounts = self._repo.list_accounts()
        if (
            password
            and self._cache_repo is not None
            and self._is_remember_password_hash_enabled()
        ):
            digest = sha1(password.encode("utf-8")).hexdigest().upper()
            self._cache_repo.upsert(
                acct_id,
                "pwned-passwords-sha1",
                1,
                {"sha1": digest, "prefix5": digest[:5], "algo": "sha1"},
            )
        self._refresh_accounts_table()
        self.statusBar().showMessage("Account added", 2500)

    def _is_remember_password_hash_enabled(self) -> bool:
        if self._settings_repo is None:
            return True
        return (self._settings_repo.get("remember_pw_hash") or "1").strip() != "0"

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

    def delete_accounts(self, account_ids: list[int]) -> None:
        if self._repo is None:
            return
        self._repo.delete_accounts(account_ids)
        self._accounts = self._repo.list_accounts()
        self._refresh_accounts_table()
        self.statusBar().showMessage("Account(s) deleted", 2500)

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
        self._settings_repo = SettingsRepo(self._session)
        self._load_settings_into_ui()
        return True

    def _on_check_now(self) -> None:
        if self._run_repo is None or self._result_repo is None or self._cache_repo is None:
            return

        self.check_now_btn.setEnabled(False)
        self.statusBar().showMessage("Processing checks...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        QApplication.processEvents()

        run_id = 0
        try:
            run_id = self._run_repo.create_run()

            pp = PwnedPasswordsClient()
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

                cached = self._cache_repo.get(acct.id, "pwned-passwords-sha1", 1)
                sha1_hex: str | None = None
                if cached is not None and self._is_remember_password_hash_enabled():
                    sha1_hex = str(cached.data.get("sha1") or "").strip()

                if not sha1_hex:
                    dlg = PasswordDialog(self, service=acct.service)
                    if dlg.exec() != QDialog.Accepted:
                        self.statusBar().showMessage("Run cancelled", 2500)
                        break
                    if dlg.skipped():
                        self._result_repo.add_result(
                            run_id=run_id,
                            account_id=acct.id,
                            provider="pwned-passwords",
                            status="skipped",
                            data={},
                        )
                        continue
                    sha1_hex = sha1(dlg.get_password().encode("utf-8")).hexdigest().upper()
                    if self._is_remember_password_hash_enabled():
                        self._cache_repo.upsert(
                            acct.id,
                            "pwned-passwords-sha1",
                            1,
                            {"sha1": sha1_hex, "prefix5": sha1_hex[:5], "algo": "sha1"},
                        )

                try:
                    res = pp.check_sha1(sha1_hex)
                    self._result_repo.add_result(
                        run_id=run_id,
                        account_id=acct.id,
                        provider="pwned-passwords",
                        status="ok",
                        data={"count": res.count, "prefix5": res.prefix5},
                    )
                except Exception as e:
                    self._result_repo.add_result(
                        run_id=run_id,
                        account_id=acct.id,
                        provider="pwned-passwords",
                        status="error",
                        data={"error": type(e).__name__},
                    )

                # No-key domain posture check (email domain security posture).
                dom = ""
                if "@" in acct.identifier_value:
                    dom = acct.identifier_value.split("@", 1)[1].strip().lower()
                dp = assess_domain(dom)
                self._result_repo.add_result(
                    run_id=run_id,
                    account_id=acct.id,
                    provider="domain-posture",
                    status=dp.status,
                    data={"domain": dp.domain, "message": dp.message},
                )
        finally:
            QApplication.restoreOverrideCursor()
            self.check_now_btn.setEnabled(True)
            self.statusBar().showMessage("Ready", 2500)

        self._refresh_runs()
        self._refresh_results()
        self.tabs.setCurrentWidget(self.reports_tab)
        if run_id:
            self.statusBar().showMessage(f"Run #{run_id} completed", 3500)
