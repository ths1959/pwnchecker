from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)


class VaultDialog(QDialog):
    def __init__(self, parent: QWidget, *, mode: str) -> None:
        super().__init__(parent)
        if mode not in {"create", "unlock"}:
            raise ValueError("mode must be 'create' or 'unlock'")

        self._mode = mode
        self.setModal(True)
        self.setWindowTitle("Create Vault" if mode == "create" else "Unlock Vault")

        self.password = QLineEdit()
        self.password.setObjectName("vault_password")
        self.password.setEchoMode(QLineEdit.Password)

        form = QFormLayout()
        form.addRow("Master Password", self.password)

        self.confirm = None
        if mode == "create":
            self.confirm = QLineEdit()
            self.confirm.setObjectName("vault_password_confirm")
            self.confirm.setEchoMode(QLineEdit.Password)
            form.addRow("Confirm Password", self.confirm)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _on_accept(self) -> None:
        pw = self.password.text()
        if not pw:
            QMessageBox.warning(self, "Invalid Input", "Master password is required.")
            return
        if self._mode == "create":
            assert self.confirm is not None
            if pw != self.confirm.text():
                QMessageBox.warning(self, "Invalid Input", "Passwords do not match.")
                return
        self.accept()

    def get_password(self) -> str:
        return self.password.text()

