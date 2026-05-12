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


class PasswordDialog(QDialog):
    def __init__(self, parent: QWidget, *, service: str) -> None:
        super().__init__(parent)
        self.setModal(True)
        self.setWindowTitle(f"Password for {service}")

        self.password = QLineEdit()
        self.password.setObjectName("check_password")
        self.password.setEchoMode(QLineEdit.Password)

        form = QFormLayout()
        form.addRow("Password", self.password)

        buttons = QDialogButtonBox()
        self.ok_btn = buttons.addButton("Check", QDialogButtonBox.AcceptRole)
        self.skip_btn = buttons.addButton("Skip", QDialogButtonBox.DestructiveRole)
        self.cancel_btn = buttons.addButton("Cancel Run", QDialogButtonBox.RejectRole)

        self.ok_btn.clicked.connect(self._on_ok)
        self.skip_btn.clicked.connect(self._on_skip)
        self.cancel_btn.clicked.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

        self._skipped = False

    def _on_ok(self) -> None:
        if not self.password.text():
            QMessageBox.warning(self, "Invalid Input", "Password is required to run the check.")
            return
        self.accept()

    def _on_skip(self) -> None:
        self._skipped = True
        self.accept()

    def skipped(self) -> bool:
        return self._skipped

    def get_password(self) -> str:
        return self.password.text()

