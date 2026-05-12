from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from .ui.main_window import MainWindow
from .ui.style import apply_app_style


def main() -> int:
    app = QApplication(sys.argv)
    apply_app_style(app)
    win = MainWindow()
    if not win.is_ready():
        return 0
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
