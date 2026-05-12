from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from .ui.main_window import MainWindow
from .ui.style import apply_app_style

_APP_ICON_PATH = (Path(__file__).resolve().parents[2] / "assets" / "pwnchecker.png").resolve()


def main() -> int:
    app = QApplication(sys.argv)
    if _APP_ICON_PATH.exists():
        icon = QIcon(str(_APP_ICON_PATH))
        app.setWindowIcon(icon)
    apply_app_style(app)
    win = MainWindow()
    if _APP_ICON_PATH.exists():
        win.setWindowIcon(QIcon(str(_APP_ICON_PATH)))
    if not win.is_ready():
        return 0
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
