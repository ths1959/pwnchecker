from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication


def apply_app_style(app: QApplication) -> None:
    # Cyber/game-inspired dark theme, still work-focused and readable.
    # Prefer a monospace-ish UI font if present.
    font = QFont("Cascadia Mono", 10)
    if not font.exactMatch():
        font = QFont("Consolas", 10)
    app.setFont(font)
    app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
    app.setStyleSheet(
        """
        QWidget {
          background: #070b12;
          color: #d6faff;
        }

        QMainWindow > QWidget {
          background: #070b12;
        }

        QLabel#app_title {
          font-size: 18px;
          font-weight: 700;
          color: #79ffe1;
        }

        QLabel#app_subtitle {
          color: #76b7ff;
        }

        QTabWidget::pane {
          border: 1px solid #16314d;
          top: -1px;
          background: #0b1220;
        }

        QTabBar::tab {
          background: #0a1020;
          border: 1px solid #16314d;
          padding: 8px 12px;
          margin-right: 4px;
          border-top-left-radius: 6px;
          border-top-right-radius: 6px;
          min-width: 90px;
          color: #a6d7ff;
        }

        QTabBar::tab:selected {
          background: #0b1220;
          border-bottom-color: #0b1220;
          color: #79ffe1;
        }

        QPushButton {
          background: #0a1020;
          border: 1px solid #1b3b57;
          padding: 6px 10px;
          border-radius: 6px;
          color: #d6faff;
        }

        QPushButton:hover {
          background: #0c1630;
          border-color: #79ffe1;
        }

        QPushButton:pressed {
          background: #0a1430;
        }

        QPushButton:disabled {
          color: #5b7187;
          border-color: #14283a;
          background: #081020;
        }

        QPushButton#check_now_btn {
          background: #0d2a2c;
          border-color: #79ffe1;
          color: #79ffe1;
          font-weight: 700;
          padding: 7px 12px;
        }

        QPushButton#check_now_btn:hover {
          background: #103a3c;
        }

        QLineEdit {
          background: #070f1e;
          border: 1px solid #1b3b57;
          padding: 6px 10px;
          border-radius: 6px;
          color: #d6faff;
        }

        QLineEdit:focus {
          border-color: #76b7ff;
        }

        QTableWidget {
          background: #0b1220;
          border: 1px solid #16314d;
          gridline-color: #10263a;
          selection-background-color: #0d2a2c;
          selection-color: #79ffe1;
        }

        QHeaderView::section {
          background: #070f1e;
          border: 0px;
          border-bottom: 1px solid #16314d;
          padding: 8px 10px;
          font-weight: 700;
          color: #a6d7ff;
        }

        QListWidget {
          background: #0b1220;
          border: 1px solid #16314d;
        }

        QStatusBar {
          background: #070b12;
          color: #76b7ff;
        }
        """
    )
