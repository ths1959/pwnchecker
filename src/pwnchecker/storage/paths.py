from __future__ import annotations

import os
from pathlib import Path

from platformdirs import user_data_dir

APP_NAME = "PwnChecker"


def data_dir() -> Path:
    override = os.environ.get("PWNCHECKER_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return Path(user_data_dir(APP_NAME, APP_NAME)).resolve()


def vault_db_path() -> Path:
    return data_dir() / "vault.sqlite3"

