from __future__ import annotations

# PyInstaller entrypoint.
# Running src/pwnchecker/gui.py directly breaks relative imports because it is
# executed as a script rather than as a package module.

from pwnchecker.gui import main


if __name__ == "__main__":
    raise SystemExit(main())

