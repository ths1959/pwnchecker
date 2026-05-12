from __future__ import annotations

from typer.testing import CliRunner

from pwnchecker.cli import app

runner = CliRunner()


def test_cli_init_add_list_show_remove(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PWNCHECKER_DATA_DIR", str(tmp_path))

    # init (password + confirm)
    res = runner.invoke(app, ["init"], input="pw123\npw123\n")
    assert res.exit_code == 0
    assert "Vault created" in res.stdout

    # add
    res = runner.invoke(
        app,
        ["add", "--service", "GitHub", "--identifier", "dev@example.com"],
        input="pw123\n",
    )
    assert res.exit_code == 0
    assert "Added account" in res.stdout

    # list (redacted)
    res = runner.invoke(app, ["list"], input="pw123\n")
    assert res.exit_code == 0
    assert "GitHub" in res.stdout
    assert "dev@example.com" not in res.stdout

    # list (reveal)
    res = runner.invoke(app, ["list", "--reveal"], input="pw123\n")
    assert res.exit_code == 0
    assert "dev@example.com" in res.stdout

    # show (reveal)
    res = runner.invoke(app, ["show", "1", "--reveal"], input="pw123\n")
    assert res.exit_code == 0
    assert "Identifier: dev@example.com" in res.stdout

    # remove
    res = runner.invoke(app, ["remove", "1", "--yes"], input="pw123\n")
    assert res.exit_code == 0
    assert "Removed" in res.stdout

    # list empty
    res = runner.invoke(app, ["list"], input="pw123\n")
    assert res.exit_code == 0
    assert "No accounts" in res.stdout


def test_cli_wrong_password(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PWNCHECKER_DATA_DIR", str(tmp_path))

    res = runner.invoke(app, ["init"], input="pw123\npw123\n")
    assert res.exit_code == 0

    res = runner.invoke(
        app,
        ["add", "--service", "GitHub", "--identifier", "dev@example.com"],
        input="wrong\n",
    )
    assert res.exit_code == 2
    assert "Invalid master password" in res.stdout

