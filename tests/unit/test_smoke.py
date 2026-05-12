from typer.testing import CliRunner

from pwnchecker.cli import app

runner = CliRunner()


def test_cli_help_renders() -> None:
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "PwnChecker" in res.stdout or "pwnchecker" in res.stdout.lower()


def test_cli_version() -> None:
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert res.stdout.strip() != ""

