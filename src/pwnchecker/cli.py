import typer

from . import __version__

app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.callback()
def main() -> None:
    """PwnChecker CLI."""


@app.command("version")
def version() -> None:
    """Print PwnChecker version."""
    typer.echo(__version__)


if __name__ == "__main__":
    app()
