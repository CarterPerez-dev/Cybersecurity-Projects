"""
©AngelaMos | 2026
cli.py
"""


from typing import Annotated

import typer

from dlp_scanner import __version__
from dlp_scanner.commands.report import report_app
from dlp_scanner.commands.scan import register


app = typer.Typer(
    name = "dlp-scan",
    help = (
        "Data Loss Prevention scanner for files, "
        "databases, and network traffic"
    ),
    no_args_is_help = True,
)


def _version_callback(value: bool) -> None:
    """
    Print version and exit
    """
    if value:
        typer.echo(f"dlp-scanner {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    config: Annotated[
        str,
        typer.Option(
            "--config",
            "-c",
            help = "Path to config YAML file",
        ),
    ] = "",
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help = "Enable verbose output",
        ),
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback = _version_callback,
            is_eager = True,
            help = "Show version and exit",
        ),
    ] = False,
) -> None:
    """
    DLP Scanner - detect sensitive data across files, databases, and network captures
    """
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["verbose"] = verbose


register(app)
app.add_typer(report_app, name = "report")
