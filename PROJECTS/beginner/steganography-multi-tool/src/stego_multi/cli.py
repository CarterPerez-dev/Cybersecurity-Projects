"""
stego_multi command-line interface.
"""

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from stego_multi import __version__
from stego_multi.techniques import zero_width


app = typer.Typer(
    help = "Multi-format steganography toolkit.",
    no_args_is_help = True,
)
zw_app = typer.Typer(
    help = "Zero-width character steganography.",
    no_args_is_help = True,
)
app.add_typer(zw_app, name = "zero-width")

err_console = Console(stderr = True)


def _write_text(text: str, output: Path | None) -> None:
    """Write text as UTF-8: to a file if given, otherwise to stdout."""
    if output is not None:
        output.write_text(text, encoding = "utf-8")
    else:
        sys.stdout.buffer.write(text.encode("utf-8") + b"\n")


def _version_callback(value: bool) -> None:
    if value:
        print(f"stego {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback = _version_callback,
            is_eager = True,
            help = "Show version and exit.",
        ),
    ] = False,
) -> None:
    """Multi-format steganography toolkit."""


@zw_app.command("hide")
def zw_hide(
    message: Annotated[str,
                       typer.Option("--message",
                                    "-m",
                                    help = "Secret message to hide.")],
    carrier: Annotated[
        str,
        typer.Option("--carrier",
                     "-c",
                     help = "Visible text to carry the message."),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output",
                     "-o",
                     help = "Write result to a UTF-8 file."),
    ] = None,
) -> None:
    """Hide a message inside carrier text using invisible characters."""
    encoded = zero_width.embed(carrier, message.encode("utf-8"))
    _write_text(encoded, output)


@zw_app.command("reveal")
def zw_reveal(
    text: Annotated[
        str | None,
        typer.Option("--text",
                     "-t",
                     help = "Text containing a hidden message."),
    ] = None,
    input_file: Annotated[
        Path | None,
        typer.Option("--input",
                     "-i",
                     help = "Read carrier text from a UTF-8 file."),
    ] = None,
) -> None:
    """Reveal a message hidden inside text."""
    if text is not None and input_file is not None:
        err_console.print("[red]Error:[/red] use either --text or --input, not both")
        raise typer.Exit(code = 1)
    if input_file is not None:
        text = input_file.read_text(encoding = "utf-8")
    if text is None:
        err_console.print("[red]Error:[/red] provide --text or --input")
        raise typer.Exit(code = 1)
    try:
        payload = zero_width.extract(text)
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code = 1) from exc
    sys.stdout.buffer.write(payload + b"\n")
