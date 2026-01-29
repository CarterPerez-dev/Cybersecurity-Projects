"""
ⒸAngelaMos | 2026
main.py
"""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from caesar_cipher.analyzer import FrequencyAnalyzer
from caesar_cipher.cipher import CaesarCipher
from caesar_cipher.utils import read_input, validate_key, write_output


app = typer.Typer(
    name = "caesar-cipher",
    help = "Caesar cipher encryption, decryption, and brute-force cracking tool",
    no_args_is_help = True,
)
console = Console()


@app.command()
def encrypt(
    text: Annotated[
        str | None,
        typer.Argument(help = "Text to encrypt (or use --input-file or stdin)"),
    ] = None,
    key: Annotated[int,
                   typer.Option("--key",
                                "-k",
                                help = "Shift key (0-25)")] = 3,
    input_file: Annotated[
        Path | None,
        typer.Option("--input-file",
                     "-i",
                     help = "Input file path")] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file",
                     "-o",
                     help = "Output file path")] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet",
                     "-q",
                     help = "Suppress output messages")] = False,
) -> None:
    """
    Encrypt text using Caesar cipher with specified shift key
    """
    try:
        validate_key(key)
        plaintext = read_input(text, input_file)
        cipher = CaesarCipher(key = key)
        encrypted = cipher.encrypt(plaintext)

        if not quiet and not output_file:
            console.print(f"[green]Encrypted:[/green] {encrypted}")
        else:
            write_output(encrypted, output_file, quiet)

    except (ValueError, OSError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code = 1) from None


@app.command()
def decrypt(
    text: Annotated[
        str | None,
        typer.Argument(help = "Text to decrypt (or use --input-file or stdin)"),
    ] = None,
    key: Annotated[int,
                   typer.Option("--key",
                                "-k",
                                help = "Shift key (0-25)")] = 3,
    input_file: Annotated[
        Path | None,
        typer.Option("--input-file",
                     "-i",
                     help = "Input file path")] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file",
                     "-o",
                     help = "Output file path")] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet",
                     "-q",
                     help = "Suppress output messages")] = False,
) -> None:
    """
    Decrypt text using Caesar cipher with specified shift key
    """
    try:
        validate_key(key)
        ciphertext = read_input(text, input_file)
        cipher = CaesarCipher(key = key)
        decrypted = cipher.decrypt(ciphertext)

        if not quiet and not output_file:
            console.print(f"[blue]Decrypted:[/blue] {decrypted}")
        else:
            write_output(decrypted, output_file, quiet)

    except (ValueError, OSError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code = 1) from None


@app.command()
def crack(
    text: Annotated[
        str | None,
        typer.Argument(help = "Text to crack (or use --input-file or stdin)"),
    ] = None,
    input_file: Annotated[
        Path | None,
        typer.Option("--input-file",
                     "-i",
                     help = "Input file path")] = None,
    top: Annotated[int,
                   typer.Option("--top",
                                "-t",
                                help = "Show top N candidates")] = 5,
    show_all: Annotated[
        bool,
        typer.Option("--all",
                     "-a",
                     help = "Show all 26 possible shifts")] = False,
) -> None:
    """
    Brute-force decrypt text by trying all shifts with frequency analysis ranking
    """
    try:
        ciphertext = read_input(text, input_file)
        candidates = CaesarCipher.crack(ciphertext)
        analyzer = FrequencyAnalyzer()
        ranked = analyzer.rank_candidates(candidates)

        table = Table(title = "Caesar Cipher Brute Force Results")
        table.add_column("Rank", style = "cyan", justify = "right")
        table.add_column("Shift", style = "magenta", justify = "right")
        table.add_column("Score", style = "yellow", justify = "right")
        table.add_column("Decrypted Text", style = "green")

        display_count = len(ranked) if show_all else min(top, len(ranked))

        for rank, (shift, text_result, score) in enumerate(ranked[:display_count], 1):
            table.add_row(
                str(rank),
                str(shift),
                f"{score:.2f}",
                text_result[: 80]
            )

        console.print(table)
        console.print(
            f"\n[bold]Best match (Shift {ranked[0][0]}):[/bold] {ranked[0][1]}"
        )

    except (ValueError, OSError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code = 1) from None


if __name__ == "__main__":
    app()
