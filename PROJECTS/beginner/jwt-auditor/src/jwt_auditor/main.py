"""
main.py

CLI entry point with decode, audit, and crack commands via Typer.

decode shows what is inside a token. audit runs the security checks and
prints a scored report. crack tries a wordlist against an HS signed token.
Every command reads the token from an argument, a file, or stdin, so the
tool drops into a pipeline the same way jq or grep would.

Key exports:
  app - the Typer application, registered as the jwt-auditor entry point

Connects to:
  decoder.py - parses the token string
  checks.py - audit command runs the check suite
  signatures.py - crack command recovers the secret
  wordlist.py - default secrets and wordlist loading
  output.py - renders results as tables or JSON
"""

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from jwt_auditor import checks
from jwt_auditor.decoder import DecodedToken, InvalidTokenError, decode
from jwt_auditor.models import AuditReport
from jwt_auditor.output import (
    decoded_to_dict,
    render_decoded,
    render_report,
    report_to_dict,
)
from jwt_auditor.signatures import crack_hmac_secret, supported_hmac_algs
from jwt_auditor.wordlist import COMMON_SECRETS, load_wordlist


app = typer.Typer(
    name = "jwt-auditor",
    help = "Decode and audit JSON Web Tokens for common security mistakes.",
    no_args_is_help = True,
)
console = Console()
err_console = Console(stderr = True)

# Order matters: the index is the severity rank, used to compare fail levels.
_FAIL_LEVELS = ("critical", "high", "medium", "low", "info")


def _read_token(token: str | None, input_file: Path | None) -> str:
    """
    Resolve the token from an argument, a file, or stdin, in that order.

    Reading from stdin lets you pipe a token in without it landing in your
    shell history, which matters because a token is a bearer credential. A
    literal "-" as the argument means stdin, the usual command line idiom.
    """
    if token is not None and token != "-":  # noqa: S105 - "-" is stdin, not a secret
        return token
    if input_file is not None:
        return input_file.read_text(encoding = "utf-8").strip()
    if not sys.stdin.isatty():
        piped = sys.stdin.read().strip()
        if piped:
            return piped
    raise typer.BadParameter(
        "provide a token as an argument, with --input-file, or via stdin"
    )


def _decode_or_exit(raw: str) -> DecodedToken:
    """Decode a token or print the error and exit with code 2."""
    try:
        return decode(raw)
    except InvalidTokenError as exc:
        err_console.print(f"[red]Not a valid JWT:[/red] {exc}")
        raise typer.Exit(code = 2) from None


def _reaches_fail_level(report: AuditReport, fail_level: str) -> bool:
    """Return True if any finding is at or above the configured fail level."""
    highest = report.highest_severity
    if highest is None:
        return False
    return highest.rank <= _FAIL_LEVELS.index(fail_level)


@app.command("decode")
def decode_command(
    token: Annotated[
        str | None,
        typer.Argument(help = "The JWT string (or use --input-file or stdin)"),
    ] = None,
    input_file: Annotated[
        Path | None,
        typer.Option("--input-file",
                     "-i",
                     help = "Read the token from a file"),
    ] = None,
    as_json: Annotated[
        bool,
        typer.Option("--json",
                     help = "Emit machine readable JSON"),
    ] = False,
) -> None:
    """
    Decode a token and print its header, payload, and signature info.

    This never verifies the signature. It only shows what the token claims.
    """
    parsed = _decode_or_exit(_read_token(token, input_file))
    if as_json:
        console.print_json(data = decoded_to_dict(parsed))
    else:
        render_decoded(console, parsed)


@app.command("audit")
def audit_command(
    token: Annotated[
        str | None,
        typer.Argument(help = "The JWT string (or use --input-file or stdin)"),
    ] = None,
    input_file: Annotated[
        Path | None,
        typer.Option("--input-file",
                     "-i",
                     help = "Read the token from a file"),
    ] = None,
    wordlist: Annotated[
        Path | None,
        typer.Option(
            "--wordlist",
            "-w",
            help = "Wordlist of secrets for the HMAC check"
        ),
    ] = None,
    public_key: Annotated[
        Path | None,
        typer.Option(
            "--public-key",
            "-p",
            help = "Public key PEM to test alg confusion"
        ),
    ] = None,
    max_lifetime: Annotated[
        float,
        typer.Option(
            "--max-lifetime",
            help = "Hours before a token counts as long lived"
        ),
    ] = 24.0,
    fail_level: Annotated[
        str,
        typer.
        Option("--fail-level",
               help = "Exit non-zero at this severity or worse"),
    ] = "high",
    as_json: Annotated[
        bool,
        typer.Option("--json",
                     help = "Emit machine readable JSON"),
    ] = False,
) -> None:
    """
    Run the full check suite against a token and print a scored report.

    Exits non-zero when a finding reaches --fail-level, so it drops into a
    CI pipeline as a gate.
    """
    if fail_level not in _FAIL_LEVELS:
        raise typer.BadParameter(
            f"--fail-level must be one of {', '.join(_FAIL_LEVELS)}"
        )

    parsed = _decode_or_exit(_read_token(token, input_file))
    secrets = load_wordlist(wordlist
                            ) if wordlist is not None else list(COMMON_SECRETS)
    key_bytes = public_key.read_bytes() if public_key is not None else None

    report = checks.audit(
        parsed,
        wordlist = secrets,
        public_key_pem = key_bytes,
        max_lifetime_hours = max_lifetime,
    )

    if as_json:
        console.print_json(data = report_to_dict(report))
    else:
        render_report(console, report)

    if _reaches_fail_level(report, fail_level):
        raise typer.Exit(code = 1)


@app.command("crack")
def crack_command(
    token: Annotated[
        str | None,
        typer.Argument(help = "The JWT string (or use --input-file or stdin)"),
    ] = None,
    input_file: Annotated[
        Path | None,
        typer.Option("--input-file",
                     "-i",
                     help = "Read the token from a file"),
    ] = None,
    wordlist: Annotated[
        Path | None,
        typer.Option(
            "--wordlist",
            "-w",
            help = "Wordlist of secrets (defaults to built in)"
        ),
    ] = None,
) -> None:
    """
    Try to recover the HMAC secret of an HS signed token from a wordlist.

    Prints the secret and exits 0 on a hit, or exits 1 if nothing matched.
    """
    parsed = _decode_or_exit(_read_token(token, input_file))

    if parsed.algorithm not in supported_hmac_algs():
        err_console.print(
            f"[yellow]{parsed.algorithm or 'this token'} is not HMAC signed, "
            "there is no shared secret to guess.[/yellow]"
        )
        raise typer.Exit(code = 1)

    secrets = load_wordlist(wordlist
                            ) if wordlist is not None else list(COMMON_SECRETS)
    found = crack_hmac_secret(parsed, secrets)
    if found is None:
        console.print(
            f"[red]No secret in the list of {len(secrets)} matched.[/red]"
        )
        raise typer.Exit(code = 1)

    console.print(f"[bold green]Secret found:[/bold green] {found!r}")
    console.print("The token can now be forged. Rotate this key.")


if __name__ == "__main__":
    app()
