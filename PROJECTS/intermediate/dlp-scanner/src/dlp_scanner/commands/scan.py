"""
©AngelaMos | 2026
scan.py
"""


from pathlib import Path
from typing import Annotated, Any

import typer


FORMAT_HELP: str = ("Output format (console, json, sarif, csv)")
OUTPUT_HELP: str = "Write report to file"
VALID_FORMATS: frozenset[str] = frozenset(
    {
        "console",
        "json",
        "sarif",
        "csv",
    }
)


def scan_file(
    ctx: typer.Context,
    target: Annotated[
        str,
        typer.Argument(help = "File or directory path"),
    ],
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help = FORMAT_HELP,
        ),
    ] = "console",
    output_file: Annotated[
        str,
        typer.Option(
            "--output",
            "-o",
            help = OUTPUT_HELP,
        ),
    ] = "",
) -> None:
    """
    Scan files and directories for sensitive data
    """
    _run_scan(ctx, "file", target, output_format, output_file)


def scan_db(
    ctx: typer.Context,
    target: Annotated[
        str,
        typer.Argument(help = "Database connection URI"),
    ],
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help = FORMAT_HELP,
        ),
    ] = "console",
    output_file: Annotated[
        str,
        typer.Option(
            "--output",
            "-o",
            help = OUTPUT_HELP,
        ),
    ] = "",
) -> None:
    """
    Scan database tables for sensitive data
    """
    _run_scan(ctx, "db", target, output_format, output_file)


def scan_network(
    ctx: typer.Context,
    target: Annotated[
        str,
        typer.Argument(help = "PCAP file path"),
    ],
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help = FORMAT_HELP,
        ),
    ] = "console",
    output_file: Annotated[
        str,
        typer.Option(
            "--output",
            "-o",
            help = OUTPUT_HELP,
        ),
    ] = "",
) -> None:
    """
    Scan network capture files for sensitive data in transit
    """
    _run_scan(
        ctx,
        "network",
        target,
        output_format,
        output_file,
    )


def register(app: typer.Typer) -> None:
    """
    Register scan commands on the root app
    """
    app.command("file")(scan_file)
    app.command("db")(scan_db)
    app.command("network")(scan_network)


def _run_scan(
    ctx: typer.Context,
    scan_type: str,
    target: str,
    output_format: str,
    output_file: str,
) -> None:
    """
    Shared scan execution logic
    """
    from dlp_scanner.config import (
        ScanConfig,
        load_config,
    )
    from dlp_scanner.engine import ScanEngine
    from dlp_scanner.log import configure_logging

    if output_format not in VALID_FORMATS:
        typer.echo(
            f"Invalid format: {output_format}. "
            f"Choose from: "
            f"{', '.join(sorted(VALID_FORMATS))}",
            err = True,
        )
        raise typer.Exit(code = 1)

    obj: dict[str, Any] = ctx.ensure_object(dict)
    config_path: str = obj.get("config_path", "")
    verbose: bool = obj.get("verbose", False)

    if verbose:
        configure_logging(level = "DEBUG")
    elif output_format == "console":
        configure_logging(level = "INFO")
    else:
        configure_logging(level = "WARNING")

    config: ScanConfig
    cfg_path = Path(config_path) if config_path else None
    if cfg_path and cfg_path.exists():
        config = load_config(cfg_path)
    else:
        config = ScanConfig()

    config.output.format = output_format
    if output_file:
        config.output.output_file = output_file

    engine = ScanEngine(config)

    scan_methods = {
        "file": engine.scan_files,
        "db": engine.scan_database,
        "network": engine.scan_network,
    }

    result = scan_methods[scan_type](target)

    if output_file:
        engine.write_report(result, output_file)
        typer.echo(f"Report written to {output_file}")
    elif output_format == "console":
        engine.display_console(result)
    else:
        output = engine.generate_report(result)
        typer.echo(output)

    if result.errors:
        raise typer.Exit(code = 1)
