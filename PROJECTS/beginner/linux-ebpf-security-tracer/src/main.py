"""
©AngelaMos | 2026
main.py
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from .config import OutputFormat, Severity, TracerType
from .detector import DetectionEngine
from .loader import (
    TracerLoader,
    check_kernel_version,
    check_privileges,
)
from .processor import (
    enrich_event,
    parse_raw_event,
    should_include,
)
from .renderer import (
    FileRenderer,
    TableRenderer,
    create_renderer,
)

app = typer.Typer(
    name="ebpf-tracer",
    help="Real-time syscall tracing with eBPF",
    add_completion=False,
)

console = Console()

VERSION = "1.0.0"


def _version_callback(value: bool) -> None:
    """
    Print version and exit
    """
    if value:
        console.print(f"ebpf-tracer v{VERSION}")
        raise typer.Exit()


@app.command()
def trace(
    format: OutputFormat = typer.Option(
        "live",
        "--format",
        "-f",
        help="Output format",
    ),
    severity: Severity = typer.Option(
        "LOW",
        "--severity",
        "-s",
        help="Minimum severity level",
    ),
    pid: int | None = typer.Option(
        None,
        "--pid",
        "-p",
        help="Filter by PID",
    ),
    comm: str | None = typer.Option(
        None,
        "--comm",
        "-c",
        help="Filter by process name",
    ),
    tracer_type: TracerType = typer.Option(
        "all",
        "--type",
        "-t",
        help="Event category filter",
    ),
    no_enrich: bool = typer.Option(
        False,
        "--no-enrich",
        help="Disable /proc enrichment",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Also write events to file",
    ),
    detections_only: bool = typer.Option(
        False,
        "--detections",
        help="Show only detection alerts",
    ),
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version",
    ),
) -> None:
    """
    Start the eBPF security tracer
    """
    check_privileges()
    check_kernel_version()

    detector = DetectionEngine()
    renderer = create_renderer(format)

    file_renderer: FileRenderer | None = None
    if output is not None:
        file_renderer = FileRenderer(output)

    def on_event(ctx: Any, data: Any, size: int) -> None:
        event = parse_raw_event(ctx, data, size)

        if not no_enrich:
            event = enrich_event(event)

        event = detector.evaluate(event)

        if not should_include(
                event,
                severity,
                pid,
                comm,
                tracer_type,
                detections_only,
        ):
            return

        renderer.render(event)

        if file_renderer is not None:
            file_renderer.render(event)

    console.print("[bold green]eBPF Security Tracer[/] "
                  f"v{VERSION}")
    console.print(f"Format: {format} | "
                  f"Min severity: {severity} | "
                  f"Type: {tracer_type}")
    console.print("Press Ctrl+C to stop\n")

    loader = TracerLoader(tracer_type, on_event)

    try:
        loader.load()
        loader.poll()
    finally:
        if isinstance(renderer, TableRenderer):
            renderer.finalize()
        if file_renderer is not None:
            file_renderer.close()
        console.print("\n[bold red]Tracer stopped[/]")
