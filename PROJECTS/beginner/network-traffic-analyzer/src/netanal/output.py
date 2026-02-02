"""
ⒸAngelaMos | 2026
output.py

Rich console output formatting for network traffic analysis
"""

import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from netanal.constants import ByteUnits, ProtocolColors, TimeConstants
from netanal.models import CaptureStatistics, PacketInfo, Protocol


def get_console() -> Console:
    """
    Create console with environment-aware settings
    """
    if not sys.stdout.isatty():
        return Console(force_terminal=False, no_color=True)
    if os.environ.get("CI"):
        return Console(force_terminal=True, force_interactive=False)
    if os.environ.get("NO_COLOR"):
        return Console(no_color=True)
    return Console()


console = get_console()


def create_capture_progress() -> Progress:
    """
    Create progress display for packet capture
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def _get_protocol_color(protocol: Protocol) -> str:
    """
    Get Rich console color for a protocol
    """
    return ProtocolColors.RICH.get(protocol.value, "white")


def print_packet(packet: PacketInfo) -> None:
    """
    Print single packet information
    """
    color = _get_protocol_color(packet.protocol)
    port_info = ""

    if packet.src_port and packet.dst_port:
        port_info = f":{packet.src_port} -> :{packet.dst_port}"

    console.print(
        f"[{color}]{packet.protocol.value:5}[/{color}] "
        f"{packet.src_ip:15} -> {packet.dst_ip:15} "
        f"{port_info:20} "
        f"[dim]{packet.size:6} bytes[/dim]"
    )


def print_protocol_table(stats: CaptureStatistics) -> None:
    """
    Print protocol distribution table
    """
    table = Table(title="Protocol Distribution")
    table.add_column("Protocol", style="cyan", justify="left")
    table.add_column("Packets", style="green", justify="right")
    table.add_column("Bytes", style="yellow", justify="right")
    table.add_column("Percentage", style="magenta", justify="right")

    percentages = stats.get_protocol_percentages()

    for protocol in sorted(stats.protocol_distribution.keys(),
                           key=lambda p: p.value):
        count = stats.protocol_distribution[protocol]
        bytes_count = stats.protocol_bytes.get(protocol, 0)
        pct = percentages.get(protocol, 0.0)
        table.add_row(
            protocol.value,
            f"{count:,}",
            format_bytes(bytes_count),
            f"{pct:.1f}%",
        )

    console.print(table)


def print_top_talkers(stats: CaptureStatistics, limit: int = 10) -> None:
    """
    Print top talkers table
    """
    table = Table(title=f"Top {limit} Talkers")
    table.add_column("IP Address", style="cyan", justify="left")
    table.add_column("Packets Sent", style="green", justify="right")
    table.add_column("Packets Recv", style="yellow", justify="right")
    table.add_column("Bytes Sent", style="blue", justify="right")
    table.add_column("Bytes Recv", style="magenta", justify="right")
    table.add_column("Total", style="white", justify="right")

    top_talkers = stats.get_top_talkers(limit)

    for endpoint in top_talkers:
        table.add_row(
            endpoint.ip_address,
            f"{endpoint.packets_sent:,}",
            f"{endpoint.packets_received:,}",
            format_bytes(endpoint.bytes_sent),
            format_bytes(endpoint.bytes_received),
            format_bytes(endpoint.total_bytes),
        )

    console.print(table)


def print_capture_summary(stats: CaptureStatistics) -> None:
    """
    Print capture session summary panel
    """
    duration = stats.duration_seconds
    avg_bandwidth = stats.average_bandwidth

    summary_lines = [
        f"Duration: {format_duration(duration)}",
        f"Total Packets: {stats.total_packets:,}",
        f"Total Bytes: {format_bytes(stats.total_bytes)}",
        f"Average Bandwidth: {format_bytes(avg_bandwidth)}/s",
        f"Unique Endpoints: {len(stats.endpoints)}",
        f"Protocols Seen: {len(stats.protocol_distribution)}",
    ]

    panel = Panel(
        "\n".join(summary_lines),
        title="[bold]Capture Summary[/bold]",
        border_style="green",
    )
    console.print(panel)


def print_bandwidth_stats(stats: CaptureStatistics) -> None:
    """
    Print bandwidth statistics
    """
    if not stats.bandwidth_samples:
        console.print("[yellow]No bandwidth samples recorded[/yellow]")
        return

    samples = stats.bandwidth_samples
    max_bps = max(s.bytes_per_second for s in samples)
    min_bps = min(s.bytes_per_second for s in samples)
    avg_bps = sum(s.bytes_per_second for s in samples) / len(samples)

    table = Table(title="Bandwidth Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green", justify="right")

    table.add_row("Peak", f"{format_bytes(max_bps)}/s")
    table.add_row("Minimum", f"{format_bytes(min_bps)}/s")
    table.add_row("Average", f"{format_bytes(avg_bps)}/s")
    table.add_row("Samples", f"{len(samples)}")

    console.print(table)


def print_interfaces(interfaces: list[str]) -> None:
    """
    Print available network interfaces
    """
    table = Table(title="Available Interfaces")
    table.add_column("Interface", style="cyan")

    for iface in interfaces:
        table.add_row(iface)

    console.print(table)


def print_error(message: str) -> None:
    """
    Print error message
    """
    console.print(f"[red]Error:[/red] {message}")


def print_warning(message: str) -> None:
    """
    Print warning message
    """
    console.print(f"[yellow]Warning:[/yellow] {message}")


def print_success(message: str) -> None:
    """
    Print success message
    """
    console.print(f"[green]Success:[/green] {message}")


def format_bytes(num_bytes: int | float) -> str:
    """
    Format byte count with appropriate unit
    """
    for unit in ByteUnits.UNITS[:-1]:
        if abs(num_bytes) < ByteUnits.BYTES_PER_KB:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= ByteUnits.BYTES_PER_KB
    return f"{num_bytes:.1f} {ByteUnits.UNITS[-1]}"


def format_duration(seconds: float) -> str:
    """
    Format duration in human-readable form
    """
    if seconds < TimeConstants.SECONDS_PER_MINUTE:
        return f"{seconds:.1f}s"
    if seconds < TimeConstants.SECONDS_PER_HOUR:
        minutes = int(seconds // TimeConstants.SECONDS_PER_MINUTE)
        secs = seconds % TimeConstants.SECONDS_PER_MINUTE
        return f"{minutes}m {secs:.1f}s"
    hours = int(seconds // TimeConstants.SECONDS_PER_HOUR)
    minutes = int(
        (seconds % TimeConstants.SECONDS_PER_HOUR) //
        TimeConstants.SECONDS_PER_MINUTE
    )
    return f"{hours}h {minutes}m"


__all__ = [
    "console",
    "create_capture_progress",
    "format_bytes",
    "format_duration",
    "get_console",
    "print_bandwidth_stats",
    "print_capture_summary",
    "print_error",
    "print_interfaces",
    "print_packet",
    "print_protocol_table",
    "print_success",
    "print_top_talkers",
    "print_warning",
]
