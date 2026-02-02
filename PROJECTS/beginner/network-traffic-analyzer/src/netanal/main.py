"""
ⒸAngelaMos | 2026
main.py

Typer CLI commands for network traffic analyzer
"""

import json
from pathlib import Path
from typing import Annotated, Literal

import typer

from netanal import __version__
from netanal.analyzer import analyze_pcap_file
from netanal.capture import (
    CaptureConfig,
    CaptureEngine,
    GracefulCapture,
    check_capture_permissions,
    get_available_interfaces,
)
from netanal.export import (
    export_to_csv,
    export_to_json,
    statistics_to_dict,
)
from netanal.filters import validate_bpf_filter
from netanal.models import CaptureStatistics, PacketInfo
from netanal.output import (
    console,
    print_bandwidth_stats,
    print_capture_summary,
    print_error,
    print_interfaces,
    print_packet,
    print_protocol_table,
    print_success,
    print_top_talkers,
    print_warning,
)
from netanal.statistics import StatisticsCollector
from netanal.visualization import (
    create_bandwidth_chart,
    create_protocol_bar_chart,
    create_top_talkers_chart,
    generate_all_charts,
    save_chart,
)


ExportFormat = Literal["json", "csv"]
ChartType = Literal["protocols", "top-talkers", "bandwidth", "all"]

app = typer.Typer(
    name="netanal",
    help="[bold cyan]Network Traffic Analyzer[/bold cyan] - Capture and analyze packets",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


def _analyze_pcap_to_stats(pcap_file: Path) -> tuple[CaptureStatistics,
                                                     list[PacketInfo]]:
    """
    Analyze a PCAP file and return statistics with packet list
    """
    packets = analyze_pcap_file(str(pcap_file))
    collector = StatisticsCollector()
    collector.start()

    for packet in packets:
        collector.record_packet(packet)

    return collector.get_statistics(), packets


def version_callback(value: bool) -> None:
    """
    Display version and exit
    """
    if value:
        console.print(
            f"[bold cyan]netanal[/bold cyan] version [green]{__version__}[/green]"
        )
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """
    [bold cyan]Network Traffic Analyzer[/bold cyan]

    Capture and analyze network packets with protocol distribution,
    top talkers identification, and bandwidth visualization.
    """


@app.command()
def capture(
    interface: Annotated[
        str | None,
        typer.Option(
            "--interface",
            "-i",
            help="Network interface to capture on",
        ),
    ] = None,
    filter_expr: Annotated[
        str | None,
        typer.Option(
            "--filter",
            "-f",
            help="BPF filter expression",
        ),
    ] = None,
    count: Annotated[
        int | None,
        typer.Option(
            "--count",
            "-c",
            help="Number of packets to capture",
        ),
    ] = None,
    timeout: Annotated[
        float | None,
        typer.Option(
            "--timeout",
            "-t",
            help="Capture timeout in seconds",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file for results (JSON)",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            help="Show individual packets",
        ),
    ] = False,
) -> None:
    """
    [bold green]Capture[/bold green] live network packets

    Examples:
        netanal capture -i eth0 --count 100
        netanal capture --filter "tcp port 80" --timeout 30
        netanal capture -i lo -c 50 --verbose
    """
    can_capture, msg = check_capture_permissions()
    if not can_capture:
        print_error(f"Cannot capture packets: {msg}")
        raise typer.Exit(1)

    if filter_expr and not validate_bpf_filter(filter_expr):
        print_error(f"Invalid BPF filter: {filter_expr}")
        raise typer.Exit(1)

    config = CaptureConfig(
        interface=interface,
        bpf_filter=filter_expr,
        packet_count=count,
        timeout_seconds=timeout,
    )

    packets_captured: list[PacketInfo] = []

    def on_packet(packet: PacketInfo) -> None:
        if verbose:
            print_packet(packet)
        if output:
            packets_captured.append(packet)

    console.print(
        f"[cyan]Starting capture on {interface or 'all interfaces'}...[/cyan]"
    )
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    engine = CaptureEngine(
        config=config,
        on_packet=on_packet if verbose or output else None
    )

    with GracefulCapture(engine) as cap:
        stats = cap.wait()

    console.print()
    print_capture_summary(stats)
    print_protocol_table(stats)
    print_top_talkers(stats)

    if output:
        export_to_json(stats, output, packets_captured)
        print_success(f"Results saved to {output}")


@app.command()
def analyze(
    pcap_file: Annotated[
        Path,
        typer.Argument(help="PCAP file to analyze"),
    ],
    top_talkers: Annotated[
        int,
        typer.Option(
            "--top-talkers",
            "-t",
            help="Show top N talkers",
        ),
    ] = 10,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help="Output results as JSON",
        ),
    ] = False,
) -> None:
    """
    [bold green]Analyze[/bold green] packets from a PCAP file

    Examples:
        netanal analyze traffic.pcap
        netanal analyze traffic.pcap --top-talkers 20
        netanal analyze traffic.pcap --json
    """
    if not pcap_file.exists():
        print_error(f"File not found: {pcap_file}")
        raise typer.Exit(1)

    console.print(f"[cyan]Analyzing {pcap_file}...[/cyan]")

    stats, _ = _analyze_pcap_to_stats(pcap_file)

    if json_output:
        console.print(json.dumps(statistics_to_dict(stats), indent=2))
    else:
        print_capture_summary(stats)
        print_protocol_table(stats)
        print_top_talkers(stats, limit=top_talkers)


@app.command()
def stats(
    pcap_file: Annotated[
        Path,
        typer.Argument(help="PCAP file to analyze"),
    ],
    bandwidth: Annotated[
        bool,
        typer.Option(
            "--bandwidth",
            "-b",
            help="Show bandwidth statistics",
        ),
    ] = False,
    protocols: Annotated[
        bool,
        typer.Option(
            "--protocols",
            "-p",
            help="Show protocol distribution",
        ),
    ] = False,
    endpoints: Annotated[
        bool,
        typer.Option(
            "--endpoints",
            "-e",
            help="Show endpoint statistics",
        ),
    ] = False,
) -> None:
    """
    [bold green]Display statistics[/bold green] from a PCAP file

    Examples:
        netanal stats traffic.pcap --bandwidth
        netanal stats traffic.pcap --protocols --endpoints
    """
    if not pcap_file.exists():
        print_error(f"File not found: {pcap_file}")
        raise typer.Exit(1)

    stats_result, _ = _analyze_pcap_to_stats(pcap_file)

    print_capture_summary(stats_result)

    if protocols or (not bandwidth and not endpoints):
        print_protocol_table(stats_result)

    if endpoints:
        print_top_talkers(stats_result, limit=20)

    if bandwidth:
        print_bandwidth_stats(stats_result)


@app.command("export")
def export_cmd(
    pcap_file: Annotated[
        Path,
        typer.Argument(help="PCAP file to export"),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Output file path",
        ),
    ],
    format_type: Annotated[
        ExportFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output format",
        ),
    ] = "json",
) -> None:
    """
    [bold green]Export[/bold green] capture data to CSV or JSON

    Examples:
        netanal export traffic.pcap -o results.json -f json
        netanal export traffic.pcap -o packets.csv -f csv
    """
    if not pcap_file.exists():
        print_error(f"File not found: {pcap_file}")
        raise typer.Exit(1)

    stats, packets = _analyze_pcap_to_stats(pcap_file)

    if format_type == "json":
        export_to_json(stats, output, packets)
    elif format_type == "csv":
        export_to_csv(stats, output, packets)

    print_success(f"Exported to {output}")


@app.command()
def chart(
    pcap_file: Annotated[
        Path,
        typer.Argument(help="PCAP file to visualize"),
    ],
    chart_type: Annotated[
        ChartType,
        typer.Option(
            "--type",
            "-t",
            help="Chart type",
        ),
    ] = "all",
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file path (for single chart)",
        ),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option(
            "--output-dir",
            "-d",
            help="Output directory (for all charts)",
        ),
    ] = None,
) -> None:
    """
    [bold green]Generate charts[/bold green] from capture data

    Examples:
        netanal chart traffic.pcap --type protocols -o protocols.png
        netanal chart traffic.pcap --type all -d ./charts/
    """
    if not pcap_file.exists():
        print_error(f"File not found: {pcap_file}")
        raise typer.Exit(1)

    stats, _ = _analyze_pcap_to_stats(pcap_file)

    if chart_type == "all":
        out_dir = output_dir or Path()
        generated = generate_all_charts(stats, out_dir)
        for path in generated:
            print_success(f"Generated {path}")
    else:
        if not output:
            output = Path(f"{chart_type}.png")

        if chart_type == "protocols":
            fig = create_protocol_bar_chart(stats)
        elif chart_type == "top-talkers":
            fig = create_top_talkers_chart(stats)
        else:
            fig = create_bandwidth_chart(stats)

        save_chart(fig, output)
        print_success(f"Generated {output}")


@app.command()
def interfaces() -> None:
    """
    [bold green]List[/bold green] available network interfaces
    """
    ifaces = get_available_interfaces()
    if not ifaces:
        print_warning("No interfaces found")
        raise typer.Exit(0)

    print_interfaces(ifaces)


if __name__ == "__main__":
    app()
