"""
ⒸAngelaMos | 2026
output.py

Rich terminal output formatting for DNS results
"""

from __future__ import annotations

import json
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from dnslookup.resolver import (
    DNSResult,
    RecordType,
    TraceResult,
)

console = Console()


RECORD_COLORS: dict[RecordType,
                    str] = {
                        RecordType.A: "green",
                        RecordType.AAAA: "blue",
                        RecordType.MX: "magenta",
                        RecordType.NS: "cyan",
                        RecordType.TXT: "yellow",
                        RecordType.CNAME: "red",
                        RecordType.SOA: "white",
                        RecordType.PTR: "bright_cyan",
                    }


def get_record_color(record_type: RecordType) -> str:
    """
    Get the color for a record type
    """
    return RECORD_COLORS.get(record_type, "white")


def format_ttl(ttl: int) -> str:
    """
    Format TTL in human-readable format
    """
    if ttl >= 86400:
        days = ttl // 86400
        return f"{days}d"
    elif ttl >= 3600:
        hours = ttl // 3600
        return f"{hours}h"
    elif ttl >= 60:
        minutes = ttl // 60
        return f"{minutes}m"
    return f"{ttl}s"


def print_header(
    domain: str,
    icon: str = ":globe_showing_americas:"
) -> None:
    """
    Print a styled header for DNS lookup
    """
    console.print()
    console.print(
        f"{icon} [bold cyan]DNS Lookup:[/bold cyan] [bold white]{domain}[/bold white]"
    )
    console.rule(style = "blue")


def print_results_table(result: DNSResult) -> None:
    """
    Display DNS results in a nice table
    """
    if not result.records:
        console.print(
            Panel(
                f"[yellow]No records found for {result.domain}[/yellow]",
                title = "[yellow]Warning[/yellow]",
                border_style = "yellow",
                expand = False,
            )
        )
        return

    table = Table(
        title = "[bold]DNS Records[/bold]",
        box = box.ROUNDED,
        border_style = "blue",
        row_styles = ["",
                      "dim"],
        show_header = True,
        header_style = "bold cyan",
    )

    table.add_column("Type", width = 8, no_wrap = True)
    table.add_column("Value", style = "green", min_width = 30)
    table.add_column(
        "TTL",
        justify = "right",
        style = "dim",
        width = 8
    )

    for record in result.records:
        color = get_record_color(record.record_type)
        value = record.value

        if record.priority is not None:
            value = f"{value} [dim](priority: {record.priority})[/dim]"

        table.add_row(
            f"[{color}]{record.record_type}[/{color}]",
            value,
            format_ttl(record.ttl),
        )

    console.print(table)


def print_summary(result: DNSResult) -> None:
    """
    Print summary line after results
    """
    record_count = len(result.records)
    time_str = f"{result.query_time_ms:.0f}ms"

    if record_count > 0:
        console.print(
            f"\n[green]:heavy_check_mark:[/green] Found [bold]{record_count}[/bold] record(s) in [cyan]{time_str}[/cyan]"
        )
    else:
        console.print(
            f"\n[yellow]:warning:[/yellow] No records found ({time_str})"
        )

    if result.nameserver:
        console.print(f"[dim]Nameserver: {result.nameserver}[/dim]")

    console.print()


def print_errors(result: DNSResult) -> None:
    """
    Print any errors that occurred
    """
    if result.errors:
        for error in result.errors:
            console.print(f"[red]:x:[/red] {error}")


def print_reverse_result(result: DNSResult) -> None:
    """
    Display reverse DNS lookup results
    """
    console.print()
    console.print(
        f":mag: [bold cyan]Reverse Lookup:[/bold cyan] [bold white]{result.domain}[/bold white]"
    )
    console.rule(style = "blue")

    if result.records:
        table = Table(
            title = "[bold]PTR Records[/bold]",
            box = box.ROUNDED,
            border_style = "blue",
        )
        table.add_column("IP Address", style = "cyan")
        table.add_column("Hostname", style = "green")
        table.add_column(
            "TTL",
            justify = "right",
            style = "dim",
            width = 8
        )

        for record in result.records:
            table.add_row(
                result.domain,
                record.value,
                format_ttl(record.ttl),
            )

        console.print(table)
        print_summary(result)
    else:
        print_errors(result)
        console.print(
            Panel(
                f"[yellow]No PTR record found for {result.domain}[/yellow]",
                border_style = "yellow",
                expand = False,
            )
        )
        console.print()


def print_trace_result(result: TraceResult) -> None:
    """
    Display DNS trace as a tree visualization
    """
    console.print()
    console.print(
        f":mag_right: [bold cyan]DNS Trace:[/bold cyan] [bold white]{result.domain}[/bold white]"
    )
    console.rule(style = "blue")

    if result.error:
        console.print(f"[red]:x:[/red] {result.error}")
        console.print()
        return

    tree = Tree(
        "[bold blue]:globe_showing_americas: DNS Resolution Path[/bold blue]",
        guide_style = "blue",
    )

    zone_nodes: dict[str, Any] = {}

    for hop in result.hops:
        if hop.zone not in zone_nodes:
            if hop.zone == ".":
                zone_display = "[bold yellow][.] Root[/bold yellow]"
            elif hop.zone.endswith("."):
                zone_display = f"[bold yellow][{hop.zone}] TLD[/bold yellow]"
            else:
                zone_display = f"[bold yellow][{hop.zone}.] Authoritative[/bold yellow]"

            zone_node = tree.add(zone_display)
            zone_nodes[hop.zone] = zone_node
        else:
            zone_node = zone_nodes[hop.zone]

        server_style = "green" if hop.is_authoritative else "cyan"
        server_branch = zone_node.add(
            f"[{server_style}]:arrow_right: {hop.server}[/{server_style}] [dim]({hop.server_ip})[/dim]"
        )
        server_branch.add(f"[dim]{hop.response}[/dim]")

    console.print(tree)

    if result.final_answer:
        console.print(
            f"\n[green]:heavy_check_mark:[/green] Resolution complete: [bold green]{result.final_answer}[/bold green]"
        )

    hop_count = len(result.hops)
    console.print(f"[dim]Total hops: {hop_count}[/dim]")
    console.print()


def print_batch_progress_header(total: int) -> None:
    """
    Print header for batch operations
    """
    console.print()
    console.print(
        f":package: [bold cyan]Batch Lookup:[/bold cyan] [bold white]{total} domains[/bold white]"
    )
    console.rule(style = "blue")


def print_batch_results(results: list[DNSResult]) -> None:
    """
    Display batch lookup results in a summary table
    """
    table = Table(
        title = "[bold]Batch Results[/bold]",
        box = box.ROUNDED,
        border_style = "blue",
        row_styles = ["",
                      "dim"],
    )

    table.add_column("Domain", style = "cyan", min_width = 25)
    table.add_column("A", justify = "center", width = 15)
    table.add_column("MX", justify = "center", width = 5)
    table.add_column("NS", justify = "center", width = 5)
    table.add_column(
        "Time",
        justify = "right",
        style = "dim",
        width = 8
    )

    for result in results:
        a_records = [
            r for r in result.records if r.record_type == RecordType.A
        ]
        mx_count = len(
            [
                r for r in result.records
                if r.record_type == RecordType.MX
            ]
        )
        ns_count = len(
            [
                r for r in result.records
                if r.record_type == RecordType.NS
            ]
        )

        a_value = a_records[0].value if a_records else "[dim]-[/dim]"
        mx_value = str(mx_count) if mx_count else "[dim]-[/dim]"
        ns_value = str(ns_count) if ns_count else "[dim]-[/dim]"

        table.add_row(
            result.domain,
            a_value,
            mx_value,
            ns_value,
            f"{result.query_time_ms:.0f}ms",
        )

    console.print(table)

    total_records = sum(len(r.records) for r in results)
    total_time = sum(r.query_time_ms for r in results)
    console.print(
        f"\n[green]:heavy_check_mark:[/green] {len(results)} domains, {total_records} total records in {total_time:.0f}ms"
    )
    console.print()


def results_to_json(results: list[DNSResult] | DNSResult) -> str:
    """
    Convert results to JSON string
    """
    if isinstance(results, DNSResult):
        results = [results]

    data = []
    for result in results:
        record_data = [
            {
                "type": r.record_type.value,
                "value": r.value,
                "ttl": r.ttl,
                "priority": r.priority,
            } for r in result.records
        ]

        data.append(
            {
                "domain": result.domain,
                "records": record_data,
                "errors": result.errors,
                "query_time_ms": round(result.query_time_ms,
                                       2),
                "nameserver": result.nameserver,
            }
        )

    if len(data) == 1:
        return json.dumps(data[0], indent = 2)

    return json.dumps(data, indent = 2)


def trace_to_json(result: TraceResult) -> str:
    """
    Convert trace result to JSON string
    """
    data = {
        "domain":
        result.domain,
        "hops": [
            {
                "zone": hop.zone,
                "server": hop.server,
                "server_ip": hop.server_ip,
                "response": hop.response,
                "is_authoritative": hop.is_authoritative,
            } for hop in result.hops
        ],
        "final_answer":
        result.final_answer,
        "error":
        result.error,
    }

    return json.dumps(data, indent = 2)
