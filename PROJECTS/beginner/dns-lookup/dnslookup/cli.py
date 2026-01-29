"""
CarterPerez-dev | 2025
cli.py
Typer CLI application for DNS lookups
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
)

from dnslookup import __version__
from dnslookup.output import (
    console,
    print_batch_progress_header,
    print_batch_results,
    print_errors,
    print_header,
    print_results_table,
    print_reverse_result,
    print_summary,
    print_trace_result,
    results_to_json,
    trace_to_json,
)
from dnslookup.resolver import (
    ALL_RECORD_TYPES,
    RecordType,
    batch_lookup,
    lookup,
    reverse_lookup,
    trace_dns,
)
from dnslookup.whois_lookup import (
    lookup_whois,
    print_whois_result,
    whois_to_json,
)

app = typer.Typer(
    name = "dnslookup",
    help =
    "[bold green]DNS Lookup Tool[/bold green] - Professional DNS query CLI with clean output",
    rich_markup_mode = "rich",
    no_args_is_help = True,
)


def version_callback(value: bool) -> None:
    """
    Display version and exit
    """
    if value:
        console.print(
            f"[bold cyan]dnslookup[/bold cyan] version [green]{__version__}[/green]"
        )
        raise typer.Exit()


def parse_record_types(types_str: str) -> list[RecordType]:
    """
    Parse comma separated record types string
    """
    if types_str.upper() == "ALL":
        return list(ALL_RECORD_TYPES)

    types = []
    for t in types_str.upper().split(","):
        t = t.strip()
        try:
            types.append(RecordType(t))
        except ValueError:
            console.print(
                f"[yellow]Warning:[/yellow] Unknown record type '{t}', skipping"
            )

    return types if types else list(ALL_RECORD_TYPES)


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help = "Show version and exit",
            callback = version_callback,
            is_eager = True,
        ),
    ] = None,
) -> None:
    """
    [bold green]DNS Lookup Tool[/bold green]

    Query DNS records, perform reverse lookups, trace resolution paths,
    and retrieve WHOIS information with nice terminal output.
    """
    pass


@app.command()
def query(
    domain: Annotated[str,
                      typer.Argument(help = "Domain name to query")],
    record_type: Annotated[
        str,
        typer.Option(
            "--type",
            "-t",
            help =
            "Record types to query (A,AAAA,MX,NS,TXT,CNAME,SOA or ALL)",
        ),
    ] = "ALL",
    server: Annotated[
        str | None,
        typer.Option(
            "--server",
            "-s",
            help = "DNS server to use (e.g., 8.8.8.8)",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            help = "Query timeout in seconds",
        ),
    ] = 5.0,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Output results as JSON",
        ),
    ] = False,
) -> None:
    """
    [bold cyan]Query DNS records[/bold cyan] for a domain.

    Examples:
        dnslookup query example.com
        dnslookup query example.com --type A,MX
        dnslookup query example.com --server 8.8.8.8 --json
    """
    record_types = parse_record_types(record_type)

    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console = console,
            transient = True,
    ) as progress:
        progress.add_task(f"Querying {domain}...", total = None)
        result = asyncio.run(
            lookup(domain,
                   record_types,
                   server,
                   timeout)
        )

    if json_output:
        console.print(results_to_json(result))
    else:
        print_header(domain)
        print_results_table(result)
        print_errors(result)
        print_summary(result)


@app.command()
def reverse(
    ip: Annotated[
        str,
        typer.Argument(help = "IP address for reverse lookup")],
    server: Annotated[
        str | None,
        typer.Option(
            "--server",
            "-s",
            help = "DNS server to use",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            help = "Query timeout in seconds",
        ),
    ] = 5.0,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Output results as JSON",
        ),
    ] = False,
) -> None:
    """
    [bold cyan]Reverse DNS lookup[/bold cyan] for an IP address.

    Examples:
        dnslookup reverse 8.8.8.8
        dnslookup reverse 2606:4700:4700::1111
    """
    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console = console,
            transient = True,
    ) as progress:
        progress.add_task(f"Resolving {ip}...", total = None)
        result = asyncio.run(reverse_lookup(ip, server, timeout))

    if json_output:
        console.print(results_to_json(result))
    else:
        print_reverse_result(result)


@app.command()
def trace(
    domain: Annotated[str,
                      typer.Argument(help = "Domain to trace")],
    record_type: Annotated[
        str,
        typer.Option(
            "--type",
            "-t",
            help = "Record type to trace (default: A)",
        ),
    ] = "A",
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Output results as JSON",
        ),
    ] = False,
) -> None:
    """
    [bold cyan]Trace DNS resolution path[/bold cyan] from root to authoritative servers.

    Shows the complete resolution chain including root servers, TLD servers,
    and authoritative nameservers.

    Examples:
        dnslookup trace example.com
        dnslookup trace example.com --type MX
    """
    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console = console,
            transient = True,
    ) as progress:
        progress.add_task(f"Tracing {domain}...", total = None)
        result = trace_dns(domain, record_type.upper())

    if json_output:
        console.print(trace_to_json(result))
    else:
        print_trace_result(result)


@app.command()
def batch(
    file: Annotated[
        Path,
        typer.
        Argument(help = "File containing domains (one per line)"),
    ],
    record_type: Annotated[
        str,
        typer.Option(
            "--type",
            "-t",
            help = "Record types to query",
        ),
    ] = "A,MX,NS",
    server: Annotated[
        str | None,
        typer.Option(
            "--server",
            "-s",
            help = "DNS server to use",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            help = "Query timeout in seconds",
        ),
    ] = 5.0,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help = "Output file for JSON results",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Output results as JSON to stdout",
        ),
    ] = False,
) -> None:
    """
    [bold cyan]Batch DNS lookup[/bold cyan] for multiple domains from a file.

    The file should contain one domain per line. Empty lines and lines
    starting with # are ignored.

    Examples:
        dnslookup batch domains.txt
        dnslookup batch domains.txt --type A,MX --output results.json
    """
    if not file.exists():
        console.print(f"[red]Error:[/red] File not found: {file}")
        raise typer.Exit(1)

    domains = []
    with open(file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)

    if not domains:
        console.print(
            "[yellow]Warning:[/yellow] No domains found in file"
        )
        raise typer.Exit(0)

    record_types = parse_record_types(record_type)

    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console = console,
            transient = True,
    ) as progress:
        progress.add_task(
            f"Querying {len(domains)} domains...",
            total = None
        )
        results = asyncio.run(
            batch_lookup(domains,
                         record_types,
                         server,
                         timeout)
        )

    if json_output:
        console.print(results_to_json(results))
    elif output:
        with open(output, "w") as f:
            f.write(results_to_json(results))
        console.print(
            f"[green]:heavy_check_mark:[/green] Results saved to {output}"
        )
    else:
        print_batch_progress_header(len(domains))
        print_batch_results(results)


@app.command()
def whois(
    domain: Annotated[str,
                      typer.Argument(help = "Domain to lookup")],
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Output results as JSON",
        ),
    ] = False,
) -> None:
    """
    [bold cyan]WHOIS lookup[/bold cyan] for domain registration information.

    Shows registrar, creation date, expiration date, name servers,
    and other registration details.

    Examples:
        dnslookup whois example.com
        dnslookup whois google.com --json
    """
    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console = console,
            transient = True,
    ) as progress:
        progress.add_task(
            f"Looking up WHOIS for {domain}...",
            total = None
        )
        result = lookup_whois(domain)

    if json_output:
        console.print(whois_to_json(result))
    else:
        print_whois_result(result)


if __name__ == "__main__":
    app()
