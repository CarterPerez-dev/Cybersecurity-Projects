"""
ⒸAngelaMos | 2026
whois_lookup.py

WHOIS domain information lookup and display
"""

from __future__ import annotations

import json
from dataclasses import (
    dataclass,
    field,
)
from datetime import datetime
from typing import Any

import whois
from rich import box
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class WhoisResult:
    """
    WHOIS lookup result
    """
    domain: str
    registrar: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    updated_date: datetime | None = None
    status: list[str] = field(default_factory = list)
    name_servers: list[str] = field(default_factory = list)
    registrant: str | None = None
    registrant_country: str | None = None
    dnssec: str | None = None
    error: str | None = None


def format_date(dt: datetime | list | None) -> str:
    """
    Format datetime for display
    """
    if dt is None:
        return "[dim]-[/dim]"

    if isinstance(dt, list):
        dt = dt[0] if dt else None

    if dt is None:
        return "[dim]-[/dim]"

    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d")

    return str(dt)


def lookup_whois(domain: str) -> WhoisResult:
    """
    Perform WHOIS lookup for a domain
    """
    result = WhoisResult(domain = domain)

    try:
        w = whois.whois(domain)

        if w is None or (hasattr(w,
                                 "domain_name")
                         and w.domain_name is None):
            result.error = "Domain not found or WHOIS data unavailable"
            return result

        result.registrar = w.registrar if hasattr(
            w,
            "registrar"
        ) else None
        result.creation_date = w.creation_date if hasattr(
            w,
            "creation_date"
        ) else None
        result.expiration_date = w.expiration_date if hasattr(
            w,
            "expiration_date"
        ) else None
        result.updated_date = w.updated_date if hasattr(
            w,
            "updated_date"
        ) else None

        if hasattr(w, "status"):
            status = w.status
            if isinstance(status, str):
                result.status = [status]
            elif isinstance(status, list):
                result.status = status
            else:
                result.status = []

        if hasattr(w, "name_servers") and w.name_servers:
            ns = w.name_servers
            if isinstance(ns, str):
                result.name_servers = [ns.lower()]
            elif isinstance(ns, list):
                result.name_servers = [n.lower() for n in ns if n]
            else:
                result.name_servers = []

        if hasattr(w, "org"):
            result.registrant = w.org
        elif hasattr(w, "name"):
            result.registrant = w.name

        if hasattr(w, "country"):
            result.registrant_country = w.country

        if hasattr(w, "dnssec"):
            result.dnssec = str(w.dnssec) if w.dnssec else None

    except Exception as e:
        result.error = str(e)

    return result


def print_whois_result(result: WhoisResult) -> None:
    """
    Display WHOIS result in a nice table
    """
    console.print()
    console.print(
        f":clipboard: [bold cyan]WHOIS:[/bold cyan] [bold white]{result.domain}[/bold white]"
    )
    console.rule(style = "blue")

    if result.error:
        console.print(f"[red]:x:[/red] {result.error}")
        console.print()
        return

    table = Table(
        box = box.ROUNDED,
        border_style = "blue",
        show_header = False,
        padding = (0,
                   1),
    )

    table.add_column("Field", style = "cyan", width = 15)
    table.add_column("Value", style = "green")

    if result.registrar:
        table.add_row("Registrar", result.registrar)

    if result.registrant:
        table.add_row("Registrant", result.registrant)

    if result.registrant_country:
        table.add_row("Country", result.registrant_country)

    table.add_row("Created", format_date(result.creation_date))
    table.add_row("Expires", format_date(result.expiration_date))
    table.add_row("Updated", format_date(result.updated_date))

    if result.status:
        status_display = result.status[0] if len(
            result.status
        ) == 1 else f"{len(result.status)} statuses"
        table.add_row("Status", status_display)

    if result.name_servers:
        for i, ns in enumerate(result.name_servers[: 4]):
            label = "Name Servers" if i == 0 else ""
            table.add_row(label, ns)

        if len(result.name_servers) > 4:
            table.add_row(
                "",
                f"[dim]... and {len(result.name_servers) - 4} more[/dim]"
            )

    if result.dnssec:
        table.add_row("DNSSEC", result.dnssec)

    console.print(table)
    console.print()


def whois_to_json(result: WhoisResult) -> str:
    """
    Convert WHOIS result to JSON string
    """
    def serialize_date(dt: datetime | list | None) -> str | None:
        if dt is None:
            return None
        if isinstance(dt, list):
            dt = dt[0] if dt else None
        if isinstance(dt, datetime):
            return dt.isoformat()
        return str(dt) if dt else None

    data: dict[str,
               Any] = {
                   "domain": result.domain,
                   "registrar": result.registrar,
                   "creation_date":
                   serialize_date(result.creation_date),
                   "expiration_date": serialize_date(
                       result.expiration_date
                   ),
                   "updated_date": serialize_date(
                       result.updated_date
                   ),
                   "status": result.status,
                   "name_servers": result.name_servers,
                   "registrant": result.registrant,
                   "registrant_country": result.registrant_country,
                   "dnssec": result.dnssec,
                   "error": result.error,
               }

    return json.dumps(data, indent = 2)
