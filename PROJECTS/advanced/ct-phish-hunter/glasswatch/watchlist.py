"""Load the list of brands to protect from a YAML config file."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")


@dataclass(frozen=True)
class Brand:
    name: str
    domain: str
    core_name: str  # domain with the public-suffix-ish tail stripped, e.g. "paypal"


def _core_name_from_domain(domain: str) -> str:
    """Best-effort "brand name" from a registrable domain.

    Strips the final label (naive TLD guess: "paypal.com" -> "paypal").
    This is not a real public-suffix-list lookup (no bundled PSL data,
    see learn/04-CHALLENGES.md for why that is a documented limitation
    rather than a bug), so multi-part suffixes like "co.uk" are not
    handled specially. "paypal.co.uk" becomes core name "co", which is
    wrong; supply the core brand name explicitly in the watchlist for
    domains like that instead of relying on the guess.
    """
    labels = domain.lower().split(".")
    if len(labels) < 2:
        return labels[0]
    return labels[-2]


def load_watchlist(path: str | Path) -> list[Brand]:
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    brands_raw = raw.get("brands", [])
    if not isinstance(brands_raw, list):
        raise TypeError("watchlist 'brands' must be a list")

    brands: list[Brand] = []
    for entry in brands_raw:
        domain: str
        name: str
        core_name: str | None

        if isinstance(entry, str):
            domain = entry
            name = entry
            core_name = None
        elif isinstance(entry, dict):
            domain = str(entry["domain"])
            name = str(entry.get("name", domain))
            raw_core_name = entry.get("core_name")
            core_name = str(raw_core_name) if raw_core_name is not None else None
        else:
            raise ValueError(f"invalid watchlist entry: {entry!r}")

        domain = domain.lower().strip(".")
        for label in domain.split("."):
            if not _LABEL_RE.match(label):
                raise ValueError(f"invalid domain label {label!r} in {domain!r}")

        brands.append(Brand(
            name=name,
            domain=domain,
            core_name=(core_name or _core_name_from_domain(domain)).lower(),
        ))
    return brands
