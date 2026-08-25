"""Tests for watchlist.yml loading."""

from __future__ import annotations

import pytest

from glasswatch.watchlist import load_watchlist


def test_loads_string_shorthand_entries(tmp_path):
    p = tmp_path / "watchlist.yml"
    p.write_text("brands:\n  - acmepay.com\n  - example.org\n", encoding="utf-8")

    brands = load_watchlist(p)
    assert len(brands) == 2
    assert brands[0].domain == "acmepay.com"
    assert brands[0].core_name == "acmepay"  # guessed from the domain


def test_loads_dict_entries_with_explicit_core_name(tmp_path):
    p = tmp_path / "watchlist.yml"
    p.write_text(
        "brands:\n"
        "  - name: Acme Pay UK\n"
        "    domain: acmepay.co.uk\n"
        "    core_name: acmepay\n",
        encoding="utf-8",
    )

    brands = load_watchlist(p)
    assert brands[0].name == "Acme Pay UK"
    assert brands[0].core_name == "acmepay"  # explicit override beats the naive guess


def test_rejects_invalid_domain_label(tmp_path):
    p = tmp_path / "watchlist.yml"
    p.write_text("brands:\n  - 'not a domain!'\n", encoding="utf-8")

    with pytest.raises(ValueError):
        load_watchlist(p)


def test_empty_file_yields_empty_list(tmp_path):
    p = tmp_path / "watchlist.yml"
    p.write_text("", encoding="utf-8")
    assert load_watchlist(p) == []
