"""Tests for RFC 6962 leaf parsing against real captured CT log entries.

tests/fixtures/sample_leaves.json holds two entries pulled live from
Cloudflare's "Nimbus2026" log with `ct/v1/get-entries`, one x509_entry
and one precert_entry, saved verbatim so these tests never depend on
the network or on a log's tree still containing that index years later.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from glasswatch import ctlog

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def sample_leaves() -> dict:
    return json.loads((FIXTURES / "sample_leaves.json").read_text(encoding="utf-8"))


def test_x509_entry_parses_to_a_certificate_with_dns_names(sample_leaves):
    entry = sample_leaves["x509_entry"]
    entry_type, timestamp_ms, cert_der = ctlog.parse_merkle_leaf(entry["leaf_input"])

    assert entry_type == ctlog.ENTRY_TYPE_X509
    assert timestamp_ms > 1_700_000_000_000  # sanity: after 2023-11, in milliseconds
    assert cert_der is not None

    cert = ctlog.load_certificate(cert_der)
    names = ctlog.extract_dns_names(cert)
    assert len(names) >= 1
    assert all(isinstance(n, str) for n in names)


def test_precert_entry_leaf_carries_no_direct_certificate(sample_leaves):
    entry = sample_leaves["precert_entry"]
    entry_type, _, cert_der = ctlog.parse_merkle_leaf(entry["leaf_input"])

    assert entry_type == ctlog.ENTRY_TYPE_PRECERT
    assert cert_der is None  # the real cert bytes live in extra_data, not the leaf


def test_precert_extra_data_yields_a_parseable_certificate(sample_leaves):
    entry = sample_leaves["precert_entry"]
    precert_der = ctlog.parse_precert_extra_data(entry["extra_data"])
    cert = ctlog.load_certificate(precert_der)
    names = ctlog.extract_dns_names(cert)
    assert len(names) >= 1


def test_leaf_to_domains_handles_both_entry_types(sample_leaves):
    for kind in ("x509_entry", "precert_entry"):
        domains = ctlog.leaf_to_domains(sample_leaves[kind])
        assert isinstance(domains, list)
        assert len(domains) >= 1
        assert all(d == d.lower() for d in domains)


def test_leaf_to_domains_does_not_raise_on_garbage():
    assert ctlog.leaf_to_domains({"leaf_input": "not-valid-base64!!!"}) == []
    assert ctlog.leaf_to_domains({}) == []


def test_rejects_unsupported_merkle_leaf_version():
    import base64
    # version=9 (invalid), rest zeroed
    garbage = bytes([9, 0]) + b"\x00" * 20
    with pytest.raises(ctlog.ProtocolError):
        ctlog.parse_merkle_leaf(base64.b64encode(garbage).decode())
