"""Tests for the SQLite findings store, mainly the dedup/upsert behavior."""

from __future__ import annotations

from glasswatch.detect import Finding
from glasswatch.store import FindingsStore


def make_finding(domain="phish.example", brand="Acme", score=60, severity="high"):
    return Finding(domain=domain, brand=brand, score=score, severity=severity,
                   reasons=["homoglyph-exact:phish"])


def test_first_record_is_new(tmp_path):
    with FindingsStore(tmp_path / "findings.db") as store:
        assert store.record(make_finding()) is True
        assert store.count() == 1


def test_duplicate_record_is_not_new_but_bumps_seen_count(tmp_path):
    with FindingsStore(tmp_path / "findings.db") as store:
        store.record(make_finding())
        is_new = store.record(make_finding())
        assert is_new is False
        assert store.count() == 1  # still one row, not two

        rows = store.list_findings()
        assert rows[0]["seen_count"] == 2


def test_same_domain_different_brand_is_a_separate_row(tmp_path):
    with FindingsStore(tmp_path / "findings.db") as store:
        store.record(make_finding(brand="Acme"))
        store.record(make_finding(brand="Other Co"))
        assert store.count() == 2


def test_list_findings_filters_by_severity(tmp_path):
    with FindingsStore(tmp_path / "findings.db") as store:
        store.record(make_finding(domain="a.example", severity="critical", score=90))
        store.record(make_finding(domain="b.example", severity="low", score=10))

        critical_only = store.list_findings(severity="critical")
        assert len(critical_only) == 1
        assert critical_only[0]["domain"] == "a.example"


def test_reopening_the_same_db_file_preserves_data(tmp_path):
    db_path = tmp_path / "findings.db"
    with FindingsStore(db_path) as store:
        store.record(make_finding())

    with FindingsStore(db_path) as store:
        assert store.count() == 1
