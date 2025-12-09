"""
CarterPerez-dev | 2025
test_resolver.py
Tests for DNS resolver functionality
"""

from __future__ import annotations

import pytest

from dnslookup.resolver import (
    ALL_RECORD_TYPES,
    DNSRecord,
    DNSResult,
    RecordType,
    TraceResult,
    batch_lookup,
    create_resolver,
    lookup,
    reverse_lookup,
    trace_dns,
)


class TestRecordType:
    """
    Tests for RecordType enum
    """
    def test_all_record_types_exist(self) -> None:
        assert RecordType.A == "A"
        assert RecordType.AAAA == "AAAA"
        assert RecordType.MX == "MX"
        assert RecordType.NS == "NS"
        assert RecordType.TXT == "TXT"
        assert RecordType.CNAME == "CNAME"
        assert RecordType.SOA == "SOA"
        assert RecordType.PTR == "PTR"

    def test_all_record_types_list(self) -> None:
        assert len(ALL_RECORD_TYPES) == 7
        assert RecordType.PTR not in ALL_RECORD_TYPES


class TestDNSRecord:
    """
    Tests for DNSRecord dataclass
    """
    def test_create_basic_record(self) -> None:
        record = DNSRecord(
            record_type = RecordType.A,
            value = "93.184.216.34",
            ttl = 3600,
        )
        assert record.record_type == RecordType.A
        assert record.value == "93.184.216.34"
        assert record.ttl == 3600
        assert record.priority is None

    def test_create_mx_record_with_priority(self) -> None:
        record = DNSRecord(
            record_type = RecordType.MX,
            value = "mail.example.com",
            ttl = 86400,
            priority = 10,
        )
        assert record.record_type == RecordType.MX
        assert record.priority == 10


class TestDNSResult:
    """
    Tests for DNSResult dataclass
    """
    def test_create_empty_result(self) -> None:
        result = DNSResult(domain = "example.com")
        assert result.domain == "example.com"
        assert result.records == []
        assert result.errors == []
        assert result.query_time_ms == 0.0
        assert result.nameserver is None

    def test_result_with_records(self) -> None:
        record = DNSRecord(RecordType.A, "1.2.3.4", 3600)
        result = DNSResult(
            domain = "example.com",
            records = [record],
            query_time_ms = 45.5,
        )
        assert len(result.records) == 1
        assert result.query_time_ms == 45.5


class TestCreateResolver:
    """
    Tests for create_resolver function
    """
    def test_default_resolver(self) -> None:
        resolver = create_resolver()
        assert resolver.timeout == 5.0
        assert resolver.lifetime == 10.0

    def test_custom_nameserver(self) -> None:
        resolver = create_resolver(nameserver = "8.8.8.8")
        assert "8.8.8.8" in resolver.nameservers

    def test_custom_timeout(self) -> None:
        resolver = create_resolver(timeout = 10.0)
        assert resolver.timeout == 10.0
        assert resolver.lifetime == 20.0


class TestLookup:
    """
    Integration tests for DNS lookup
    """
    @pytest.mark.asyncio
    async def test_lookup_real_domain(self) -> None:
        result = await lookup("example.com", [RecordType.A])
        assert result.domain == "example.com"
        assert result.query_time_ms > 0

    @pytest.mark.asyncio
    async def test_lookup_nonexistent_domain(self) -> None:
        result = await lookup(
            "this-domain-definitely-does-not-exist-12345.com",
            [RecordType.A]
        )
        assert result.domain == "this-domain-definitely-does-not-exist-12345.com"
        assert len(result.records) == 0

    @pytest.mark.asyncio
    async def test_lookup_with_custom_server(self) -> None:
        result = await lookup(
            "example.com",
            [RecordType.A],
            nameserver = "8.8.8.8"
        )
        assert result.nameserver == "8.8.8.8"


class TestReverseLookup:
    """
    Tests for reverse DNS lookup
    """
    @pytest.mark.asyncio
    async def test_reverse_lookup_google_dns(self) -> None:
        result = await reverse_lookup("8.8.8.8")
        assert result.domain == "8.8.8.8"
        assert result.query_time_ms > 0


class TestTraceDNS:
    """
    Tests for DNS trace functionality
    """
    def test_trace_result_structure(self) -> None:
        result = TraceResult(domain = "example.com")
        assert result.domain == "example.com"
        assert result.hops == []
        assert result.final_answer is None
        assert result.error is None

    def test_trace_real_domain(self) -> None:
        result = trace_dns("example.com")
        assert result.domain == "example.com"


class TestBatchLookup:
    """
    Tests for batch DNS lookups
    """
    @pytest.mark.asyncio
    async def test_batch_lookup_multiple_domains(self) -> None:
        domains = ["example.com", "example.org"]
        results = await batch_lookup(domains, [RecordType.A])
        assert len(results) == 2
        assert results[0].domain == "example.com"
        assert results[1].domain == "example.org"

    @pytest.mark.asyncio
    async def test_batch_lookup_empty_list(self) -> None:
        results = await batch_lookup([], [RecordType.A])
        assert results == []
