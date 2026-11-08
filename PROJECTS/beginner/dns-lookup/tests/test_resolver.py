"""
ⒸAngelaMos | 2026
test_resolver.py

Tests for DNS resolver functionality

Unit tests cover the data models and enum values. Integration tests make
real DNS queries against live nameservers, so network access is required
for those to pass. Async tests use pytest-asyncio.

Tests:
  TestRecordType - enum string values and ALL_RECORD_TYPES membership (PTR excluded)
  TestDNSRecord - dataclass construction including MX priority field
  TestDNSResult - default empty state and record population
  TestCreateResolver - timeout, lifetime, and custom nameserver configuration
  TestLookup - forward lookup against real and nonexistent domains, custom server
  TestReverseLookup - PTR lookup against 8.8.8.8
  TestTraceDNS - TraceResult structure and real domain trace
  TestBatchLookup - concurrent multi-domain lookup including empty list

Connects to:
  resolver.py - all public symbols imported and exercised here
"""

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
        """
        Each RecordType member matches its expected string value
        """
        assert RecordType.A == "A"
        assert RecordType.AAAA == "AAAA"
        assert RecordType.MX == "MX"
        assert RecordType.NS == "NS"
        assert RecordType.TXT == "TXT"
        assert RecordType.CNAME == "CNAME"
        assert RecordType.SOA == "SOA"
        assert RecordType.PTR == "PTR"

    def test_all_record_types_list(self) -> None:
        """
        ALL_RECORD_TYPES has exactly 7 entries and excludes PTR
        """
        assert len(ALL_RECORD_TYPES) == 7
        assert RecordType.PTR not in ALL_RECORD_TYPES


class TestDNSRecord:
    """
    Tests for DNSRecord dataclass
    """
    def test_create_basic_record(self) -> None:
        """
        A record is created with correct type, value, TTL, and no priority
        """
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
        """
        MX record stores the priority value alongside the mail server
        """
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
        """
        DNSResult initializes with empty records, errors, zero timing, and no nameserver
        """
        result = DNSResult(domain = "example.com")
        assert result.domain == "example.com"
        assert result.records == []
        assert result.errors == []
        assert result.query_time_ms == 0.0
        assert result.nameserver is None

    def test_result_with_records(self) -> None:
        """
        DNSResult correctly stores records and query timing when provided
        """
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
        """
        Default resolver uses 5s timeout and 10s lifetime
        """
        resolver = create_resolver()
        assert resolver.timeout == 5.0
        assert resolver.lifetime == 10.0

    def test_custom_nameserver(self) -> None:
        """
        Resolver uses the provided nameserver IP when one is given
        """
        resolver = create_resolver(nameserver = "8.8.8.8")
        assert "8.8.8.8" in resolver.nameservers

    def test_custom_timeout(self) -> None:
        """
        Resolver sets lifetime to double the provided timeout value
        """
        resolver = create_resolver(timeout = 10.0)
        assert resolver.timeout == 10.0
        assert resolver.lifetime == 20.0


class TestLookup:
    """
    Integration tests for DNS lookup
    """
    @pytest.mark.asyncio
    async def test_lookup_real_domain(self) -> None:
        """
        Live A record lookup for example.com returns a result with nonzero query time
        """
        result = await lookup("example.com", [RecordType.A])
        assert result.domain == "example.com"
        assert result.query_time_ms > 0

    @pytest.mark.asyncio
    async def test_lookup_nonexistent_domain(self) -> None:
        """
        Lookup for a domain that does not exist returns zero records without raising
        """
        result = await lookup(
            "this-domain-definitely-does-not-exist-12345.com",
            [RecordType.A]
        )
        assert result.domain == "this-domain-definitely-does-not-exist-12345.com"
        assert len(result.records) == 0

    @pytest.mark.asyncio
    async def test_lookup_with_custom_server(self) -> None:
        """
        Lookup using a custom nameserver records that server on the result
        """
        result = await lookup("example.com", [RecordType.A], nameserver = "8.8.8.8")
        assert result.nameserver == "8.8.8.8"


class TestReverseLookup:
    """
    Tests for reverse DNS lookup
    """
    @pytest.mark.asyncio
    async def test_reverse_lookup_google_dns(self) -> None:
        """
        Reverse lookup for 8.8.8.8 returns a result with nonzero query time
        """
        result = await reverse_lookup("8.8.8.8")
        assert result.domain == "8.8.8.8"
        assert result.query_time_ms > 0


class TestTraceDNS:
    """
    Tests for DNS trace functionality
    """
    def test_trace_result_structure(self) -> None:
        """
        TraceResult initializes with empty hops, no final answer, and no error
        """
        result = TraceResult(domain = "example.com")
        assert result.domain == "example.com"
        assert result.hops == []
        assert result.final_answer is None
        assert result.error is None

    def test_trace_real_domain(self) -> None:
        """
        Live trace for example.com returns a result with the correct domain set
        """
        result = trace_dns("example.com")
        assert result.domain == "example.com"


class TestBatchLookup:
    """
    Tests for batch DNS lookups
    """
    @pytest.mark.asyncio
    async def test_batch_lookup_multiple_domains(self) -> None:
        """
        Batch lookup returns one result per domain in the same order as input
        """
        domains = ["example.com", "example.org"]
        results = await batch_lookup(domains, [RecordType.A])
        assert len(results) == 2
        assert results[0].domain == "example.com"
        assert results[1].domain == "example.org"

    @pytest.mark.asyncio
    async def test_batch_lookup_empty_list(self) -> None:
        """
        Batch lookup with an empty domain list returns an empty list
        """
        results = await batch_lookup([], [RecordType.A])
        assert results == []
