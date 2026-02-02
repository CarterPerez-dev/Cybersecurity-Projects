"""
ⒸAngelaMos | 2026
resolver.py

Async DNS resolution with record type support
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import (
    dataclass,
    field
)
from enum import StrEnum
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename


class RecordType(StrEnum):
    """
    Supported DNS record types
    """
    A = "A"
    AAAA = "AAAA"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    CNAME = "CNAME"
    SOA = "SOA"
    PTR = "PTR"


ALL_RECORD_TYPES = [
    RecordType.A,
    RecordType.AAAA,
    RecordType.MX,
    RecordType.NS,
    RecordType.TXT,
    RecordType.CNAME,
    RecordType.SOA,
]


@dataclass
class DNSRecord:
    """
    Represents a single DNS record
    """
    record_type: RecordType
    value: str
    ttl: int
    priority: int | None = None


@dataclass
class DNSResult:
    """
    Result of a DNS lookup
    """
    domain: str
    records: list[DNSRecord] = field(default_factory = list)
    errors: list[str] = field(default_factory = list)
    query_time_ms: float = 0.0
    nameserver: str | None = None


@dataclass
class TraceHop:
    """
    Represents a single hop in DNS resolution trace
    """
    zone: str
    server: str
    server_ip: str
    response: str
    is_authoritative: bool = False


@dataclass
class TraceResult:
    """
    Result of a DNS trace
    """
    domain: str
    hops: list[TraceHop] = field(default_factory = list)
    final_answer: str | None = None
    error: str | None = None


def create_resolver(
    nameserver: str | None = None,
    timeout: float = 5.0,
) -> dns.asyncresolver.Resolver:
    """
    Create a configured async DNS resolver
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2

    if nameserver:
        resolver.nameservers = [nameserver]

    return resolver


def extract_record_value(rdata: Any,
                         record_type: RecordType
                         ) -> tuple[str,
                                    int | None]:
    """
    Extract value and priority from rdata based on record type
    """
    priority = None

    if record_type == RecordType.A or record_type == RecordType.AAAA:
        value = rdata.address
    elif record_type == RecordType.MX:
        value = str(rdata.exchange).rstrip(".")
        priority = rdata.preference
    elif record_type in (RecordType.NS,
                         RecordType.CNAME,
                         RecordType.PTR):
        value = str(rdata.target).rstrip(".")
    elif record_type == RecordType.TXT:
        value = rdata.to_text()
    elif record_type == RecordType.SOA:
        value = f"NS: {str(rdata.mname).rstrip('.')}, Serial: {rdata.serial}"
    else:
        value = rdata.to_text()

    return value, priority


async def query_record_type(
    domain: str,
    record_type: RecordType,
    resolver: dns.asyncresolver.Resolver,
) -> list[DNSRecord]:
    """
    Query a single record type for a domain
    """
    records = []

    try:
        answers = await resolver.resolve(domain, record_type.value)

        for rdata in answers:
            value, priority = extract_record_value(rdata, record_type)
            records.append(
                DNSRecord(
                    record_type = record_type,
                    value = value,
                    ttl = answers.rrset.ttl,
                    priority = priority,
                )
            )
    except (dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers):
        pass
    except dns.exception.Timeout:
        pass

    return records


async def lookup(
    domain: str,
    record_types: list[RecordType] | None = None,
    nameserver: str | None = None,
    timeout: float = 5.0,
) -> DNSResult:
    """
    Perform DNS lookup for specified record types
    """
    if record_types is None:
        record_types = ALL_RECORD_TYPES

    resolver = create_resolver(nameserver, timeout)
    result = DNSResult(domain = domain, nameserver = nameserver)

    start_time = time.perf_counter()

    tasks = [
        query_record_type(domain,
                          rt,
                          resolver) for rt in record_types
    ]
    query_results = await asyncio.gather(
        *tasks,
        return_exceptions = True
    )

    for i, query_result in enumerate(query_results):
        if isinstance(query_result, Exception):
            result.errors.append(f"{record_types[i]}: {query_result}")
        else:
            result.records.extend(query_result)

    result.query_time_ms = (time.perf_counter() - start_time) * 1000

    return result


async def reverse_lookup(
    ip_address: str,
    nameserver: str | None = None,
    timeout: float = 5.0,
) -> DNSResult:
    """
    Perform reverse DNS lookup for an IP address
    """
    resolver = create_resolver(nameserver, timeout)
    result = DNSResult(domain = ip_address, nameserver = nameserver)

    start_time = time.perf_counter()

    try:
        answers = await resolver.resolve_address(ip_address)
        for rdata in answers:
            result.records.append(
                DNSRecord(
                    record_type = RecordType.PTR,
                    value = str(rdata.target).rstrip("."),
                    ttl = answers.rrset.ttl,
                )
            )
    except dns.resolver.NXDOMAIN:
        result.errors.append("No PTR record found")
    except dns.resolver.NoAnswer:
        result.errors.append("No answer from nameserver")
    except dns.resolver.NoNameservers:
        result.errors.append("No nameservers available")
    except dns.exception.Timeout:
        result.errors.append("Query timed out")
    except dns.exception.DNSException as e:
        result.errors.append(str(e))

    result.query_time_ms = (time.perf_counter() - start_time) * 1000

    return result


def trace_dns(domain: str, record_type: str = "A") -> TraceResult:
    """
    Trace DNS resolution path from root to authoritative servers
    """
    result = TraceResult(domain = domain)

    try:
        name = dns.name.from_text(domain)
        rdtype = dns.rdatatype.from_text(record_type)

        root_servers = [
            ("a.root-servers.net",
             "198.41.0.4"),
            ("b.root-servers.net",
             "170.247.170.2"),
            ("c.root-servers.net",
             "192.33.4.12"),
        ]

        current_servers = root_servers
        current_zone = "."

        while True:
            server_name, server_ip = current_servers[0]

            try:
                query = dns.message.make_query(name, rdtype)
                response = dns.query.udp(
                    query,
                    server_ip,
                    timeout = 3.0
                )

                rcode = response.rcode()

                if rcode != dns.rcode.NOERROR:
                    result.error = f"DNS error: {dns.rcode.to_text(rcode)}"
                    break

                if response.answer:
                    for rrset in response.answer:
                        for rdata in rrset:
                            result.final_answer = str(rdata)
                            break

                    result.hops.append(
                        TraceHop(
                            zone = current_zone,
                            server = server_name,
                            server_ip = server_ip,
                            response =
                            f"{record_type}: {result.final_answer}",
                            is_authoritative = True,
                        )
                    )
                    break

                if response.authority:
                    ns_records = []
                    for rrset in response.authority:
                        if rrset.rdtype == dns.rdatatype.NS:
                            for rdata in rrset:
                                ns_name = str(rdata.target
                                              ).rstrip(".")
                                ns_records.append(ns_name)
                            new_zone = str(rrset.name).rstrip(".")
                            if not new_zone:
                                new_zone = "."

                    if ns_records:
                        referral_msg = f"Referred to {new_zone or 'next'} servers"
                        result.hops.append(
                            TraceHop(
                                zone = current_zone,
                                server = server_name,
                                server_ip = server_ip,
                                response = referral_msg,
                            )
                        )

                        glue_ips = {}
                        if response.additional:
                            for rrset in response.additional:
                                if rrset.rdtype == dns.rdatatype.A:
                                    for rdata in rrset:
                                        glue_ips[str(
                                            rrset.name
                                        ).rstrip(".")] = rdata.address

                        new_servers = []
                        for ns in ns_records:
                            if ns in glue_ips:
                                new_servers.append((ns, glue_ips[ns]))
                            else:
                                try:
                                    answers = dns.resolver.resolve(
                                        ns,
                                        "A"
                                    )
                                    for rdata in answers:
                                        new_servers.append(
                                            (ns,
                                             rdata.address)
                                        )
                                        break
                                except dns.exception.DNSException:
                                    continue

                        if new_servers:
                            current_servers = new_servers
                            current_zone = new_zone
                        else:
                            result.error = "Could not resolve nameserver IPs"
                            break
                    else:
                        result.error = "No NS records in authority section"
                        break
                else:
                    result.error = "No answer or authority in response"
                    break

            except dns.exception.Timeout:
                result.error = f"Timeout querying {server_name}"
                break
            except dns.exception.DNSException as e:
                result.error = str(e)
                break

    except Exception as e:
        result.error = str(e)

    return result


async def batch_lookup(
    domains: list[str],
    record_types: list[RecordType] | None = None,
    nameserver: str | None = None,
    timeout: float = 5.0,
) -> list[DNSResult]:
    """
    Perform DNS lookups for multiple domains concurrently
    """
    tasks = [
        lookup(domain,
               record_types,
               nameserver,
               timeout) for domain in domains
    ]
    return await asyncio.gather(*tasks)
