# 00-OVERVIEW.md

# DLP Scanner

## What This Is

A command-line Data Loss Prevention scanner that detects sensitive data across three surfaces: files (PDF, DOCX, XLSX, CSV, JSON, XML, YAML, Parquet, Avro, archives, emails), databases (PostgreSQL, MySQL, MongoDB, SQLite), and network captures (PCAP/PCAPNG with protocol parsing and TCP reassembly). It uses a confidence scoring pipeline combining regex matching, checksum validation (Luhn for credit cards, Mod-97 for IBANs, Mod-11 for NHS numbers), keyword proximity analysis, and Shannon entropy detection. Findings are classified by severity and mapped to compliance frameworks (HIPAA, PCI-DSS, GDPR, CCPA, SOX, GLBA, FERPA). Output supports console Rich tables, JSON, SARIF 2.1.0 for CI/CD, and CSV for compliance teams.

## Why This Matters

Data breaches involving PII exposure keep appearing because organizations cannot find sensitive data they do not know exists. The 2017 Equifax breach exposed 147 million SSNs from an unpatched Apache Struts application, but the underlying problem was that SSNs were stored in plaintext across multiple database tables without anyone tracking where that data lived. In 2019, Capital One lost 100 million credit applications from an S3 bucket because a misconfigured WAF allowed server-side request forgery, and nobody had scanned those files to realize unencrypted SSNs and credit card numbers sat in flat CSV exports. The Marriott breach (2018) exposed 500 million records including 5.25 million unencrypted passport numbers, partially because the Starwood reservation system merged without a data inventory that would have flagged those fields as sensitive.

These are not failure-of-firewall problems. They are failure-of-visibility problems. DLP tools exist to answer "where is our sensitive data?" before attackers answer it for you. Commercial solutions (Symantec DLP, Microsoft Purview, Netskope) cost six figures and require enterprise deployment, but the core detection logic is straightforward: pattern matching with validation, context analysis to reduce false positives, and compliance framework mapping to prioritize remediation.

This project builds a DLP engine from scratch, teaching you the same detection techniques that power production systems.

**Real world scenarios where this applies:**
- Security engineers scanning file shares before a cloud migration to find PII that needs encryption
- Compliance teams auditing database tables for HIPAA-regulated PHI that should not be in plaintext
- SOC analysts inspecting PCAP captures for credentials or PII transmitted in the clear
- DevOps teams running DLP checks in CI/CD pipelines to catch secrets before they reach production
- Incident responders determining what sensitive data was accessible from a compromised network segment

## What You'll Learn

**Security Concepts:**
- Data classification tiers and how PII, PHI, PCI, and credential data map to regulatory requirements
- Confidence scoring: why regex alone produces false positives and how checksum validation, context keywords, and entity co-occurrence reduce them
- Compliance framework mapping: HIPAA's 18 identifiers, PCI-DSS cardholder data, GDPR personal data categories, CCPA consumer information
- Network DLP: detecting sensitive data in transit, DNS exfiltration via high-entropy subdomain labels, base64-encoded payloads in HTTP bodies
- Redaction strategies: why you never store the raw matched content in findings

**Technical Skills:**
- Building a multi-format text extraction pipeline that handles 14+ file formats through a unified Protocol interface
- Database schema introspection across 4 database engines with statistical sampling (TABLESAMPLE BERNOULLI, $sample aggregation)
- TCP stream reassembly from raw packets using sequence-number ordering and bidirectional flow key normalization
- Confidence scoring pipeline: base scores, checksum boosts, context keyword proximity windows, entity co-occurrence
- SARIF 2.1.0 output for GitHub code scanning integration

**Tools and Techniques:**
- Typer CLI with Annotated-style parameters and global option propagation through Click context
- Pydantic 2.x for configuration validation with YAML loading
- structlog with stdlib integration for structured JSON logging
- orjson for high-performance JSON serialization
- asyncpg, aiomysql, pymongo async, aiosqlite for async database access
- dpkt for fast PCAP parsing (100x faster than Scapy)
- pytest with hypothesis for property-based testing of detection rules

## Prerequisites

**Required knowledge:**
- Python fundamentals: dataclasses, type hints, list comprehensions, context managers
- Basic networking: TCP/IP, ports, packets, what PCAP files contain
- Basic SQL: SELECT, WHERE, table schemas, column types
- Security basics: what PII is, why SSNs and credit card numbers need protection, what compliance frameworks exist

**Tools you'll need:**
- Python 3.12+ (uses modern generic syntax and `from __future__ import annotations`)
- uv package manager (install: `curl -LsSf https://astral.sh/uv/install.sh | sh`)
- A terminal with UTF-8 support (for Rich console output)

**Helpful but not required:**
- Experience with regex and pattern matching
- Familiarity with dpkt or Scapy for packet analysis
- Knowledge of database URIs and connection strings
- Understanding of SARIF format for CI/CD security tooling

## Quick Start

```bash
bash install.sh
dlp-scan file ./data
dlp-scan file ./data -f json -o results.json
dlp-scan db sqlite:///path/to/database.db
dlp-scan report summary results.json
```
