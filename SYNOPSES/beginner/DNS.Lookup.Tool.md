# DNS Lookup Tool

## Overview
Create a Python tool that queries DNS records using the `dnspython` library to retrieve multiple record types (A, AAAA, MX, TXT, NS, CNAME) for a target domain. This project teaches network fundamentals, DNS protocol knowledge, and domain reconnaissance techniques essential for cybersecurity professionals and system administrators.

## Step-by-Step Instructions

1. **Install and explore dnspython library** by running `pip install dnspython` and familiarizing yourself with its query functions, resolver objects, and exception handling. Understand how DNS queries work at a fundamental level—how different record types serve different purposes (A records for IPv4, MX for mail servers, TXT for text records, etc.) and how DNS is hierarchical with root nameservers delegating to authoritative servers.

2. **Implement individual query functions** for each major DNS record type, creating separate functions for A records (IPv4 addresses), AAAA records (IPv6 addresses), MX records (mail exchange servers), TXT records (text information), NS records (nameservers), and CNAME records (aliases). Test each function independently to ensure it queries correctly and handles the specific response format for that record type.

3. **Add error handling and exception management** to gracefully handle common DNS issues like domain not found (NXDOMAIN), no records of that type (NODATA), DNS server timeouts, and network connectivity problems. Provide clear error messages to users explaining what went wrong and suggesting troubleshooting steps.

4. **Create a unified query interface** that allows users to specify a domain and optionally which record types to query, or simply query all types automatically. Implement this as a main function that coordinates calls to individual record type functions and aggregates the results into a cohesive output.

5. **Implement reverse DNS lookup functionality** that takes an IP address and queries for the corresponding domain name (PTR records). This is valuable for security investigations, ISP identification, and understanding network ownership—demonstrate how reverse DNS can reveal hostname information associated with an IP.

6. **Build formatted table output** using libraries like `tabulate` to display results in clean, organized columns showing record type, value, TTL (time-to-live), and other relevant metadata. Use color coding or styling to distinguish between different record types and make the output visually scannable.

7. **Add querying options and filters** allowing users to specify custom DNS servers to query (instead of using system defaults), set query timeouts, enable recursive resolution options, and filter results by specific criteria. Include a verbose mode that shows additional metadata like response codes and query statistics.

8. **Create comprehensive documentation** with examples of querying different domain types, explaining what each record type means and why it matters in cybersecurity contexts (MX records for phishing analysis, TXT records for DMARC/SPF verification, NS records for infrastructure mapping, etc.). Include usage examples and explain how DNS reconnaissance fits into broader security reconnaissance workflows.

## Key Concepts to Learn
- DNS protocol and record types
- Network querying and socket operations
- Exception handling and error management
- Domain infrastructure reconnaissance
- IPv4 and IPv6 addressing

## Deliverables
- Functional DNS query tool for all major record types
- Reverse DNS lookup capability
- Clean formatted output with multiple display options
- Custom DNS server support and advanced filtering
