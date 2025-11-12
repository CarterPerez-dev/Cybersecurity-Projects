# OSINT Reconnaissance Framework

## Overview
Build an Open Source Intelligence (OSINT) framework that aggregates publicly available information about targets from multiple sources including WHOIS, DNS, social media, breach databases, and search engines, automating reconnaissance for penetration testing and threat analysis. This project teaches information gathering techniques, API integration, and demonstrates tools used for threat intelligence and reconnaissance.

## Step-by-Step Instructions

1. **Understand OSINT techniques and information sources** by learning that OSINT collects intelligence exclusively from public sources (no hacking required): WHOIS provides domain/IP registration information and contact details, DNS queries reveal infrastructure, social media contains employee information and organizational structure, breach databases (HaveIBeenPwned, Breachbase) show compromised credentials, search engines and cached pages archive historical information, GitHub reveals infrastructure details and secrets in code. Study reconnaissance workflows: starting with target organization, discovering employee information, identifying infrastructure, finding application URLs, and collecting all information into profiles.

2. **Implement WHOIS and domain information collection** using `whois` library and APIs to query domain registration details: registrant information (name, organization, address, email, phone), nameservers, creation/expiration dates, and registrar details. Build IP WHOIS queries determining IP ownership and ISP details. Extract metadata indicating hosting providers, DNS services, and organizational information from WHOIS records.

3. **Build DNS reconnaissance functionality** querying multiple DNS record types (A, AAAA, MX, TXT, NS, CNAME, SOT) to map organizational infrastructure. Implement DNS enumeration discovering subdomains through zone transfers (if misconfigured), brute-force enumeration trying common subdomain names, and analyzing DNS propagation. Extract information about email servers (MX records), organizational domains (TXT records with DMARC/SPF), and hosting infrastructure.

4. **Create social media and people search integration** extracting information about target employees from LinkedIn, GitHub, Twitter, and other platforms. Build APIs to search for employees, extract employment history, skills, and organizational structure. Query GitHub for code repositories revealing infrastructure details, architecture information, and sometimes accidentally committed secrets. Parse public profiles extracting email addresses, phone numbers, and organizational information.

5. **Implement breach database queries** checking whether email addresses or usernames appear in known breaches using APIs like HaveIBeenPwned, Breachbase, or others. Retrieve compromised data associated with targets: leaked passwords (useful for credential stuffing attacks), personal information (dates of birth, phone numbers useful for social engineering), and behavioral information. Maintain local copies of popular breach databases for offline searching.

6. **Build search engine and cached data collection** using Google Custom Search API, Shodan API, and other search services to discover web-accessible resources: find email addresses through Google search, discover subdomain information via search engines, use Shodan to find services running on non-standard ports, and retrieve historical data from Internet Archive's Wayback Machine. Extract information about previously published pages revealing infrastructure changes over time.

7. **Create unified target profile generation** aggregating information from all sources into comprehensive dossier: compile employee information with social media profiles and organizational roles, correlate different identities (same person with multiple usernames), build infrastructure map showing hosting providers and services, identify email patterns and potential additional addresses. Generate timeline showing organizational changes and infrastructure modifications.

8. **Build comprehensive reporting with visualization** displaying collected intelligence organized by category: company/organizational structure with employee hierarchy, infrastructure diagram showing discovered services and hosting, timeline of discovered information and changes, breach information associated with employees, and risk assessment based on information exposure. Create mind maps visualizing relationships between discovered entities, generate exportable reports for penetration testing documentation, and provide raw data exports for analysis tools. Compare to commercial OSINT frameworks (Maltego, SpiderFoot, TheHarvester) and discuss limitations (information availability varies, privacy concerns, legal considerations around data use).

## Key Concepts to Learn
- OSINT techniques and information sources
- WHOIS and DNS reconnaissance
- Social media scraping and aggregation
- Breach database integration
- Search engine and archive querying
- Data correlation and entity linking
- Target profiling methodology
- Visualization and reporting

## Deliverables
- WHOIS and domain information gathering
- DNS reconnaissance and enumeration
- Social media intelligence gathering
- Breach database integration
- Search engine reconnaissance
- Internet Archive (Wayback Machine) querying
- Unified target profile generation
- Relationship mapping and visualization
- Comprehensive OSINT reports
