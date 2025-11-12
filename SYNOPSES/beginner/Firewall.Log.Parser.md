# Simple Firewall Log Parser

## Overview
Build a tool that parses firewall logs from iptables, UFW, or pfSense to generate security reports on blocked connections, identify top attacking IPs, reveal most targeted ports, and visualize attack patterns. This project teaches log analysis, attack pattern recognition, and provides practical insights into network security incidents.

## Step-by-Step Instructions

1. **Understand firewall log formats** across different platforms—iptables logs typically appear in syslog with format "iptables: IN= OUT= SRC= DST= PROTO= SPT= DPT=", UFW uses similar formats with additional descriptors, and pfSense logs in a structured format with timestamp, rule, and traffic details. Research the specific format for each firewall type, document the fields available, and create parsing templates that extract source IP, destination IP, port numbers, protocol types, and action taken (ACCEPT/DROP).

2. **Implement robust log file parsing** by reading firewall log files and extracting key information using regular expressions or structured parsing libraries. Handle variations in log formatting, incomplete entries, and corrupted lines gracefully, implementing error handling that continues processing even when encountering malformed data. Support multiple log file formats through pluggable parsers or conditional logic.

3. **Create connection analysis functions** that aggregate blocked connections by source IP to identify the most active attackers, track which ports are most frequently targeted to reveal attack focus, and calculate attack frequency over time periods. Identify patterns like port scanning (attempts on many different ports from single source) vs. focused attacks (repeated attempts on specific ports/services).

4. **Build IP geolocation and reputation lookup** by integrating with APIs or local databases to identify where attacking IPs are located geographically and whether they're known malicious sources. Add context about ISP, hosting provider, and known threat intelligence about each attacking IP, helping analysts understand attack sources and patterns.

5. **Implement protocol and service analysis** by mapping target ports to common services (port 22 = SSH, 80 = HTTP, 443 = HTTPS, 3306 = MySQL, etc.) and analyzing protocol distribution to understand what services are being targeted. Identify unusual protocol combinations or suspicious port selections that might indicate specific attack types or reconnaissance.

6. **Create timeline and temporal analysis** showing when attacks occur (time of day, day of week, trending patterns), identifying whether attacks are persistent, escalating, or sporadic. Build heatmaps showing attack intensity over time and detect anomalies like sudden spikes in firewall blocks that might indicate coordinated attacks.

7. **Generate comprehensive reports** in multiple formats (HTML dashboards, PDF reports, JSON data) showing top attacking IPs ranked by frequency, most targeted ports with attack counts, geographic distribution of attackers, and timeline visualizations. Include summary statistics (total blocked connections, unique attackers, ports targeted) and highlight the most critical findings for executive visibility.

8. **Build comprehensive documentation** explaining firewall log analysis concepts, providing examples of parsed logs, and discussing how this analysis fits into incident response and security operations workflows. Include guidance on interpreting results (distinguishing research traffic from actual attacks), discussing legitimate reasons for blocks, and providing recommendations for response actions (blocking IPs, alerting administrators, investigating incidents).

## Key Concepts to Learn
- Firewall configuration and log formats
- Regular expressions and text parsing
- Data aggregation and statistical analysis
- IP geolocation and threat intelligence
- Timeline analysis and temporal patterns
- Security event investigation

## Deliverables
- Multi-format firewall log parser (iptables, UFW, pfSense)
- Blocked connection analysis and aggregation
- Top attacking IPs and targeted ports identification
- Temporal analysis and attack pattern detection
- IP reputation and geolocation lookup
- Multi-format reporting and dashboards
