# Network Traffic Analyzer

## Overview
Build a packet analysis tool using Scapy that captures and analyzes network traffic to visualize protocol distribution, identify top communication partners, and measure bandwidth usage. This project teaches packet-level network analysis, data visualization, and network troubleshooting techniques essential for network security and infrastructure management.

## Step-by-Step Instructions

1. **Install Scapy and understand packet structures** by running `pip install scapy` and learning how to capture packets from network interfaces using `sniff()`. Understand the OSI model layers and how different protocols (TCP, UDP, IP, DNS, HTTP, ICMP) are structured as nested packet layers—explore Scapy's packet dissection capabilities to understand what information is available from raw network packets.

2. **Implement packet capture functionality** that listens on a specified network interface (or all interfaces) and captures live packets for a specified duration or packet count. Handle the complexities of packet capture (may require root/administrator privileges on some systems) and implement proper error handling for permissions, offline pcap files, or unavailable network interfaces.

3. **Build protocol analysis and statistics** by parsing captured packets to categorize them by protocol type (TCP, UDP, ICMP, DNS, HTTP, HTTPS, etc.). Count packets per protocol and track statistics like total protocol bytes, percentage of traffic, and packet counts to understand the traffic composition of your network.

4. **Identify and track "top talkers"** by extracting source and destination IP addresses from packets and tallying communication volume between IP pairs. Track both incoming and outgoing traffic separately, rank the top communicating IP addresses, and calculate how much data was exchanged with each host to identify the busiest network participants.

5. **Calculate bandwidth usage statistics** by tracking bytes transferred per unit time and over the entire capture period. Implement running bandwidth calculations (e.g., bytes per second) to show traffic spikes over time, and calculate average bandwidth usage to understand typical network load patterns.

6. **Implement filtering capabilities** allowing users to capture and analyze specific types of traffic—filter by protocol (show only DNS, HTTP, TCP, etc.), source/destination IP addresses, or port numbers. Create a flexible filter syntax that users can specify from the command line or configuration file.

7. **Add data visualization** using `matplotlib`, `plotly`, or `bokeh` to create charts showing protocol distribution (pie chart), bandwidth usage over time (line graph), and top talkers (bar chart). Export visualizations as images or create interactive HTML dashboards for better data exploration and presentation.

8. **Create CSV/JSON export functionality** that outputs captured packet data and analysis statistics in structured formats suitable for further analysis in spreadsheets, databases, or custom analysis tools. Include detailed documentation explaining what each field means and provide example analysis workflows for common network troubleshooting scenarios (finding bandwidth hogs, detecting unusual protocols, investigating network issues).

## Key Concepts to Learn
- Packet capture and network sniffing
- OSI model and protocol structures
- Data aggregation and statistical analysis
- Visualization libraries and dashboard creation
- Network troubleshooting methodology

## Deliverables
- Live packet capture from network interfaces
- Protocol distribution analysis and statistics
- Top talkers identification with bandwidth tracking
- Flexible filtering by protocol, IP, and port
- Visualization dashboards and export formats
