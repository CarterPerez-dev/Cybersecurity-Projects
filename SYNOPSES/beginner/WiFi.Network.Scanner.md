# WiFi Network Scanner

## Overview
Build a wireless network reconnaissance tool that scans for nearby wireless access points, displaying SSIDs, signal strength, encryption types, connected clients, and identifying rogue access points or weak security configurations. This project teaches wireless networking fundamentals, WiFi security protocols, and demonstrates reconnaissance techniques for network assessments.

## Step-by-Step Instructions

1. **Understand WiFi protocols and terminology** by learning about wireless networks operating on 2.4GHz and 5GHz bands, SSID (Service Set Identifier) as the network name, signal strength measured in dBm, and encryption standards (WEP, WPA, WPA2, WPA3, Open). Study authentication methods (PSK for personal networks, Enterprise for corporate), understand beacon frames that advertise networks, and learn how to interpret these signals to assess network security posture.

2. **Install and configure wireless scanning tools** on your system—on Linux, install tools like `aircrack-ng` suite, `iwconfig`, `nmcli`, or use Python libraries like `scapy` or `wifi` module. On Windows, use tools like NetStumbler, Acrylic WiFi Home, or Python wrappers around Windows WiFi APIs. Understand that WiFi scanning often requires elevated privileges and may not work on all network cards.

3. **Implement access point discovery** by capturing WiFi beacon frames that contain network information—use packet sniffing libraries (Scapy) to intercept and parse frames, or use system APIs to query available networks and their properties. Extract and display SSIDs, BSSID (MAC address), channel numbers, signal strength in dBm or percentage, frequency band, and encryption type for each discovered network.

4. **Add encryption and security assessment** by analyzing the security protocols advertised by each network: identify WEP (very weak and deprecated), WPA (outdated but better than WEP), WPA2 (current standard), and WPA3 (newest, most secure). Flag networks using deprecated or weak encryption, networks with no encryption (open networks), and enterprise vs. personal authentication modes.

5. **Implement client detection and identification** by using ARP scanning or manufacturer database lookups to identify connected devices on open networks or through other reconnaissance techniques. Display the number of active clients on each network, their MAC addresses if available, and use vendor lookup tables to identify device types (phones, laptops, IoT devices) based on MAC prefixes.

6. **Create rogue access point detection** by identifying suspicious networks mimicking legitimate ones (similar SSIDs, unusual channel selections, MAC addresses not matching known vendor patterns). Implement algorithms to detect "evil twins" (networks impersonating legitimate services like airport WiFi), suspicious broadcast options, and networks with unusual signal patterns.

7. **Build a comprehensive scan report** displaying results in organized formats (table view, JSON export, CSV export) sorted by signal strength, SSID, security level, or other criteria. Include visual elements like signal strength bars, color-coded security ratings (green for WPA3, yellow for WPA2, red for WEP/Open), and summary statistics showing total networks found, security distribution, and identified risks.

8. **Create detailed documentation** explaining WiFi security concepts, discussing risk assessment for different encryption types, providing examples of scanning output, and including guidance on what to do if rogue networks or insecure configurations are detected. Cover legal considerations (only scan networks you own or have permission to assess), explain limitations of wireless scanning, and discuss WiFi security recommendations for users and organizations.

## Key Concepts to Learn
- WiFi protocols and frame structures
- Wireless security standards and encryption
- Packet sniffing and beacon frame analysis
- MAC address lookup and vendor identification
- Signal strength analysis and interpretation
- Rogue access point detection

## Deliverables
- Wireless access point discovery and enumeration
- SSID, BSSID, channel, and signal strength reporting
- Encryption type and security level assessment
- Connected client detection
- Rogue access point identification
- Multi-format reporting and export
