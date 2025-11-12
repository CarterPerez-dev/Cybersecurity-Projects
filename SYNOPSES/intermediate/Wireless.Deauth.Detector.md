# Wireless Deauthentication Detector

## Overview
Build a WiFi security monitor that detects deauthentication attacks by analyzing wireless frames, identifying abnormal disconnect patterns, and alerting administrators when clients are being forcibly disconnected from networks. This project teaches WiFi frame analysis, packet-level networking, and demonstrates techniques for detecting layer 2 wireless attacks.

## Step-by-Step Instructions

1. **Understand WiFi deauthentication attacks and frame analysis** by learning that deauthentication attacks use 802.11 management frames (subtype 12) to disconnect clients from access points by sending spoofed deauth messages. Study frame structure: management frames contain source/destination MAC addresses, reason codes indicating disconnect reasons (1=unspecified, 2=previous auth no longer valid, 7=class 2 frame received from non-authenticated entity, etc.), and sequence numbers. Legitimate deauth frames exist but attack frames have anomalous patterns: rapid sequences, unusual reason codes, or spoofed MAC addresses.

2. **Implement packet capture for 802.11 frames** using `scapy` to capture WiFi packets in monitor mode on Linux using `aircrack-ng` suite tools. Parse management frames specifically, extracting deauthentication frame information including source/destination MACs, reason code, timestamp, and signal strength. Handle frame encryption and implement decryption for WPA2 if capturing encrypted traffic requires it (may use encrypted traffic analysis even without decryption).

3. **Build deauthentication frame detection** that identifies and filters packets for deauth frames specifically (management frame with type 0, subtype 12), extracts details about the disconnect event, and tracks which clients are being disconnected from which access points. Implement frame validation detecting spoofed or malformed frames, and log legitimate reasons for disconnection (e.g., client leaving network gracefully) differently from attack indicators.

4. **Create anomaly detection for deauth patterns** by establishing baseline: normal networks have occasional deauth frames (clients disconnecting, roaming between APs), while attacks show abnormal patterns. Detect red flags: high volume of deauth frames in short time period, repeated disconnections of same client, deauth from multiple sources targeting single client (indicates multiple attackers), or deauth frames with unusual reason codes commonly used in attacks (reason 2 "previous authentication no longer valid" or 7 "class 2 frame from non-authenticated entity").

5. **Implement client impact tracking** monitoring which WiFi clients are affected by deauthentication patterns: identify clients experiencing frequent unexpected disconnects, correlate deauth frame timing with client disconnect events, and track clients that repeatedly reconnect to network (indicating attack followed by victim reconnection). Build profiles of client behavior helping distinguish attacks from legitimate disconnections.

6. **Add spoofed frame detection** identifying deauthentication frames originating from sources other than legitimate access points (spoofed source MACs). Compare deauth source MAC against known legitimate APs in network, detect when frames claim to come from non-existent APs, and identify when single attacker uses multiple spoofed MACs to send many deauth frames. Track attacker MAC addresses and attempt to localize attacker location using signal strength analysis.

7. **Create alerting and logging system** that triggers alerts when deauthentication attacks detected, including attack details (affected clients, AP, attack duration, frames captured, attacker info if identifiable). Log all deauth frames for forensic analysis, build attack timelines showing attack progression, and maintain statistics on attack frequency and trends. Implement graduated alerting: single deauth frame = log only, attack pattern = alert administrators, severe attack = escalate to incident response.

8. **Build comprehensive documentation** explaining WiFi deauthentication attacks and defenses, discussing detection limitations (cannot fully prevent attacks, only detect them), and providing deployment guidance. Compare your detector to similar tools (MDK3, Airgeddon wrapper), discuss legal considerations (only monitor networks you own or have permission to assess), and explain how deauth detection fits into broader WiFi security monitoring. Include examples of actual attack detection and discuss response actions (changing AP channels to avoid attack, increasing authentication security, using protected management frames - PMF).

## Key Concepts to Learn
- 802.11 WiFi frame structure and types
- Management frames and subframes
- Monitor mode packet capture
- Anomaly detection and pattern analysis
- Spoofed frame identification
- Client behavior tracking
- Wireless attack signatures

## Deliverables
- 802.11 management frame capture
- Deauthentication frame identification and parsing
- Anomaly detection for attack patterns
- Client impact tracking
- Spoofed frame detection and localization
- Attack alerting and logging
- Forensic timeline generation
