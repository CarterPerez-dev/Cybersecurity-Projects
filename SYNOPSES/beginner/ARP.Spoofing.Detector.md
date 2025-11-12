# ARP Spoofing Detector

## Overview
Build a network security tool that monitors Address Resolution Protocol (ARP) traffic to detect spoofing attacks where attackers forge ARP messages to intercept network traffic. This project teaches layer 2 network attacks, ARP protocol mechanics, and demonstrates fundamental network intrusion detection techniques.

## Step-by-Step Instructions

1. **Understand ARP protocol and spoofing attacks** by learning that ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on local networks, and that ARP spoofing (also called ARP poisoning) involves sending forged ARP messages claiming an attacker's MAC address is associated with legitimate IPs. Study attack mechanics: when a victim trusts the forged ARP, it sends traffic destined for a legitimate IP to the attacker instead, enabling man-in-the-middle (MITM) attacks, session hijacking, and network disruption.

2. **Implement ARP packet capture** using `scapy` to sniff network traffic and filter for ARP packets specifically. Extract relevant information from each ARP packet: source MAC address, source IP, destination MAC address, destination IP, and operation type (request vs. reply). Understand that detecting ARP spoofing requires analyzing patterns rather than individual packets since ARP is legitimate protocol with normal variation.

3. **Build MAC-to-IP mapping database** that tracks the relationship between IP addresses and their legitimate MAC addresses on the network. Create a baseline of known-good mappings through active ARP scanning or passive observation over time, storing these mappings with timestamps and confidence levels. Use this database as reference to detect when a single IP suddenly claims to come from a different MAC address.

4. **Implement duplicate IP detection** by identifying when the same IP address is claimed by multiple different MAC addresses within a suspicious time window. Legitimate cases exist (like DHCP reassignment or IP changes), but rapid duplicates indicate spoofing. Implement heuristics distinguishing normal IP transitions (gradual, expected) from suspicious patterns (sudden, frequent changes, many IPs from one MAC).

5. **Create MAC address change detection** by monitoring when a previously known MAC-to-IP association changes, flagging unexpected transitions as suspicious. Track the source of the mapping change (was it a unicast ARP reply to this specific host, or broadcast to whole network?) and the frequency (legitimate changes happen infrequently while spoofing may generate many changes quickly).

6. **Add gratuitous ARP analysis** recognizing that legitimate hosts send gratuitous ARPs when joining networks or recovering from network issues, but attackers abuse this to poison ARP caches. Detect suspicious patterns: numerous gratuitous ARPs from single MAC, gratuitous ARPs announcing IPs the sender shouldn't legitimately possess, or targeted gratuitous ARPs after network changes.

7. **Implement alerting and logging** that notifies administrators when potential ARP spoofing is detected, including evidence (affected IPs, MAC addresses, ARP messages seen). Log all ARP traffic to files for forensic analysis, storing complete packet captures and statistical summaries enabling incident investigation and proving attacks occurred to stakeholders.

8. **Build comprehensive documentation** explaining ARP protocol mechanics and spoofing attack techniques, discussing detection methodology and limitations (cannot detect application-layer spoofing), and providing deployment guidance. Compare your detector to other tools (Arpwatch, Arpalert), discuss integration with network infrastructure (DHCP snooping, DAI - Dynamic ARP Inspection), and explain how ARP spoofing detection fits into broader network security monitoring strategies.

## Key Concepts to Learn
- ARP protocol and layer 2 networking
- Man-in-the-middle attack techniques
- Packet capture and analysis
- Pattern recognition for attack detection
- Statistical analysis of network behavior
- Network intrusion detection systems

## Deliverables
- Live ARP packet capture and analysis
- MAC-to-IP mapping database and tracking
- Duplicate IP detection
- Suspicious MAC-to-IP association identification
- Gratuitous ARP pattern analysis
- Alerting and comprehensive logging
