# MAC Address Spoofer

## Overview
Create a tool that changes network interface MAC addresses on Linux and Windows systems to test network configuration, improve privacy, or avoid network-based access controls. This project teaches network interface manipulation, platform-specific system administration, and demonstrates why network security can't rely solely on MAC address filtering.

## Step-by-Step Instructions

1. **Understand MAC addresses and network interfaces** by learning that Media Access Control (MAC) addresses are hardware identifiers assigned to network interface cards (NICs) on the data link layer. MAC addresses are typically 48 bits represented as six hexadecimal pairs (e.g., 00:1A:2B:3C:4D:5E), and each manufacturer is assigned a specific prefix—MAC addresses are local to the network and not routable on the internet like IP addresses.

2. **Research platform-specific techniques** for changing MAC addresses: on Linux, network interfaces are typically managed through `ifconfig`, `ip`, or network manager tools; on Windows, registry modifications or driver-level changes may be necessary. Understand that MAC spoofing requires administrator/root privileges and that different Linux distributions and Windows versions have different methods requiring careful implementation.

3. **Implement Linux MAC address modification** using subprocess calls to `ip link set` or `ifconfig` commands to change the MAC address. First disable the network interface, apply the new MAC address, then re-enable it. Handle different interface naming conventions (eth0, wlan0, enp0s3, etc.) and gracefully report errors if the interface doesn't exist or operations fail.

4. **Add Windows MAC address modification** support by modifying registry keys or using WMI (Windows Management Instrumentation) to update network adapter settings. Document Windows-specific limitations and compatibility issues across different Windows versions, and note when administrator elevation is required.

5. **Create MAC address validation** to ensure user-provided addresses are properly formatted and theoretically valid. Verify correct hexadecimal formatting, ensure the address is 48 bits (six octets), optionally validate that the address doesn't conflict with reserved ranges, and handle unicast vs. multicast address requirements.

6. **Implement automatic backup and restoration** by storing the original MAC address before modification so users can easily revert to factory settings. Create functions to restore the original address, and include a restore-on-exit feature that automatically reverts MAC addresses if the program is interrupted (via signal handlers or try/finally blocks).

7. **Add realistic MAC address generation** by optionally generating new MAC addresses that match real manufacturer prefixes (OUI - Organizationally Unique Identifier). Parse a database of known manufacturer prefixes and generate convincing MAC addresses that won't raise suspicion if logged—this teaches data realism in security testing scenarios.

8. **Build comprehensive documentation** explaining how MAC addresses work, discussing legitimate use cases (testing network behavior, privacy on local networks, testing MAC filtering), and including warnings about network policy violations if performed on corporate networks. Provide platform-specific usage examples, explain MAC address limitations for security (MAC filtering is easily spoofed), and discuss how proper network security uses stronger authentication methods beyond MAC addresses.

## Key Concepts to Learn
- MAC address format and purpose
- Network interface management
- Platform-specific system administration
- Subprocess execution and error handling
- Privilege requirements and security implications
- OUI database and manufacturer prefixes

## Deliverables
- Linux and Windows MAC address modification support
- Original MAC address backup and restoration
- MAC address validation and formatting
- Realistic MAC address generation with manufacturer prefixes
- Comprehensive error handling and permission checking
