#!/usr/bin/env bash
# ©AngelaMos | 2026
# registry_data.sh

register_control "1.1.1" \
    "Initial Setup" \
    "Ensure mounting of cramfs is disabled" \
    "1" \
    "yes" \
    "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. Disabling cramfs eliminates a potential attack surface by preventing rarely-used filesystem modules from being loaded. Most modern systems have no legitimate need for cramfs support." \
    "echo 'install cramfs /bin/true' >> /etc/modprobe.d/cramfs.conf && echo 'blacklist cramfs' >> /etc/modprobe.d/cramfs.conf"

register_control "1.1.2" \
    "Initial Setup" \
    "Ensure mounting of freevxfs is disabled" \
    "1" \
    "yes" \
    "The freevxfs filesystem type is a free version of the Veritas filesystem used by HP-UX and other commercial systems. Disabling this module reduces the attack surface by removing support for an uncommon filesystem. Exploitation of vulnerabilities in rarely maintained filesystem drivers is a known threat vector." \
    "echo 'install freevxfs /bin/true' >> /etc/modprobe.d/freevxfs.conf && echo 'blacklist freevxfs' >> /etc/modprobe.d/freevxfs.conf"

register_control "1.1.3" \
    "Initial Setup" \
    "Ensure mounting of jffs2 is disabled" \
    "1" \
    "yes" \
    "The jffs2 filesystem type is a log-structured filesystem used in flash memory devices. Disabling this module prevents potential exploitation through crafted jffs2 filesystem images. Standard servers typically do not require jffs2 support as it is designed for embedded systems." \
    "echo 'install jffs2 /bin/true' >> /etc/modprobe.d/jffs2.conf && echo 'blacklist jffs2' >> /etc/modprobe.d/jffs2.conf"

register_control "1.1.4" \
    "Initial Setup" \
    "Ensure mounting of hfs is disabled" \
    "1" \
    "yes" \
    "The hfs filesystem type is the native filesystem for older Macintosh systems. Disabling hfs prevents potential exploits targeting this legacy filesystem driver. Linux servers rarely need to mount Apple HFS volumes and removing the capability reduces risk." \
    "echo 'install hfs /bin/true' >> /etc/modprobe.d/hfs.conf && echo 'blacklist hfs' >> /etc/modprobe.d/hfs.conf"

register_control "1.1.5" \
    "Initial Setup" \
    "Ensure mounting of hfsplus is disabled" \
    "1" \
    "yes" \
    "The hfsplus filesystem type is the successor to hfs used on modern Apple systems. Disabling this kernel module reduces exposure to vulnerabilities in an unnecessary filesystem driver. Servers should not need to interact with Apple-formatted media." \
    "echo 'install hfsplus /bin/true' >> /etc/modprobe.d/hfsplus.conf && echo 'blacklist hfsplus' >> /etc/modprobe.d/hfsplus.conf"

register_control "1.1.6" \
    "Initial Setup" \
    "Ensure mounting of squashfs is disabled" \
    "2" \
    "yes" \
    "The squashfs filesystem is a compressed read-only filesystem commonly used for live CDs and snap packages. Disabling squashfs prevents attackers from using crafted squashfs images to exploit kernel vulnerabilities. This is a Level 2 control because disabling squashfs may break snap package functionality." \
    "echo 'install squashfs /bin/true' >> /etc/modprobe.d/squashfs.conf && echo 'blacklist squashfs' >> /etc/modprobe.d/squashfs.conf"

register_control "1.1.7" \
    "Initial Setup" \
    "Ensure mounting of udf is disabled" \
    "1" \
    "yes" \
    "The udf filesystem type is the universal disk format used on DVDs and newer optical media. Disabling this module prevents potential exploitation of vulnerabilities in the UDF driver through crafted media. Servers generally do not need optical disc filesystem support." \
    "echo 'install udf /bin/true' >> /etc/modprobe.d/udf.conf && echo 'blacklist udf' >> /etc/modprobe.d/udf.conf"

register_control "1.1.8" \
    "Initial Setup" \
    "Ensure mounting of vfat is limited" \
    "2" \
    "yes" \
    "The vfat filesystem type is used for the FAT filesystem common on removable media and UEFI system partitions. On non-UEFI systems this module should be disabled to reduce the attack surface. UEFI systems require vfat for the EFI System Partition so this control must be evaluated accordingly." \
    "echo 'install vfat /bin/true' >> /etc/modprobe.d/vfat.conf && echo 'blacklist vfat' >> /etc/modprobe.d/vfat.conf"

register_control "1.2.1" \
    "Initial Setup" \
    "Ensure /tmp is a separate partition" \
    "1" \
    "yes" \
    "The /tmp directory is a world-writable location used for temporary file storage by all users and applications. Mounting /tmp as a separate partition enables administrators to apply restrictive mount options. This prevents /tmp from consuming root filesystem space and allows enforcing noexec, nosuid, and nodev protections." \
    "echo 'tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0' >> /etc/fstab && mount -o remount /tmp"

register_control "1.2.2" \
    "Initial Setup" \
    "Ensure noexec option set on /tmp" \
    "1" \
    "yes" \
    "The noexec mount option prevents execution of binaries stored on the /tmp partition. This blocks attackers from downloading and running malicious executables in the world-writable /tmp directory. Setting noexec on /tmp is a critical defense-in-depth measure against privilege escalation attacks." \
    "mount -o remount,noexec /tmp"

register_control "1.2.3" \
    "Initial Setup" \
    "Ensure nosuid option set on /tmp" \
    "1" \
    "yes" \
    "The nosuid mount option prevents setuid and setgid bits from taking effect on the /tmp partition. This stops attackers from placing setuid binaries in /tmp to escalate privileges. Combined with noexec this provides strong protection against local privilege escalation via temporary files." \
    "mount -o remount,nosuid /tmp"

register_control "1.2.4" \
    "Initial Setup" \
    "Ensure nodev option set on /tmp" \
    "1" \
    "yes" \
    "The nodev mount option prevents the creation and use of block and character special devices on the /tmp partition. Attackers could create device files in /tmp to access hardware directly and bypass security controls. Setting nodev on /tmp ensures that no device nodes can be exploited from temporary storage." \
    "mount -o remount,nodev /tmp"

register_control "1.3.1" \
    "Initial Setup" \
    "Ensure package manager repositories are configured" \
    "1" \
    "no" \
    "Package repositories provide a trusted source for installing and updating software on the system. Verifying that repositories are correctly configured ensures that security patches come from legitimate sources. Misconfigured or unauthorized repositories could introduce backdoored or vulnerable packages." \
    "apt-cache policy"

register_control "1.3.2" \
    "Initial Setup" \
    "Ensure GPG keys are configured" \
    "1" \
    "no" \
    "GPG keys are used to authenticate packages downloaded from repositories before installation. Ensuring GPG keys are properly configured prevents the installation of tampered or unsigned packages. Without valid GPG keys an attacker could perform a man-in-the-middle attack on package downloads." \
    "apt-key list"

register_control "1.4.1" \
    "Initial Setup" \
    "Ensure bootloader password is set" \
    "1" \
    "yes" \
    "Setting a bootloader password prevents unauthorized users from modifying boot parameters at the GRUB menu. Without this protection an attacker with physical access could boot into single user mode or modify kernel parameters. A GRUB password ensures that only authorized administrators can alter the boot process." \
    "grub-mkpasswd-pbkdf2 && cat <<GRUBEOF >> /etc/grub.d/40_custom\nset superusers=\"root\"\npassword_pbkdf2 root <encrypted-password>\nGRUBEOF\nupdate-grub"

register_control "1.4.2" \
    "Initial Setup" \
    "Ensure permissions on bootloader config are configured" \
    "1" \
    "yes" \
    "The GRUB configuration file contains sensitive boot parameters and potentially the bootloader password hash. Restricting permissions ensures only root can read or modify the bootloader configuration. World-readable bootloader configs could leak password hashes or reveal system configuration details." \
    "chown root:root /boot/grub/grub.cfg && chmod 600 /boot/grub/grub.cfg"

register_control "1.4.3" \
    "Initial Setup" \
    "Ensure authentication required for single user mode" \
    "1" \
    "yes" \
    "Single user mode provides a root shell with minimal services for system recovery. Without authentication requirements an attacker with physical access gains immediate root access through single user mode. Requiring a root password for single user mode prevents unauthorized recovery-mode access." \
    "passwd root"

register_control "1.5.1" \
    "Initial Setup" \
    "Ensure address space layout randomization is enabled" \
    "1" \
    "yes" \
    "Address Space Layout Randomization (ASLR) randomizes the memory addresses used by processes including the stack, heap, and libraries. This makes it significantly harder for attackers to exploit memory corruption vulnerabilities reliably. ASLR should be set to mode 2 for full randomization of stack, VDSO, shared memory, and data segments." \
    "sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-cisaudit.conf"

register_control "1.5.2" \
    "Initial Setup" \
    "Ensure core dumps are restricted" \
    "1" \
    "yes" \
    "Core dumps capture the memory contents of a process when it crashes and may contain sensitive data such as passwords or encryption keys. Restricting core dumps prevents users from creating files that could expose this information. Setuid programs must also be prevented from dumping core via the suid_dumpable sysctl." \
    "echo '* hard core 0' >> /etc/security/limits.conf && sysctl -w fs.suid_dumpable=0 && echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-cisaudit.conf"

register_control "1.5.3" \
    "Initial Setup" \
    "Ensure prelink is not installed" \
    "1" \
    "yes" \
    "Prelink modifies ELF shared libraries and executables to reduce startup time by pre-computing symbol resolutions. However prelink interferes with AIDE and other integrity-checking tools by changing binary checksums after each prelink run. Removing prelink ensures that file integrity monitoring produces reliable and consistent results." \
    "prelink -ua && apt-get remove -y prelink"

register_control "2.1.1" \
    "Services" \
    "Ensure xinetd is not installed" \
    "1" \
    "yes" \
    "The xinetd service is an extended internet services daemon that manages network connections for various legacy services. Modern systems use systemd socket activation instead making xinetd unnecessary. Removing xinetd eliminates a potential entry point for attacks targeting legacy network services." \
    "apt-get remove -y xinetd"

register_control "2.1.2" \
    "Services" \
    "Ensure openbsd-inetd is not installed" \
    "1" \
    "yes" \
    "The openbsd-inetd package provides a legacy internet super-server similar to xinetd. Like xinetd it has been superseded by systemd socket activation on modern distributions. Removing it reduces the attack surface by eliminating an unnecessary network service dispatcher." \
    "apt-get remove -y openbsd-inetd"

register_control "2.2.1" \
    "Services" \
    "Ensure X Window System is not installed" \
    "1" \
    "yes" \
    "The X Window System provides a graphical user interface framework that is unnecessary on server systems. Running X11 significantly increases the attack surface with a large codebase that has a history of security vulnerabilities. Servers should be administered remotely via SSH and do not require graphical display capabilities." \
    "apt-get remove -y xserver-xorg*"

register_control "2.2.2" \
    "Services" \
    "Ensure Avahi Server is not installed" \
    "1" \
    "yes" \
    "Avahi is a system that implements multicast DNS/DNS-SD for zero-configuration networking and automatic service discovery. On a server this service is unnecessary and exposes the system to multicast-based network attacks. Removing Avahi eliminates a service that could be exploited for network reconnaissance or denial of service." \
    "systemctl disable avahi-daemon && apt-get remove -y avahi-daemon"

register_control "2.2.3" \
    "Services" \
    "Ensure CUPS is not installed" \
    "1" \
    "no" \
    "CUPS provides the Common Unix Printing System that enables a system to act as a print server. Unless the server specifically needs to manage printers CUPS should be removed to reduce the attack surface. CUPS listens on network ports and has had multiple remote code execution vulnerabilities in the past." \
    "apt-get remove -y cups"

register_control "2.2.4" \
    "Services" \
    "Ensure DHCP Server is not installed" \
    "1" \
    "yes" \
    "The ISC DHCP server package allows a system to act as a DHCP server assigning IP addresses to network clients. Unless the system is specifically designated as a DHCP server this service should not be present. An unauthorized DHCP server can be used to perform man-in-the-middle attacks on the local network." \
    "apt-get remove -y isc-dhcp-server"

register_control "2.2.5" \
    "Services" \
    "Ensure LDAP server is not installed" \
    "1" \
    "yes" \
    "The slapd package provides an OpenLDAP directory server for centralized authentication and directory services. Unless the system is specifically designated as an LDAP server this service increases the attack surface unnecessarily. LDAP servers handle sensitive authentication data and must be carefully secured if required." \
    "apt-get remove -y slapd"

register_control "2.2.6" \
    "Services" \
    "Ensure NFS is not installed" \
    "1" \
    "yes" \
    "NFS allows sharing directories over the network and is a common target for exploitation. Unless the system specifically needs to serve NFS shares the server package should be removed. NFS has historically had numerous security issues including weak authentication and data exposure." \
    "apt-get remove -y nfs-kernel-server"

register_control "2.2.7" \
    "Services" \
    "Ensure DNS Server is not installed" \
    "1" \
    "yes" \
    "The BIND DNS server package allows a system to act as a domain name resolver for the network. DNS servers are high-value targets frequently exploited for cache poisoning and denial of service attacks. Unless the system is a designated DNS server this package should be removed." \
    "apt-get remove -y bind9"

register_control "2.2.8" \
    "Services" \
    "Ensure FTP Server is not installed" \
    "1" \
    "yes" \
    "FTP is an insecure file transfer protocol that transmits credentials and data in cleartext. The vsftpd package or any other FTP server should be removed in favor of secure alternatives like SFTP. Attackers can trivially capture FTP credentials through network sniffing." \
    "apt-get remove -y vsftpd"

register_control "2.2.9" \
    "Services" \
    "Ensure HTTP Server is not installed" \
    "1" \
    "yes" \
    "Web server packages such as Apache or nginx should not be installed unless the system is a designated web server. Web servers present a large attack surface with complex configurations that are frequently misconfigured. Removing unused web servers eliminates a major category of potential remote exploitation." \
    "apt-get remove -y apache2 nginx"

register_control "2.2.10" \
    "Services" \
    "Ensure IMAP and POP3 server is not installed" \
    "1" \
    "yes" \
    "IMAP and POP3 servers like Dovecot provide email retrieval services for mail clients. Unless the system is a designated mail server these services needlessly expand the attack surface. Mail servers handle sensitive communications and require dedicated security hardening if needed." \
    "apt-get remove -y dovecot-imapd dovecot-pop3d"

register_control "2.2.11" \
    "Services" \
    "Ensure Samba is not installed" \
    "1" \
    "yes" \
    "Samba provides Windows-compatible file and print sharing services using the SMB/CIFS protocol. Unless the system must share resources with Windows clients Samba should be removed. The SMB protocol has been the target of numerous critical vulnerabilities including the WannaCry ransomware exploit." \
    "apt-get remove -y samba"

register_control "2.2.12" \
    "Services" \
    "Ensure HTTP Proxy Server is not installed" \
    "1" \
    "yes" \
    "HTTP proxy servers like Squid allow a system to act as an intermediary for web requests. Unless the system is a designated proxy this service increases the attack surface and could be abused for traffic interception. Proxy servers can be leveraged to bypass network security controls if misconfigured." \
    "apt-get remove -y squid"

register_control "2.2.13" \
    "Services" \
    "Ensure SNMP Server is not installed" \
    "1" \
    "yes" \
    "SNMP provides network management and monitoring capabilities but older versions transmit community strings in cleartext. The SNMP server should be removed unless it is specifically needed for network monitoring infrastructure. Attackers can exploit SNMP to gather detailed system information or modify device configurations." \
    "apt-get remove -y snmpd"

register_control "2.2.14" \
    "Services" \
    "Ensure NIS Server is not installed" \
    "1" \
    "yes" \
    "The Network Information Service is a legacy client-server directory service for distributing system configuration data. NIS transmits all data including password hashes unencrypted over the network. Modern systems should use LDAP with TLS or other encrypted directory services instead of NIS." \
    "apt-get remove -y nis"

register_control "2.2.15" \
    "Services" \
    "Ensure mail transfer agent is configured for local-only mode" \
    "1" \
    "yes" \
    "Mail Transfer Agents like Postfix or Exim handle email delivery and may listen on network port 25. Unless the system is a designated mail relay the MTA should only accept connections from localhost. Configuring local-only mode prevents the system from being used as an open relay for spam or phishing attacks." \
    "sed -i 's/^inet_interfaces.*/inet_interfaces = loopback-only/' /etc/postfix/main.cf && systemctl restart postfix"

register_control "2.2.16" \
    "Services" \
    "Ensure rsync service is not installed" \
    "1" \
    "yes" \
    "The rsync service provides fast file synchronization over the network and can run as a daemon on port 873. Unless specifically required for system administration rsync should be removed to reduce exposure. An improperly configured rsync daemon can expose sensitive files to unauthorized network access." \
    "apt-get remove -y rsync"

register_control "3.1.1" \
    "Network Configuration" \
    "Ensure IP forwarding is disabled" \
    "1" \
    "yes" \
    "IP forwarding allows the system to route packets between network interfaces acting as a router. Unless the system is specifically designed as a router or gateway IP forwarding must be disabled. An attacker could exploit IP forwarding to redirect network traffic through a compromised system for interception." \
    "sysctl -w net.ipv4.ip_forward=0 && echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/99-cisaudit.conf"

register_control "3.1.2" \
    "Network Configuration" \
    "Ensure packet redirect sending is disabled" \
    "1" \
    "yes" \
    "ICMP redirect messages inform hosts of more efficient routes and should only be sent by routers. A non-router system sending redirects could be exploited to manipulate routing tables on neighboring hosts. Disabling send_redirects prevents the system from being used in route manipulation attacks." \
    "sysctl -w net.ipv4.conf.all.send_redirects=0 && sysctl -w net.ipv4.conf.default.send_redirects=0 && echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.d/99-cisaudit.conf && echo 'net.ipv4.conf.default.send_redirects = 0' >> /etc/sysctl.d/99-cisaudit.conf"

register_control "3.1.3" \
    "Network Configuration" \
    "Ensure source routed packets are not accepted" \
    "1" \
    "yes" \
    "Source routed packets allow the sender to specify the route through the network bypassing normal routing decisions. Attackers use source routing to direct traffic through compromised systems for eavesdropping or to bypass firewall rules. Disabling acceptance of source routed packets forces all traffic to follow the normal routing path." \
    "sysctl -w net.ipv4.conf.all.accept_source_route=0 && sysctl -w net.ipv4.conf.default.accept_source_route=0 && echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.d/99-cisaudit.conf && echo 'net.ipv4.conf.default.accept_source_route = 0' >> /etc/sysctl.d/99-cisaudit.conf"

register_control "3.1.4" \
    "Network Configuration" \
    "Ensure ICMP redirects are not accepted" \
    "1" \
    "yes" \
    "ICMP redirect messages can alter the routing table of a host directing traffic to a different gateway. Attackers can send forged ICMP redirects to perform man-in-the-middle attacks by rerouting traffic through a malicious host. Disabling ICMP redirect acceptance prevents these routing table manipulation attacks." \
    "sysctl -w net.ipv4.conf.all.accept_redirects=0 && sysctl -w net.ipv4.conf.default.accept_redirects=0 && echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.d/99-cisaudit.conf && echo 'net.ipv4.conf.default.accept_redirects = 0' >> /etc/sysctl.d/99-cisaudit.conf"

register_control "3.2.1" \
    "Network Configuration" \
    "Ensure suspicious packets are logged" \
    "1" \
    "yes" \
    "Logging martian packets records instances where the system receives packets with impossible source addresses. These packets often indicate spoofing attempts, misconfigured systems, or ongoing attacks. Enabling log_martians provides valuable forensic data for security incident investigation." \
    "sysctl -w net.ipv4.conf.all.log_martians=1 && sysctl -w net.ipv4.conf.default.log_martians=1 && echo 'net.ipv4.conf.all.log_martians = 1' >> /etc/sysctl.d/99-cisaudit.conf && echo 'net.ipv4.conf.default.log_martians = 1' >> /etc/sysctl.d/99-cisaudit.conf"

register_control "3.2.2" \
    "Network Configuration" \
    "Ensure broadcast ICMP requests are ignored" \
    "1" \
    "yes" \
    "Broadcast ICMP echo requests can be used in Smurf amplification attacks where an attacker sends pings to a broadcast address causing all hosts to respond. Ignoring broadcast ICMP requests prevents the system from participating in these amplification attacks. This is a fundamental network hardening measure against denial of service." \
    "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 && echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' >> /etc/sysctl.d/99-cisaudit.conf"

register_control "3.2.3" \
    "Network Configuration" \
    "Ensure bogus ICMP responses are ignored" \
    "1" \
    "yes" \
    "Some routers send bogus ICMP error responses that violate RFC standards and can fill up log files. Ignoring these bogus responses prevents unnecessary log noise and potential log-based denial of service. This setting reduces the impact of malformed ICMP traffic on system stability." \
    "sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 && echo 'net.ipv4.icmp_ignore_bogus_error_responses = 1' >> /etc/sysctl.d/99-cisaudit.conf"

register_control "3.2.4" \
    "Network Configuration" \
    "Ensure Reverse Path Filtering is enabled" \
    "1" \
    "yes" \
    "Reverse Path Filtering validates that incoming packets arrive on the interface that would be used to reach the source address. This prevents IP spoofing by dropping packets whose source address does not match the expected routing path. Enabling strict mode (value 1) provides the strongest anti-spoofing protection." \
    "sysctl -w net.ipv4.conf.all.rp_filter=1 && sysctl -w net.ipv4.conf.default.rp_filter=1 && echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/sysctl.d/99-cisaudit.conf && echo 'net.ipv4.conf.default.rp_filter = 1' >> /etc/sysctl.d/99-cisaudit.conf"

register_control "3.2.5" \
    "Network Configuration" \
    "Ensure TCP SYN Cookies is enabled" \
    "1" \
    "yes" \
    "TCP SYN Cookies protect against SYN flood attacks by encoding connection state in the sequence number instead of allocating memory for half-open connections. When the SYN queue is full the kernel uses cryptographic cookies to validate legitimate connections. This is an essential defense against one of the most common denial of service attack vectors." \
    "sysctl -w net.ipv4.tcp_syncookies=1 && echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.d/99-cisaudit.conf"

register_control "3.2.6" \
    "Network Configuration" \
    "Ensure IPv6 router advertisements are not accepted" \
    "1" \
    "yes" \
    "IPv6 router advertisements allow routers to automatically configure IPv6 addresses and routing on hosts. Accepting rogue router advertisements could allow an attacker to redirect IPv6 traffic or perform man-in-the-middle attacks. Disabling acceptance of router advertisements prevents unauthorized network reconfiguration via IPv6." \
    "sysctl -w net.ipv6.conf.all.accept_ra=0 && sysctl -w net.ipv6.conf.default.accept_ra=0 && echo 'net.ipv6.conf.all.accept_ra = 0' >> /etc/sysctl.d/99-cisaudit.conf && echo 'net.ipv6.conf.default.accept_ra = 0' >> /etc/sysctl.d/99-cisaudit.conf"

register_control "3.3.1" \
    "Network Configuration" \
    "Ensure iptables is installed" \
    "1" \
    "yes" \
    "Iptables provides host-based firewall functionality that is essential for controlling network traffic to and from the system. Without a firewall all network services are exposed to the network without any filtering. Installing iptables is the prerequisite for implementing any host-based firewall policy." \
    "apt-get install -y iptables"

register_control "3.3.2" \
    "Network Configuration" \
    "Ensure default deny firewall policy for INPUT" \
    "1" \
    "yes" \
    "A default deny policy for the INPUT chain drops all incoming packets that do not match an explicit allow rule. This ensures that only specifically authorized traffic can reach the system. Without a default deny policy any traffic not explicitly blocked will be accepted." \
    "iptables -P INPUT DROP"

register_control "3.3.3" \
    "Network Configuration" \
    "Ensure default deny firewall policy for FORWARD" \
    "1" \
    "yes" \
    "A default deny policy for the FORWARD chain prevents the system from routing traffic between interfaces unless explicitly permitted. This is critical for systems with multiple network interfaces to prevent unauthorized traffic forwarding. Even on single-interface systems this policy provides defense in depth." \
    "iptables -P FORWARD DROP"

register_control "3.3.4" \
    "Network Configuration" \
    "Ensure default deny firewall policy for OUTPUT" \
    "1" \
    "yes" \
    "A default deny policy for the OUTPUT chain blocks all outgoing packets that do not match an explicit allow rule. This restricts what traffic the system can send preventing compromised services from establishing outbound connections. Outbound filtering is essential for detecting and containing breaches." \
    "iptables -P OUTPUT DROP"

register_control "3.3.5" \
    "Network Configuration" \
    "Ensure firewall rules exist for all open ports" \
    "1" \
    "yes" \
    "Every listening network port should have a corresponding firewall rule that explicitly allows or denies access. Ports without firewall rules rely solely on the default policy which may change over time. Explicit rules provide documentation of intended network access and ensure consistent security posture." \
    "iptables -L INPUT -v -n"

register_control "3.4.1" \
    "Network Configuration" \
    "Ensure wireless interfaces are disabled" \
    "1" \
    "no" \
    "Wireless interfaces provide an additional attack vector through which unauthorized users can access the network. Server systems rarely need wireless connectivity and should use wired connections for reliability and security. Disabling wireless interfaces prevents rogue access point attacks and unauthorized wireless connections." \
    "ip link set wlan0 down && echo 'blacklist cfg80211' >> /etc/modprobe.d/wireless.conf"

register_control "3.4.2" \
    "Network Configuration" \
    "Ensure DCCP is disabled" \
    "2" \
    "yes" \
    "The Datagram Congestion Control Protocol is a transport protocol that is rarely used on production systems. Disabling DCCP reduces the kernel attack surface by removing an unnecessary protocol handler. Vulnerabilities in rarely audited protocol implementations can provide exploitation opportunities." \
    "echo 'install dccp /bin/true' >> /etc/modprobe.d/dccp.conf && echo 'blacklist dccp' >> /etc/modprobe.d/dccp.conf"

register_control "3.4.3" \
    "Network Configuration" \
    "Ensure SCTP is disabled" \
    "2" \
    "yes" \
    "The Stream Control Transmission Protocol is a transport protocol primarily used in telecommunications. Unless specifically required SCTP should be disabled to minimize the kernel attack surface. Reducing the number of loaded protocol modules limits the potential for kernel-level exploitation." \
    "echo 'install sctp /bin/true' >> /etc/modprobe.d/sctp.conf && echo 'blacklist sctp' >> /etc/modprobe.d/sctp.conf"

register_control "3.4.4" \
    "Network Configuration" \
    "Ensure RDS is disabled" \
    "2" \
    "yes" \
    "The Reliable Datagram Sockets protocol is a transport protocol developed by Oracle for high-performance cluster communication. RDS is not needed on most systems and has had critical kernel vulnerabilities in the past. Disabling RDS eliminates a protocol module with a history of security issues." \
    "echo 'install rds /bin/true' >> /etc/modprobe.d/rds.conf && echo 'blacklist rds' >> /etc/modprobe.d/rds.conf"

register_control "3.4.5" \
    "Network Configuration" \
    "Ensure TIPC is disabled" \
    "2" \
    "yes" \
    "The Transparent Inter-Process Communication protocol is a cluster communication protocol designed for intra-cluster messaging. TIPC is unnecessary on systems that are not part of a TIPC-based cluster. Disabling this module reduces kernel attack surface by removing an uncommon network protocol handler." \
    "echo 'install tipc /bin/true' >> /etc/modprobe.d/tipc.conf && echo 'blacklist tipc' >> /etc/modprobe.d/tipc.conf"

register_control "4.1.1" \
    "Logging and Auditing" \
    "Ensure auditd is installed" \
    "2" \
    "yes" \
    "The Linux Audit daemon provides detailed system call auditing and security event logging. Auditd is essential for forensic analysis, compliance monitoring, and detecting unauthorized access attempts. Without auditd the system lacks the ability to record detailed security-relevant events." \
    "apt-get install -y auditd audispd-plugins"

register_control "4.1.2" \
    "Logging and Auditing" \
    "Ensure auditd service is enabled" \
    "2" \
    "yes" \
    "The auditd service must be enabled to start automatically at boot to ensure continuous security event logging. A gap in audit logging between boot and manual service start could allow attackers to operate undetected. Enabling the service guarantees audit coverage from the earliest possible point in the boot process." \
    "systemctl enable auditd"

register_control "4.1.3" \
    "Logging and Auditing" \
    "Ensure auditing for processes that start prior to auditd is enabled" \
    "2" \
    "yes" \
    "Some processes start before the auditd service is running and their activity would not be captured by default. Adding audit=1 to the kernel boot parameters ensures the kernel begins auditing from the earliest stages of boot. This closes the window where malicious activity could occur before the audit daemon starts." \
    "sed -i 's/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"audit=1 /' /etc/default/grub && update-grub"

register_control "4.1.4" \
    "Logging and Auditing" \
    "Ensure audit_backlog_limit is sufficient" \
    "2" \
    "yes" \
    "The audit_backlog_limit parameter sets the maximum number of audit records that can be queued before the kernel begins dropping events. An insufficient backlog limit can cause audit events to be lost during periods of high system activity. Setting this to at least 8192 ensures adequate buffer space for burst audit activity." \
    "sed -i 's/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"audit_backlog_limit=8192 /' /etc/default/grub && update-grub"

register_control "4.1.5" \
    "Logging and Auditing" \
    "Ensure events that modify date and time information are collected" \
    "2" \
    "yes" \
    "Monitoring changes to the system clock is critical because attackers often modify timestamps to cover their tracks. Audit rules should capture all calls to adjtimex, settimeofday, stime, and clock_settime as well as changes to /etc/localtime. Time modification events are essential for maintaining the integrity of audit log timelines." \
    "echo '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change' >> /etc/audit/rules.d/cisaudit.rules && echo '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' >> /etc/audit/rules.d/cisaudit.rules && echo '-w /etc/localtime -p wa -k time-change' >> /etc/audit/rules.d/cisaudit.rules"

register_control "4.1.6" \
    "Logging and Auditing" \
    "Ensure events that modify user/group information are collected" \
    "2" \
    "yes" \
    "Changes to user and group files such as /etc/passwd, /etc/shadow, /etc/group, and /etc/gshadow must be monitored. Unauthorized modifications to these files could indicate an attacker creating backdoor accounts or escalating privileges. Audit rules on identity files provide early detection of account manipulation." \
    "echo '-w /etc/group -p wa -k identity' >> /etc/audit/rules.d/cisaudit.rules && echo '-w /etc/passwd -p wa -k identity' >> /etc/audit/rules.d/cisaudit.rules && echo '-w /etc/gshadow -p wa -k identity' >> /etc/audit/rules.d/cisaudit.rules && echo '-w /etc/shadow -p wa -k identity' >> /etc/audit/rules.d/cisaudit.rules"

register_control "4.1.7" \
    "Logging and Auditing" \
    "Ensure events that modify the system network environment are collected" \
    "2" \
    "yes" \
    "Network configuration changes including modifications to /etc/hosts, /etc/hostname, and sethostname system calls should be audited. Unauthorized network configuration changes could redirect traffic or hide malicious activity. Monitoring these events helps detect network-based attacks and unauthorized system reconfiguration." \
    "echo '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale' >> /etc/audit/rules.d/cisaudit.rules && echo '-w /etc/issue -p wa -k system-locale' >> /etc/audit/rules.d/cisaudit.rules && echo '-w /etc/hosts -p wa -k system-locale' >> /etc/audit/rules.d/cisaudit.rules && echo '-w /etc/hostname -p wa -k system-locale' >> /etc/audit/rules.d/cisaudit.rules"

register_control "4.1.8" \
    "Logging and Auditing" \
    "Ensure events that modify the system MAC policy are collected" \
    "2" \
    "yes" \
    "Mandatory Access Control policies defined by AppArmor or SELinux provide an additional layer of access restrictions beyond standard permissions. Changes to MAC policies could weaken security controls or disable protection for critical services. Auditing modifications to /etc/apparmor/ and /etc/selinux/ detects unauthorized policy weakening." \
    "echo '-w /etc/apparmor/ -p wa -k MAC-policy' >> /etc/audit/rules.d/cisaudit.rules && echo '-w /etc/apparmor.d/ -p wa -k MAC-policy' >> /etc/audit/rules.d/cisaudit.rules"

register_control "4.1.9" \
    "Logging and Auditing" \
    "Ensure login and logout events are collected" \
    "2" \
    "yes" \
    "Login and logout events recorded in /var/log/faillog, /var/log/lastlog, and /var/log/tallylog provide critical authentication audit trails. Monitoring these files helps detect brute force attacks, unauthorized access, and anomalous login patterns. These records are essential for security incident investigation and compliance reporting." \
    "echo '-w /var/log/faillog -p wa -k logins' >> /etc/audit/rules.d/cisaudit.rules && echo '-w /var/log/lastlog -p wa -k logins' >> /etc/audit/rules.d/cisaudit.rules && echo '-w /var/log/tallylog -p wa -k logins' >> /etc/audit/rules.d/cisaudit.rules"

register_control "4.1.10" \
    "Logging and Auditing" \
    "Ensure session initiation information is collected" \
    "2" \
    "yes" \
    "Session initiation files such as /var/run/utmp, /var/log/wtmp, and /var/log/btmp track active sessions and login history. Monitoring these files provides visibility into who is logged in and historical session data. Unauthorized modifications to session tracking files could indicate an attacker attempting to hide their presence." \
    "echo '-w /var/run/utmp -p wa -k session' >> /etc/audit/rules.d/cisaudit.rules && echo '-w /var/log/wtmp -p wa -k logins' >> /etc/audit/rules.d/cisaudit.rules && echo '-w /var/log/btmp -p wa -k logins' >> /etc/audit/rules.d/cisaudit.rules"

register_control "4.1.11" \
    "Logging and Auditing" \
    "Ensure discretionary access control permission modification events are collected" \
    "2" \
    "yes" \
    "DAC permission changes via chmod, fchmod, chown, fchown, lchown, setxattr, and similar system calls should be audited. Unauthorized permission changes could grant attackers access to sensitive files or enable privilege escalation. Collecting these events provides a complete record of who changed permissions on which files." \
    "echo '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod' >> /etc/audit/rules.d/cisaudit.rules && echo '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k perm_mod' >> /etc/audit/rules.d/cisaudit.rules"

register_control "4.1.12" \
    "Logging and Auditing" \
    "Ensure unsuccessful unauthorized file access attempts are collected" \
    "2" \
    "yes" \
    "Failed file access attempts where the system returns EACCES or EPERM indicate either misconfigured applications or potential attack activity. Monitoring these failures helps detect unauthorized users attempting to access files beyond their permission level. Patterns of access failures often precede successful exploitation." \
    "echo '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access' >> /etc/audit/rules.d/cisaudit.rules && echo '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access' >> /etc/audit/rules.d/cisaudit.rules"

register_control "4.1.13" \
    "Logging and Auditing" \
    "Ensure successful file system mounts are collected" \
    "2" \
    "yes" \
    "Monitoring the mount system call detects when users mount filesystems which could be used to introduce unauthorized media or access hidden data. Successful mounts by non-privileged users are particularly suspicious and should be investigated. This audit rule captures all mount operations along with the user identity for forensic analysis." \
    "echo '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts' >> /etc/audit/rules.d/cisaudit.rules && echo '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts' >> /etc/audit/rules.d/cisaudit.rules"

register_control "4.1.14" \
    "Logging and Auditing" \
    "Ensure file deletion events by users are collected" \
    "2" \
    "yes" \
    "Monitoring file deletion system calls such as unlink, unlinkat, rename, and renameat detects when users delete or overwrite files. Attackers often delete log files and other evidence after compromising a system. Collecting file deletion events ensures that evidence destruction attempts are themselves recorded in the audit log." \
    "echo '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete' >> /etc/audit/rules.d/cisaudit.rules && echo '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete' >> /etc/audit/rules.d/cisaudit.rules"

register_control "4.2.1" \
    "Logging and Auditing" \
    "Ensure rsyslog is installed" \
    "1" \
    "yes" \
    "Rsyslog is the standard system logging facility that collects messages from services, the kernel, and applications. Without rsyslog critical system events including security warnings and errors go unrecorded. Installing rsyslog is the foundation for all system-level log collection and analysis." \
    "apt-get install -y rsyslog"

register_control "4.2.2" \
    "Logging and Auditing" \
    "Ensure rsyslog service is enabled" \
    "1" \
    "yes" \
    "The rsyslog service must be enabled to start automatically at boot to ensure continuous logging coverage. A system without active logging cannot detect or record security incidents, hardware failures, or application errors. Enabling rsyslog ensures log collection begins immediately at system startup." \
    "systemctl enable rsyslog"

register_control "4.2.3" \
    "Logging and Auditing" \
    "Ensure rsyslog default file permissions configured" \
    "1" \
    "yes" \
    "Log files should be created with restrictive permissions to prevent unauthorized users from reading sensitive log data. The FileCreateMode setting in rsyslog controls the default permissions applied to newly created log files. Setting this to 0640 ensures only root and the syslog group can access log contents." \
    "echo '\$FileCreateMode 0640' >> /etc/rsyslog.conf && systemctl restart rsyslog"

register_control "4.2.4" \
    "Logging and Auditing" \
    "Ensure logging is configured" \
    "1" \
    "no" \
    "System logging should be configured to capture relevant events from all critical services and facilities. The rsyslog configuration should direct logs to appropriate files based on facility and severity. Proper logging configuration ensures that security events are recorded and available for review and incident response." \
    "vi /etc/rsyslog.conf"

register_control "5.1.1" \
    "Access, Authentication and Authorization" \
    "Ensure cron daemon is enabled and running" \
    "1" \
    "yes" \
    "The cron daemon executes scheduled commands and is essential for automated system maintenance tasks including log rotation and security updates. If cron is disabled scheduled security tasks such as ClamAV scans and AIDE integrity checks will not run. Ensuring cron is enabled maintains the automated security posture of the system." \
    "systemctl enable cron && systemctl start cron"

register_control "5.1.2" \
    "Access, Authentication and Authorization" \
    "Ensure permissions on /etc/crontab are configured" \
    "1" \
    "yes" \
    "The /etc/crontab file contains system-wide cron job definitions that run with elevated privileges. Improper permissions on this file could allow unauthorized users to schedule malicious commands as root. Restricting access to root only prevents privilege escalation through crontab manipulation." \
    "chown root:root /etc/crontab && chmod 600 /etc/crontab"

register_control "5.1.3" \
    "Access, Authentication and Authorization" \
    "Ensure permissions on /etc/cron.hourly are configured" \
    "1" \
    "yes" \
    "The /etc/cron.hourly directory contains scripts that execute every hour with root privileges. Unrestricted access to this directory would allow any user to place malicious scripts that run as root. Setting restrictive permissions ensures only authorized administrators can manage hourly cron jobs." \
    "chown root:root /etc/cron.hourly && chmod 700 /etc/cron.hourly"

register_control "5.1.4" \
    "Access, Authentication and Authorization" \
    "Ensure permissions on /etc/cron.daily are configured" \
    "1" \
    "yes" \
    "The /etc/cron.daily directory contains scripts that execute daily with root privileges including log rotation and package updates. Unauthorized access could allow attackers to insert persistent backdoors that execute once per day. Restricting this directory to root prevents privilege escalation through daily cron job manipulation." \
    "chown root:root /etc/cron.daily && chmod 700 /etc/cron.daily"

register_control "5.2.1" \
    "Access, Authentication and Authorization" \
    "Ensure permissions on /etc/ssh/sshd_config are configured" \
    "1" \
    "yes" \
    "The sshd_config file controls the behavior of the SSH daemon including authentication methods and access restrictions. If this file is writable by unauthorized users an attacker could weaken SSH security settings to facilitate access. Restricting permissions ensures only root can view or modify the SSH server configuration." \
    "chown root:root /etc/ssh/sshd_config && chmod 600 /etc/ssh/sshd_config"

register_control "5.2.2" \
    "Access, Authentication and Authorization" \
    "Ensure SSH access is limited" \
    "1" \
    "yes" \
    "SSH access should be restricted to specific users or groups using AllowUsers, AllowGroups, DenyUsers, or DenyGroups directives. Without explicit access controls any valid user account can authenticate via SSH potentially including service accounts. Limiting SSH access reduces the number of accounts that can be targeted for remote brute force attacks." \
    "sed -i 's/^#*AllowUsers.*/AllowUsers root/' /etc/ssh/sshd_config && systemctl restart sshd"

register_control "5.2.3" \
    "Access, Authentication and Authorization" \
    "Ensure permissions on SSH private host key files are configured" \
    "1" \
    "yes" \
    "SSH private host key files must be protected from unauthorized access as they authenticate the server to clients. Compromised host keys allow attackers to impersonate the server and perform man-in-the-middle attacks. These files should be owned by root with permissions set to 600 to prevent any non-root access." \
    "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \\; -exec chmod 600 {} \\;"

register_control "5.2.4" \
    "Access, Authentication and Authorization" \
    "Ensure SSH LogLevel is appropriate" \
    "1" \
    "yes" \
    "SSH LogLevel controls the verbosity of the SSH daemon logging and should be set to INFO or VERBOSE for adequate security monitoring. Insufficient logging prevents detection of brute force attacks and unauthorized access attempts. The INFO level provides a balance between useful security data and log volume." \
    "sed -i 's/^#*LogLevel.*/LogLevel INFO/' /etc/ssh/sshd_config && systemctl restart sshd"

register_control "5.2.5" \
    "Access, Authentication and Authorization" \
    "Ensure SSH X11 forwarding is disabled" \
    "2" \
    "yes" \
    "X11 forwarding allows graphical applications to be tunneled over SSH which introduces security risks from the X11 protocol. The X11 protocol was not designed with security in mind and forwarding can expose the local X server to attacks from the remote system. Disabling X11 forwarding eliminates this attack vector on servers that do not need graphical application support." \
    "sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config && systemctl restart sshd"

register_control "5.2.6" \
    "Access, Authentication and Authorization" \
    "Ensure SSH MaxAuthTries is set to 4 or less" \
    "1" \
    "yes" \
    "MaxAuthTries limits the number of authentication attempts permitted per SSH connection. Setting this to 4 or less slows down brute force attacks by forcing the attacker to establish new connections frequently. A lower value combined with fail2ban provides effective protection against automated password guessing." \
    "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config && systemctl restart sshd"

register_control "5.2.7" \
    "Access, Authentication and Authorization" \
    "Ensure SSH IgnoreRhosts is enabled" \
    "1" \
    "yes" \
    "The IgnoreRhosts parameter prevents SSH from using the legacy .rhosts and .shosts files for host-based authentication. These files allow authentication without passwords based solely on the source hostname which can be trivially spoofed. Enabling IgnoreRhosts forces proper cryptographic authentication for all SSH sessions." \
    "sed -i 's/^#*IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config && systemctl restart sshd"

register_control "5.2.8" \
    "Access, Authentication and Authorization" \
    "Ensure SSH root login is disabled" \
    "1" \
    "yes" \
    "Allowing direct root login via SSH provides attackers with a known username to target for brute force attacks. Disabling root login forces administrators to authenticate with personal accounts before using sudo for privilege escalation. This improves accountability by ensuring all administrative actions are traceable to individual users." \
    "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd"

register_control "5.2.9" \
    "Access, Authentication and Authorization" \
    "Ensure SSH PermitEmptyPasswords is disabled" \
    "1" \
    "yes" \
    "The PermitEmptyPasswords parameter controls whether accounts with empty passwords can authenticate via SSH. Allowing empty passwords completely undermines authentication security and gives attackers trivial access. This must be disabled to ensure all SSH connections require proper credential verification." \
    "sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config && systemctl restart sshd"

register_control "5.2.10" \
    "Access, Authentication and Authorization" \
    "Ensure SSH PermitUserEnvironment is disabled" \
    "1" \
    "yes" \
    "The PermitUserEnvironment option allows users to set environment variables that could modify the behavior of SSH sessions. Attackers can use this to set LD_PRELOAD or PATH variables to load malicious libraries or override system commands. Disabling this option prevents environment-based attacks through SSH sessions." \
    "sed -i 's/^#*PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config && systemctl restart sshd"

register_control "5.2.11" \
    "Access, Authentication and Authorization" \
    "Ensure only strong ciphers are used" \
    "1" \
    "yes" \
    "SSH cipher configuration determines the encryption algorithms used to protect session confidentiality. Weak ciphers such as 3des-cbc, arcfour, and blowfish can be broken with modern computing resources. Restricting SSH to strong ciphers like chacha20-poly1305 and aes256-gcm ensures session data remains protected." \
    "sed -i 's/^#*Ciphers.*/Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr/' /etc/ssh/sshd_config && systemctl restart sshd"

register_control "5.2.12" \
    "Access, Authentication and Authorization" \
    "Ensure only strong MAC algorithms are used" \
    "1" \
    "yes" \
    "Message Authentication Code algorithms ensure the integrity of SSH traffic by detecting tampering. Weak MAC algorithms such as hmac-md5 and hmac-sha1 are vulnerable to collision attacks that could allow traffic modification. Configuring only strong MACs like hmac-sha2-512-etm ensures reliable integrity verification of all SSH communications." \
    "sed -i 's/^#*MACs.*/MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256/' /etc/ssh/sshd_config && systemctl restart sshd"

register_control "5.2.13" \
    "Access, Authentication and Authorization" \
    "Ensure only strong Key Exchange algorithms are used" \
    "1" \
    "yes" \
    "Key Exchange algorithms negotiate the shared secret used to derive session encryption keys. Weak key exchange methods like diffie-hellman-group1-sha1 use small key sizes vulnerable to offline attacks. Restricting to curve25519-sha256 and strong diffie-hellman groups ensures the key exchange cannot be compromised." \
    "sed -i 's/^#*KexAlgorithms.*/KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512/' /etc/ssh/sshd_config && systemctl restart sshd"

register_control "5.2.14" \
    "Access, Authentication and Authorization" \
    "Ensure SSH LoginGraceTime is set to one minute or less" \
    "1" \
    "yes" \
    "LoginGraceTime sets the maximum time allowed for a user to complete authentication after connecting to SSH. A long grace time allows attackers to hold open unauthenticated connections consuming server resources. Setting this to 60 seconds or less limits the window for brute force attacks and reduces resource consumption from idle connections." \
    "sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config && systemctl restart sshd"

register_control "5.3.1" \
    "Access, Authentication and Authorization" \
    "Ensure password creation requirements are configured" \
    "1" \
    "yes" \
    "Password quality modules like pam_pwquality enforce minimum complexity requirements for user passwords. Without these requirements users can set trivially guessable passwords that are vulnerable to brute force and dictionary attacks. The 2019 Collection #1 breach exposed 773 million credentials many of which used weak passwords that complexity rules would have prevented." \
    "apt-get install -y libpam-pwquality && echo 'password requisite pam_pwquality.so retry=3' >> /etc/pam.d/common-password"

register_control "5.4.1" \
    "Access, Authentication and Authorization" \
    "Ensure password expiration is 365 days or less" \
    "1" \
    "yes" \
    "PASS_MAX_DAYS in /etc/login.defs sets the maximum number of days a password may be used before it must be changed. Requiring periodic password changes limits the window during which a compromised password can be exploited. The NIST 800-63B guidelines recommend expiration only when compromise is suspected but CIS maintains this control for defense in depth." \
    "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs"

register_control "5.4.2" \
    "Access, Authentication and Authorization" \
    "Ensure minimum days between password changes is configured" \
    "1" \
    "yes" \
    "PASS_MIN_DAYS prevents users from immediately changing passwords back to a previous value after a forced change. Without a minimum interval users can cycle through password history to reuse a compromised password. Setting this to at least 1 day forces meaningful password rotation." \
    "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs"

register_control "5.4.3" \
    "Access, Authentication and Authorization" \
    "Ensure password expiration warning days is 7 or more" \
    "1" \
    "yes" \
    "PASS_WARN_AGE controls how many days before password expiration the user receives a warning. Adequate warning prevents account lockouts caused by expired passwords which can disrupt operations and trigger helpdesk overhead. Seven days provides sufficient notice for users to change their password before expiration." \
    "sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs"

register_control "5.5.1" \
    "Access, Authentication and Authorization" \
    "Ensure account lockout for failed password attempts is configured" \
    "1" \
    "yes" \
    "Account lockout after failed authentication attempts prevents brute force password attacks against local and remote accounts. The pam_faillock module tracks failed attempts and temporarily locks accounts after a configurable threshold. Without lockout an attacker can attempt unlimited password guesses against any account on the system." \
    "echo 'auth required pam_faillock.so preauth' >> /etc/pam.d/common-auth && echo 'auth required pam_faillock.so authfail' >> /etc/pam.d/common-auth"

register_control "6.1.1" \
    "System Maintenance" \
    "Ensure permissions on /etc/passwd are configured" \
    "1" \
    "yes" \
    "The /etc/passwd file contains user account information that all users and many system processes need to read. This file must be owned by root with permissions set to 644 to allow read access while preventing unauthorized modifications. Incorrect permissions on /etc/passwd could allow attackers to add accounts or modify existing ones." \
    "chown root:root /etc/passwd && chmod 644 /etc/passwd"

register_control "6.1.2" \
    "System Maintenance" \
    "Ensure permissions on /etc/shadow are configured" \
    "1" \
    "yes" \
    "The /etc/shadow file stores hashed passwords and must have the most restrictive permissions possible. This file should be owned by root with group shadow and permissions set to 640 to prevent unauthorized password hash access. Exposed password hashes can be cracked offline giving attackers valid credentials." \
    "chown root:shadow /etc/shadow && chmod 640 /etc/shadow"

register_control "6.1.3" \
    "System Maintenance" \
    "Ensure permissions on /etc/group are configured" \
    "1" \
    "yes" \
    "The /etc/group file defines group membership information used for access control decisions across the system. This file must be owned by root with 644 permissions to allow read access while preventing unauthorized group modifications. Tampering with group membership could grant attackers access to resources protected by group permissions." \
    "chown root:root /etc/group && chmod 644 /etc/group"

register_control "6.1.4" \
    "System Maintenance" \
    "Ensure permissions on /etc/gshadow are configured" \
    "1" \
    "yes" \
    "The /etc/gshadow file contains encrypted group passwords and group administrator information. This file should be owned by root with group shadow and permissions set to 640 similar to /etc/shadow. Unauthorized access to gshadow could reveal group passwords enabling lateral movement within the system." \
    "chown root:shadow /etc/gshadow && chmod 640 /etc/gshadow"

register_control "6.1.5" \
    "System Maintenance" \
    "Ensure permissions on /etc/passwd- are configured" \
    "1" \
    "yes" \
    "The /etc/passwd- file is a backup copy of /etc/passwd created automatically by system utilities. This backup file must have the same restrictive permissions as the original to prevent information leakage. Attackers could read an improperly secured backup to enumerate system users and their properties." \
    "chown root:root /etc/passwd- && chmod 644 /etc/passwd-"

register_control "6.2.1" \
    "System Maintenance" \
    "Ensure no duplicate UIDs exist" \
    "1" \
    "yes" \
    "Each user account must have a unique User ID to ensure proper access control and audit trail attribution. Duplicate UIDs cause multiple users to share the same file permissions and appear identical in log files. Resolving duplicate UIDs ensures that every action on the system can be traced to a specific user account." \
    "cat /etc/passwd | cut -f3 -d: | sort -n | uniq -d"

register_control "6.2.2" \
    "System Maintenance" \
    "Ensure no duplicate GIDs exist" \
    "1" \
    "yes" \
    "Each group must have a unique Group ID to ensure correct group-based access control enforcement. Duplicate GIDs cause different group names to share the same access permissions leading to unintended access grants. Eliminating duplicate GIDs ensures that group membership provides the expected level of access." \
    "cat /etc/group | cut -f3 -d: | sort -n | uniq -d"

register_control "6.2.3" \
    "System Maintenance" \
    "Ensure no duplicate user names exist" \
    "1" \
    "yes" \
    "Duplicate user names in /etc/passwd would cause ambiguity in permission assignments and audit logging. Systems may behave unpredictably when multiple entries share the same username potentially granting unintended access. Each user name must be unique to ensure consistent authentication and authorization behavior." \
    "cat /etc/passwd | cut -f1 -d: | sort | uniq -d"

register_control "6.2.4" \
    "System Maintenance" \
    "Ensure root is the only UID 0 account" \
    "1" \
    "yes" \
    "UID 0 grants unrestricted superuser privileges and should only be assigned to the root account. Additional UID 0 accounts create hidden administrator access that bypasses normal sudo-based privilege escalation auditing. Any account other than root with UID 0 should be investigated as a potential backdoor." \
    "awk -F: '(\$3 == 0) { print \$1 }' /etc/passwd"

register_control "6.2.5" \
    "System Maintenance" \
    "Ensure no legacy + entries exist in passwd, shadow, or group" \
    "1" \
    "yes" \
    "Legacy plus entries in /etc/passwd, /etc/shadow, or /etc/group were used with NIS to include external directory data. These entries can introduce security vulnerabilities by importing uncontrolled account or group information. Removing legacy + entries eliminates the risk of unintended account injection from external sources." \
    "sed -i '/^+/d' /etc/passwd /etc/shadow /etc/group"
