<!-- © AngelaMos | 2026 | 01-CONCEPTS.md -->

# Core Security Concepts

This document covers the security fundamentals behind CIS benchmarks, system hardening, and compliance auditing. By the end you should understand why each of the six audit sections exists, what real attacks they prevent, and how the controls map to compliance frameworks you will encounter in production environments. Read time is roughly 20-25 minutes.

---

## CIS Benchmarks

### What They Are

The Center for Internet Security (CIS) publishes hardening guides called benchmarks for operating systems, cloud platforms, databases, and applications. Each benchmark is a PDF document containing hundreds of prescriptive controls, organized into sections, with a title, a rationale, an audit procedure, and a remediation command for every single one.

This project implements the **CIS Debian Linux 12 Benchmark v1.1.0**, which contains 104 controls spread across six sections. Each control is either Level 1 (should be applied to every system) or Level 2 (for high-security environments where the hardening may break some functionality). Each control is also scored (counts toward a compliance percentage) or unscored (advisory only).

The benchmark does not invent new security ideas. It codifies the lessons that security teams learned from decades of breaches, incident response, and penetration testing. When the benchmark says "disable IP forwarding," it is because IP forwarding on a non-router host has been used in countless attacks to pivot traffic between network segments.

### How Levels Work

**Level 1** controls are the baseline. They are intended to be applied to every system without breaking standard functionality. If you deploy a Debian server and apply all Level 1 controls, the system should still function normally as a web server, database server, or application host. Examples: disable unused filesystems, set noexec on /tmp, disable SSH root login.

**Level 2** controls provide deeper hardening but may restrict functionality. Disabling the squashfs filesystem (control 1.1.6) is Level 2 because it breaks snap packages on Ubuntu. Disabling vfat (control 1.1.8) is Level 2 because UEFI systems need vfat for the EFI System Partition. An organization running containers might skip squashfs restrictions. A bare-metal server with legacy BIOS can safely disable vfat.

The level distinction matters in practice. A compliance audit that demands "CIS Level 1" is achievable for nearly every Linux deployment. An audit that demands "CIS Level 2" requires careful evaluation of which controls are safe to apply in your specific environment.

### Scored vs. Unscored

Scored controls count toward the compliance percentage. If you have 80 scored controls and pass 64 of them, your score is 80%. Unscored controls are recommendations that do not affect the score. They are typically controls where the correct configuration depends entirely on the organization's context (like which syslog destination to send logs to).

This project treats all 104 controls as scored by default. The scoring engine in `engine.sh` counts only PASS and FAIL results (not WARN or SKIP) when computing percentages, which matches how CIS scoring guidelines work.

---

## System Hardening

### What It Is

System hardening is the process of reducing a system's attack surface by disabling unnecessary features, restricting permissions, and configuring security controls. A freshly installed operating system is designed for broad compatibility, not security. It ships with dozens of kernel modules loaded, services enabled, and permissive default configurations because the vendor does not know your use case.

Hardening is the opposite of that. You start with the defaults and methodically lock down everything that is not required for the system's specific role.

### Why It Matters

The 2017 Equifax breach exposed 147 million Social Security numbers. The initial attack vector was CVE-2017-5638, an Apache Struts vulnerability. But the breach was catastrophic because of systemic hardening failures. The compromised server had unencrypted credentials stored in configuration files, no network segmentation isolating the web tier from the database tier, and expired SSL certificates on internal monitoring tools, which meant that intrusion detection had been effectively blind for 19 months.

Hardening would not have prevented the Struts vulnerability. But it would have contained the blast radius. If /tmp had noexec set, the attacker's uploaded web shell would not have executed. If the audit subsystem had been enabled, the initial compromise would have generated alerts. If file permissions on sensitive configuration files had been restricted, the attacker would not have found database credentials in plaintext.

The point of hardening is not to make a system invulnerable. It is to make the gap between initial compromise and full breach as wide as possible.

### Defense in Depth

CIS benchmarks implement defense in depth through six layers, each corresponding to a section of the benchmark. No single control stops every attack. But together, they create a system where an attacker has to defeat multiple independent defenses.

```
Layer 6: System Maintenance (file permissions, user accounts)
    ↑ prevents privilege escalation via misconfigurations
Layer 5: Access Controls (cron, SSH, passwords, PAM)
    ↑ restricts who can authenticate and how
Layer 4: Logging and Auditing (auditd, rsyslog)
    ↑ ensures attacks leave evidence
Layer 3: Network Configuration (sysctl, firewall, protocols)
    ↑ limits lateral movement and network attacks
Layer 2: Services (remove unnecessary daemons)
    ↑ reduces attack surface
Layer 1: Initial Setup (filesystems, bootloader, kernel)
    ↑ hardens the foundation
```

An attacker who compromises a web application on a hardened system faces all six layers. They cannot drop executables in /tmp (Layer 1). They cannot pivot through an unnecessary DHCP or NFS service (Layer 2). They cannot redirect traffic via IP forwarding (Layer 3). Their actions are logged by auditd (Layer 4). They cannot SSH as root (Layer 5). They cannot find a second account with UID 0 (Layer 6).

---

## Section 1: Initial Setup

### Filesystem Hardening

Controls 1.1.1 through 1.1.8 disable kernel modules for filesystems that servers should never need to mount. cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf, and vfat are all filesystems designed for embedded systems, Apple hardware, optical media, or removable devices. A production Linux server has no reason to mount HFS volumes from a Mac.

The risk is not theoretical. CVE-2013-1773 was a buffer overflow in the Linux kernel's VFAT filesystem driver that allowed arbitrary code execution when mounting a crafted FAT filesystem image. CVE-2019-19813 was a use-after-free in the HFS+ filesystem driver. If the kernel module is loaded, any user who can trigger a mount (or trick the kernel into auto-mounting) can exploit these vulnerabilities. Disabling the module eliminates the attack surface entirely.

The check function `_check_module_disabled` in `01_initial_setup.sh` verifies that each module has an `install [module] /bin/true` directive in `/etc/modprobe.d/`, which causes the kernel to silently ignore load requests.

Controls 1.2.1 through 1.2.4 ensure that /tmp is a separate partition with `noexec`, `nosuid`, and `nodev` mount options. The /tmp directory is world-writable, which makes it the first place an attacker drops payloads after gaining initial access. With noexec, those payloads will not execute. With nosuid, setuid binaries placed in /tmp cannot escalate privileges. With nodev, device nodes cannot be created.

### Bootloader Protection

Controls 1.4.1 through 1.4.3 protect the boot process. Without a bootloader password (1.4.1), anyone with physical or console access can modify GRUB boot parameters to boot into single-user mode and reset the root password. Control 1.4.3 verifies that single-user mode requires `sulogin` authentication, which prevents the classic "init=/bin/bash" attack from granting an unauthenticated root shell.

### Kernel Hardening

ASLR (Address Space Layout Randomization, control 1.5.1) randomizes the memory addresses used by system libraries, the stack, and the heap. Without ASLR (`kernel.randomize_va_space = 0`), an attacker who finds a buffer overflow vulnerability can predict exactly where their shellcode will land in memory. With full ASLR (`kernel.randomize_va_space = 2`), they have to guess from billions of possible addresses.

Core dump restriction (control 1.5.2) prevents programs from writing their memory contents to disk when they crash. Core dumps can contain passwords, encryption keys, and other sensitive data that was in memory at the time of the crash.

---

## Section 2: Services

### Attack Surface Reduction

Every running service is a potential entry point. CIS Section 2 checks for 16 services that should not be installed on a hardened server unless there is an explicit business requirement. The philosophy is simple: if you do not need it, remove it.

The services checked include:

- **xinetd and openbsd-inetd** (2.1.1, 2.1.2): Legacy super-daemons that listen for connections and spawn other services. These are relics from the 1990s when memory was expensive and running a separate daemon for each service was wasteful. Modern systems use systemd socket activation. inetd has been a favored target in attacks for decades.

- **X Window System** (2.2.1): A graphical display server has no place on a headless server. The X protocol was designed without security in mind. Running X increases the attack surface dramatically and provides capabilities (screen capture, input recording) that attackers exploit for collection.

- **NFS, Samba, LDAP, DNS, FTP** (2.2.5 through 2.2.8): Each is a complex network service with a long history of vulnerabilities. An NFS server misconfiguration in 2020 (no specific CVE, it was a configuration error) allowed an attacker to mount an internal file share from the internet and exfiltrate 4TB of customer data from an unnamed financial institution.

- **MTA local-only configuration** (2.2.15): Mail transfer agents like Postfix default to listening on all interfaces. Control 2.2.15 verifies that the MTA only listens on loopback (`inet_interfaces = loopback-only`). An MTA listening on a public interface is an open relay waiting to happen.

---

## Section 3: Network Configuration

### Kernel Network Parameters

The Linux kernel exposes tunable network parameters through `/proc/sys/net/` and `sysctl`. Controls 3.1.1 through 3.2.6 verify that these parameters are set to secure values.

**IP forwarding** (3.1.1): `net.ipv4.ip_forward` controls whether the kernel routes packets between network interfaces. On a server with two NICs, enabled forwarding turns that server into a router. An attacker who compromises such a server can pivot traffic between network segments, bypassing network segmentation controls. Unless the server is explicitly a router or VPN gateway, this must be disabled.

**ICMP redirects** (3.1.2, 3.1.4): ICMP redirect messages tell a host to use a different gateway for a specific destination. An attacker on the local network can send forged ICMP redirects to reroute a victim's traffic through an attacker-controlled machine, enabling man-in-the-middle attacks. Disabling send_redirects and accept_redirects eliminates this vector.

**Source routing** (3.1.3): Source-routed packets allow the sender to specify the exact path through the network. This bypasses routing policies and firewall rules because the attacker dictates which routers the packet traverses. Modern networks should never accept source-routed packets.

**Reverse path filtering** (3.2.4): `rp_filter` causes the kernel to verify that incoming packets on an interface could legitimately arrive on that interface based on the routing table. This stops IP spoofing attacks where an attacker sends packets with a forged source address.

**TCP SYN cookies** (3.2.5): `tcp_syncookies` defends against SYN flood denial-of-service attacks. Without SYN cookies, an attacker who sends millions of SYN packets can exhaust the server's connection table, preventing legitimate clients from connecting. With SYN cookies enabled, the kernel uses a cryptographic technique to validate connection attempts without allocating resources until the handshake completes.

### Firewall Configuration

Controls 3.3.1 through 3.3.5 verify that iptables is installed, that the default policies for INPUT, FORWARD, and OUTPUT chains are DROP or REJECT, and that every open port has a matching firewall rule.

A default-deny firewall policy means that any traffic not explicitly allowed is dropped. This is the opposite of the default-accept policy that most distributions ship with. Default-deny catches the cases where a developer starts a service on an unexpected port, a dependency opens a debug listener, or a misconfiguration exposes an internal service to the network.

### Uncommon Protocol Modules

Controls 3.4.2 through 3.4.5 disable DCCP, SCTP, RDS, and TIPC kernel modules. These are specialized transport protocols that most servers never use. Each has had kernel vulnerabilities (CVE-2017-6074 was a double-free in DCCP that allowed local privilege escalation to root). Disabling the module is the simplest mitigation.

---

## Section 4: Logging and Auditing

### Why Logging Matters

Without logging, a breach is invisible. The median dwell time for attackers (the gap between initial compromise and detection) was 16 days in 2023 according to Mandiant's M-Trends report. For organizations with poor logging, it was significantly longer. The Target breach in 2013 went undetected for weeks despite FireEye generating alerts, because the security team did not have adequate logging infrastructure to correlate the events.

### auditd

Controls 4.1.1 through 4.1.14 verify that the Linux audit framework (`auditd`) is installed, enabled, configured to start at boot, and has rules covering security-critical system calls and files.

The audit framework operates at the kernel level. When configured with rules, it generates log entries every time a process calls specific system calls or modifies specific files. The audit rules in this project check for:

- **Time changes** (4.1.5): `adjtimex`, `settimeofday`, `clock_settime`. Attackers modify system time to make their activity appear to have occurred during a maintenance window or to invalidate time-based authentication tokens.
- **User/group changes** (4.1.6): Modifications to `/etc/passwd`, `/etc/shadow`, `/etc/group`. Any unauthorized changes to these files indicate account creation, privilege escalation, or persistence.
- **Network environment changes** (4.1.7): `sethostname`, `setdomainname`, modifications to `/etc/hosts`. Changing the hostname or DNS configuration can be part of a man-in-the-middle attack or C2 redirection.
- **DAC permission changes** (4.1.11): `chmod`, `chown`, `fchmod`, `setxattr`. These system calls modify file access controls. Attackers use them to make sensitive files readable or to set the setuid bit for privilege escalation.
- **Unauthorized access attempts** (4.1.12): Failed file access attempts that return EACCES or EPERM. A pattern of denied access attempts is a strong indicator of an attacker probing the filesystem for sensitive files.

### rsyslog

Controls 4.2.1 through 4.2.4 verify that rsyslog is installed, enabled, configured with a restrictive file creation mode (0640 or stricter), and has logging rules defined. rsyslog captures application and system messages that auditd does not cover: authentication events, service start/stop, kernel messages, and application logs.

---

## Section 5: Access, Authentication and Authorization

### Cron Security

Controls 5.1.1 through 5.1.4 verify that cron is enabled and that cron-related files and directories have restrictive permissions. An attacker who can write to `/etc/cron.daily/` can install a persistence mechanism that executes every day as root. Restricting cron directories to mode 700 owned by root:root prevents non-root users from planting cron jobs.

### SSH Hardening

Controls 5.2.1 through 5.2.14 cover SSH configuration. SSH is the primary remote access vector for Linux servers, and its configuration directly determines whether the server is accessible to attackers.

**Root login** (5.2.8): `PermitRootLogin no` forces administrators to log in with a named account and then escalate to root with `sudo`. This creates an audit trail of who performed which actions. When root login is allowed, multiple administrators share the root password, and there is no way to determine which human executed which commands.

**Weak cryptography** (5.2.11 through 5.2.13): These controls check that SSH does not allow CBC-mode ciphers (vulnerable to plaintext recovery attacks like CVE-2008-5161), MD5-based MACs (computationally broken), or weak key exchange algorithms like diffie-hellman-group1-sha1 (vulnerable to the Logjam attack, CVE-2015-4000, which allowed man-in-the-middle attackers to downgrade connections to 512-bit keys).

**MaxAuthTries** (5.2.6): Limiting authentication attempts to 4 makes brute-force attacks impractical over SSH. Without this limit, an attacker can try thousands of passwords in a single connection.

**LoginGraceTime** (5.2.14): The time window for completing authentication. Setting it to 60 seconds prevents attackers from opening hundreds of connections and holding them open indefinitely, which can exhaust the SSH daemon's connection pool.

### Password Policies

Controls 5.3.1 and 5.4.1 through 5.4.3 check PAM password quality modules and login.defs settings. `PASS_MAX_DAYS` forces password rotation. `PASS_MIN_DAYS` prevents users from immediately cycling back to their old password. `PASS_WARN_AGE` gives users advance notice of expiration.

Control 5.5.1 verifies account lockout. Without `pam_faillock` or `pam_tally2`, an attacker can attempt unlimited password guesses against a local account through PAM without any lockout mechanism.

---

## Section 6: System Maintenance

### File Permissions

Controls 6.1.1 through 6.1.5 verify that critical system files have correct ownership and permissions:

- `/etc/passwd` should be 644 root:root (readable by all, writable only by root)
- `/etc/shadow` should be 640 root:shadow (only root and the shadow group can read password hashes)
- `/etc/group` should be 644 root:root
- `/etc/gshadow` should be 640 root:shadow

If `/etc/shadow` were world-readable, any user on the system could extract password hashes and crack them offline with tools like hashcat. A modern GPU can test billions of hash combinations per second against SHA-512 hashes.

### Account Integrity

Controls 6.2.1 through 6.2.5 check for duplicate UIDs, duplicate GIDs, duplicate usernames, UID 0 accounts other than root, and legacy "+" entries in passwd/shadow/group files.

**UID 0 accounts** (6.2.4): Any account with UID 0 has full root privileges regardless of its name. A common persistence technique is to create an innocent-looking account like "sysadmin" or "backup" with UID 0. Control 6.2.4 catches this by verifying that only "root" has UID 0.

**Legacy + entries** (6.2.5): The "+" prefix in passwd/shadow/group files is a relic of NIS (Network Information Service). A line starting with "+" in /etc/passwd tells the system to include entries from a remote NIS server. If NIS is not in use, a "+" entry can introduce unexpected accounts or, in some configurations, create a passwordless root-equivalent account.

---

## How These Concepts Relate

```
CIS Benchmark (104 controls)
    ↓ organized into
6 Sections (defense in depth layers)
    ↓ each control has
Level (1 = baseline, 2 = advanced)
    ↓ and produces
Scored Results (PASS / FAIL / WARN / SKIP)
    ↓ which feed into
Compliance Score (percentage)
    ↓ which maps to
Regulatory Frameworks (NIST 800-53, PCI DSS, SOC 2)
```

---

## Industry Standards and Frameworks

### NIST 800-53

CIS benchmarks map directly to NIST 800-53 control families:
- **AC (Access Control)**: SSH hardening, cron permissions, password policies
- **AU (Audit and Accountability)**: auditd configuration, audit rules, rsyslog
- **CM (Configuration Management)**: Kernel parameters, disabled services, mount options
- **SC (System and Communications Protection)**: Firewall policies, disabled protocols, IP forwarding

### PCI DSS

PCI DSS Requirement 2 ("Do not use vendor-supplied defaults") maps directly to CIS hardening. Requirement 2.2 specifically calls for removing unnecessary services, protocols, and daemons, which is exactly what CIS Section 2 checks. PCI QSAs (Qualified Security Assessors) regularly accept CIS benchmark audit reports as evidence for Requirement 2 compliance.

### MITRE ATT&CK

The controls in this project map to ATT&CK mitigations:
- **M1042 (Disable or Remove Feature)**: Disabling unused filesystems and services (Sections 1, 2)
- **M1037 (Filter Network Traffic)**: Firewall configuration (Section 3)
- **M1029 (Remote Data Storage)**: rsyslog forwarding (Section 4)
- **M1032 (Multi-factor Authentication)**: SSH key authentication enforcement (Section 5)
- **M1018 (User Account Management)**: Duplicate UID checks, UID 0 restriction (Section 6)

---

## Real World Examples

### Case Study 1: The Equifax Breach (2017)

The initial compromise was CVE-2017-5638, a remote code execution vulnerability in Apache Struts. But the breach investigation revealed that the compromised servers lacked basic hardening controls that CIS benchmarks define. The internal certificate authority had expired certificates, which meant encrypted traffic inspection was disabled. Filesystem permissions were permissive. Network segmentation was absent. The attackers moved laterally from the web tier to the database tier without triggering any alerts because audit logging was insufficient.

A CIS Level 1 audit on those servers would have flagged the missing audit rules, the permissive file permissions, and the absence of network controls. The initial exploit would still have worked, but the attacker's lateral movement and data exfiltration would have been significantly harder and would have generated audit events.

### Case Study 2: The SolarWinds SUNBURST Attack (2020)

The SUNBURST backdoor inserted into SolarWinds Orion updates used sophisticated C2 communications, but the compromised build systems showed evidence of inadequate hardening. Build servers had IP forwarding enabled between network segments, audit logging was not configured to capture file modifications in the build pipeline, and SSH access was not restricted to authorized groups.

The lesson: even the most sophisticated supply chain attack exploits the gap between having security tools and actually hardening the systems those tools run on.

---

## Testing Your Understanding

Before moving to the architecture, make sure you can answer:

1. Why does the CIS benchmark distinguish between Level 1 and Level 2 controls? Give an example where applying a Level 2 control would break functionality.
2. An attacker has compromised a web application and can write files to /tmp. Explain which three mount options would limit their ability to use /tmp for privilege escalation and why each one works.
3. Why is `kernel.randomize_va_space = 1` (partial ASLR) insufficient while `2` (full ASLR) is required by the CIS benchmark?
4. A SOC analyst finds that `net.ipv4.conf.all.accept_redirects = 1` on a production server. Describe the specific attack this enables.

---

## Further Reading

**Essential:**
- [CIS Debian Linux 12 Benchmark v1.1.0](https://www.cisecurity.org/benchmark/debian_linux) - The actual benchmark document this project implements
- [NIST 800-123: Guide to General Server Security](https://csrc.nist.gov/publications/detail/sp/800-123/final) - The foundational document on server hardening

**Deep dives:**
- [Linux Audit Framework Documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening) - Comprehensive guide to auditd configuration
- [OpenSSH Hardening Guide](https://www.ssh-audit.com/hardening_guides.html) - Detailed analysis of SSH cipher and key exchange security

**Historical context:**
- [Mandiant M-Trends Report](https://www.mandiant.com/m-trends) - Annual report on attacker dwell times, techniques, and the role of logging in detection
