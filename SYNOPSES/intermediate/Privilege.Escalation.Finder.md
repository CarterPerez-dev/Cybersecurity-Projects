# Privilege Escalation Path Finder

## Overview
Build an analysis tool that examines Windows and Linux systems for privilege escalation vectors including SUID binaries, weak permissions, kernel exploits, and misconfigured services. This project teaches system hardening assessment, privilege escalation methodology, and demonstrates post-exploitation analysis techniques used in penetration testing.

## Step-by-Step Instructions

1. **Understand privilege escalation concepts and attack vectors** by learning that escalation converts limited user access to system/root access, enabling attackers to fully compromise systems. Study common vectors: SUID/SGID binaries (execute with elevated privileges), capabilities-based permissions (granular privilege delegation), weak file/directory permissions (overwrite critical files), kernel vulnerabilities (patches fix known exploits), misconfigurations (services running as root accepting user input), Sudo/sudoers misconfigurations (users can run privileged commands without passwords), and DLL hijacking. Research public exploit databases (Exploit-DB, CVE Details) tracking known escalation exploits.

2. **Implement SUID/SGID binary enumeration on Linux** by scanning filesystem for binaries with setuid/setgid bits set, extracting: file path, owner (should be restricted user, typically root), permissions, and file type. Use `find` command or direct system calls to identify all SUID/SGID binaries. Cross-reference discovered binaries against known vulnerable binaries database (certain versions of sudo, su, etc. have known escalation exploits). Analyze binary functionality: binaries accepting user input have escalation potential.

3. **Build file and directory permission analysis** examining permission structure for vulnerabilities: identify world-writable directories in critical paths (/tmp is expected, but /etc shouldn't be), world-readable files containing sensitive information (shadow files, SSH keys, configuration files), and misconfigured home directories. Build permission matrices showing which users/groups have access to which resources. Highlight permission mismatches (file readable by all when it should be restricted, directories writable by unprivileged users).

4. **Create kernel vulnerability scanning** identifying vulnerable kernel versions susceptible to known exploits: extract current kernel version, cross-reference against CVE databases, identify applicable exploits (DirtyCOW, PwnKit, Polkit vulnerabilities). Recommend patches and kernel updates. Handle multiple Linux distributions with different kernel versioning schemes.

5. **Implement service configuration analysis** examining running services for escalation opportunities: identify services running as root, analyze service configurations checking for accepted user input, identify common vulnerable services (Apache with mod_cgi, database services accepting client connections). Check init scripts and systemd service files for vulnerabilities (scripts with weak permissions allowing modification, environment variable injection opportunities).

6. **Build capability and sudo analysis** on Linux systems: extract capabilities set on binaries (granular privilege delegation), identify sudo configurations allowing specific users to run privileged commands. Parse sudoers files detecting misconfigurations (users with NOPASSWD tags, wildcards allowing excessive command execution, weak command restrictions). Analyze which commands users can elevate and their potential for escalation.

7. **Create Windows privilege escalation scanning** examining Windows systems for escalation vectors: identify services running as system/admin, analyze service permissions checking for weak DACLs (users can modify service executables), examine registry permissions for escalation opportunities, identify scheduled tasks running with elevated privileges that users can modify. Check for weak permissions on critical directories (Windows, System32, Program Files).

8. **Build comprehensive reporting with attack path analysis** generating reports showing discovered escalation vectors, creating attack paths (initial access → escalation vector → system compromise), and assigning severity scores. Provide proof-of-concept showing how each vector could be exploited, include remediation recommendations (patch vulnerable binaries, fix permission issues, implement least-privilege). Create executive summary highlighting critical escalation paths, compare to security benchmarks, and explain how escalation testing fits into penetration testing and system hardening assessments. Include documentation of escalation methodology, discussion of detection evasion, and incident response implications.

## Key Concepts to Learn
- Privilege escalation vectors and techniques
- SUID/SGID binaries and capabilities
- File and directory permissions
- Kernel vulnerabilities and CVEs
- Service configuration analysis
- Sudo and sudoers security
- Windows service and registry analysis
- Attack path identification

## Deliverables
- SUID/SGID binary enumeration
- File and directory permission analysis
- Kernel vulnerability identification
- Service configuration auditing
- Capability analysis (Linux)
- Sudoers configuration analysis
- Windows privilege escalation vectors
- Attack path visualization
- Comprehensive escalation reporting
- Proof-of-concept demonstrations
