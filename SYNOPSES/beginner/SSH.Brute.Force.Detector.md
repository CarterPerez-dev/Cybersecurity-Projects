# SSH Brute Force Detector

## Overview
Build a security tool that monitors system authentication logs for SSH brute force attack patterns, automatically detecting repeated failed login attempts and responding by adding offending IPs to firewall rules. This project teaches log file parsing, threat pattern recognition, and demonstrates automated security response capabilities used in production systems.

## Step-by-Step Instructions

1. **Understand SSH authentication logs** on different systems—on Linux, failed SSH attempts are typically logged to `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RedHat/CentOS) with entries showing source IP, username attempted, and authentication status. Learn the log format patterns for successful logins, failed password attempts, and invalid usernames, then build log line parsers that extract relevant information (timestamp, source IP, username, result status).

2. **Implement log file monitoring and parsing** using Python to read log files and extract failed SSH login attempts, including source IP addresses and timestamps. Handle the complexity of log rotation (logs are archived and new ones created) and ensure continuous monitoring even as log files change, implementing state tracking to avoid re-reading lines already processed.

3. **Build brute force pattern detection** by tracking failed login attempts per source IP over time windows (e.g., 5 failed attempts in 10 minutes indicates an attack). Implement configurable thresholds for what constitutes an attack, distinguishing between user mistakes (occasional failed logins from legitimate IPs) and actual brute force (many failed attempts from unexpected sources).

4. **Create IP reputation tracking** by maintaining a database of known-good IPs (internal networks, remote offices, trusted partners) that should be excluded from blocking, and a list of known-bad IPs that have shown attack behavior. Implement whitelist/blacklist functionality preventing false positives where legitimate users get blocked after mistyping passwords a few times.

5. **Implement automatic firewall rule addition** using iptables (Linux), UFW, or similar tools to dynamically block attacking IPs. Execute firewall commands programmatically when thresholds are exceeded, adding rules that drop all packets from the attacking source or rate-limit connections. Build in safeguards preventing accidental self-blocking (blocking the admin's own IP, blocking critical IPs).

6. **Add escalating response mechanisms** implementing multi-stage responses: first alert administrators of potential attack, then rate-limit connections from the source IP, then block the IP entirely if attacks continue. Include automatic unblocking after a configurable time period (24-48 hours) to allow IPs to be whitelisted, and implement manual unblock capabilities for legitimate IPs accidentally blocked.

7. **Create alerting and logging functionality** that notifies administrators when attacks are detected through email, Slack, system logs, or dashboard alerts. Log all detected attacks, blocking actions, and false positives to a database or file for audit trails, compliance documentation, and incident investigation—include details about the attacking IP, targeted usernames, attempt frequency, and response actions taken.

8. **Build comprehensive documentation** explaining SSH security best practices, discussing brute force attack patterns and mitigation strategies, and providing deployment instructions with security considerations. Discuss alternative protections (key-based authentication, fail2ban integration, VPN access restrictions), explain how to configure sensitivity to avoid false positives, and provide examples of logs from actual brute force attacks for analysis and training.

## Key Concepts to Learn
- Log file parsing and text analysis
- State tracking and continuous monitoring
- Pattern recognition for threat detection
- Firewall integration and automation
- Alerting and incident response
- Whitelist/blacklist management

## Deliverables
- SSH log file parser and monitor
- Brute force pattern detection with configurable thresholds
- Automatic firewall rule generation and management
- IP whitelist/blacklist functionality
- Multi-stage escalating response
- Alert notifications and attack logging
