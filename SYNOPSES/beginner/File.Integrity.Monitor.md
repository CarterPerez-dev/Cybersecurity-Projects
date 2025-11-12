# File Integrity Monitor

## Overview
Build a security tool that monitors specified directories for unauthorized file changes by computing and tracking checksums of files, alerting on modifications, additions, or deletions with timestamped logs. This project teaches cryptographic hashing, file system monitoring, and demonstrates core concepts used in enterprise security tools for detecting system compromise.

## Step-by-Step Instructions

1. **Implement checksum calculation functionality** using MD5 or SHA256 algorithms to generate fixed-length fingerprints of file contents—use the `hashlib` library to compute hashes efficiently, supporting both small files loaded entirely into memory and large files processed in chunks. Create a baseline snapshot of files in monitored directories by computing and storing checksums with associated metadata (filename, path, file size, modification time, timestamp of calculation).

2. **Build a persistent database** to store baseline checksums and monitored file information—use SQLite for simplicity or JSON files for portability, storing records of each file's name, path, size, and hash value. Structure the database to support multiple monitoring sessions and historical tracking so you can generate reports showing changes over time and identify patterns of tampering.

3. **Create a baseline snapshot command** that scans specified directories (recursively or non-recursively based on configuration), computes checksums for all files, and stores them in the database as the reference state. Include filtering capabilities to exclude certain file types, paths, or sizes, allowing users to focus monitoring on critical system files rather than monitoring entire directories including temporary or log files.

4. **Implement continuous monitoring** using file system watchers (Python's `watchdog` library) or periodic rescanning to detect when files change. Compare newly computed checksums against the stored baseline, tracking three types of events: modified files (checksum changed), new files (not in baseline), and deleted files (in baseline but no longer exist). Log each event with precise timestamps for forensic analysis.

5. **Add alerting capabilities** to notify administrators when suspicious changes are detected, supporting multiple alert channels (write to log file, email alerts, webhook notifications, system notifications). Implement alert severity levels distinguishing between critical files (immediate alert) and less important files (batch alerts), allowing administrators to tune notification frequency and avoid alert fatigue.

6. **Create reporting functionality** generating detailed logs and reports showing all detected changes with timestamps, file paths, before-and-after file sizes, and calculated checksums. Include summary statistics (total files monitored, changes detected, false positives if any) and provide export options (CSV, JSON, PDF) suitable for compliance documentation and forensic investigations.

7. **Build configuration management** allowing users to specify monitored directories, file filters, checksum algorithms, monitoring frequency, database location, and alert settings through configuration files. Include command-line arguments for common operations (create baseline, run monitor, generate report) making the tool convenient for both interactive and automated/scheduled use.

8. **Create comprehensive documentation** explaining file integrity monitoring concepts, discussing use cases (detecting system compromise, compliance monitoring, configuration drift detection), and providing deployment examples. Explain limitations (monitoring adds overhead, doesn't prevent modifications, only detects them), compare your tool to enterprise solutions like Tripwire or AIDE, and include guidance on responding to detected changes (isolating systems, analyzing logs, involving incident response).

## Key Concepts to Learn
- Cryptographic hash functions and checksums
- File system operations and monitoring
- Database design and persistence
- Event logging and alerting systems
- Compliance and forensic investigation

## Deliverables
- Baseline checksum snapshot creation
- Continuous file monitoring with change detection
- SQLite or JSON database for checksum storage
- Multi-channel alerting (logs, email, webhooks)
- Detailed reporting with export formats
