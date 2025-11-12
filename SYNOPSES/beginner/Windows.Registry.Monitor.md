# Windows Registry Change Monitor

## Overview
Build a Windows security tool that monitors critical registry keys for unauthorized modifications, focusing on common persistence locations used by malware like Run keys, Services, and Scheduled Tasks. This project teaches Windows system administration, malware persistence mechanisms, and demonstrates host-based threat detection techniques.

## Step-by-Step Instructions

1. **Understand Windows Registry structure and persistence mechanisms** by learning that the Registry is Windows' configuration database organized in hives (HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, etc.) with subkeys and values. Study how malware achieves persistence: Run/RunOnce keys (HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run) execute programs at startup, Services keys enable malware to run as system services, Scheduled Tasks hide in Task Scheduler, and many other locations offer persistence opportunities. Create a comprehensive list of high-risk registry locations.

2. **Install Windows Registry monitoring library** using `python-registry` or `pywin32` to programmatically access and monitor the Windows Registry. Learn how to enumerate Registry keys, read values, and handle Registry permissions—understand that monitoring may require administrator privileges and that accessing certain Registry hives might need special handling.

3. **Implement Registry snapshot creation** by taking a baseline of critical registry keys and their values, storing this in a database or JSON file. Include all values under high-risk keys like HKLM\Software\Microsoft\Windows\CurrentVersion\Run, HKLM\System\CurrentControlSet\Services, and similar locations. Create a comprehensive inventory of existing legitimate persistence mechanisms to distinguish them from suspicious additions.

4. **Build continuous monitoring** that periodically reads the current Registry state and compares it against the baseline, detecting three types of changes: new registry values added (potential malware persistence), modified values (altered commands or locations), and deleted values (attempted cleanup or legitimate removal). Track timestamps and implement change detection that runs at configurable intervals (continuous polling, scheduled checks).

5. **Implement change tracking and analysis** by creating records for each detected modification including timestamp, registry path, previous value, new value, value type, and change type. Build analysis logic that distinguishes between legitimate changes (software updates, user configuration changes, administrator actions) and suspicious changes (new .exe files in Run keys, suspicious scheduled tasks, service additions).

6. **Create alerting and logging** that generates alerts when suspicious Registry modifications are detected, including detailed change information and recommendations for investigation. Log all changes to a secure location with immutable timestamps, create audit trails showing who accessed Registry monitoring, and provide capabilities to export logs for compliance documentation or incident investigation.

7. **Add remediation capabilities** allowing administrators to quickly revert suspicious Registry changes by restoring values to previous states. Implement whitelist/blacklist functionality where known-good Registry modifications can be approved and excluded from alerts, preventing alert fatigue while focusing on truly suspicious changes. Include rollback functionality with safeguards preventing accidental deletion of critical Registry values.

8. **Build comprehensive documentation** explaining Registry persistence mechanisms and how malware achieves persistence through Registry modifications, discussing detection methodology and limitations (Registry monitoring adds system overhead, sophisticated malware may hide changes). Provide setup instructions, examples of legitimate vs. suspicious Registry changes, and integration guidance with Windows Event Log monitoring and incident response procedures. Compare your tool to enterprise solutions and discuss Registry-level protections available in Windows security features.

## Key Concepts to Learn
- Windows Registry structure and organization
- Malware persistence mechanisms
- Registry access and enumeration
- Change detection and baseline comparison
- Alerting and logging systems
- Incident response and remediation

## Deliverables
- Registry snapshot and baseline creation
- Continuous Registry monitoring
- Change detection for additions, modifications, deletions
- Suspicious pattern analysis and detection
- Alerting with detailed change information
- Remediation and rollback capabilities
