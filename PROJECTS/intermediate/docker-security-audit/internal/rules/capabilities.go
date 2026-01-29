/*
AngelaMos | 2026
capabilities.go
*/

package rules

import (
	"strings"

	"github.com/CarterPerez-dev/docksec/internal/finding"
)

type CapabilityInfo struct {
	Severity    finding.Severity
	Description string
}

var Capabilities = map[string]CapabilityInfo{
	// CAP 0 - File Ownership
	"CAP_CHOWN": {
		Severity:    finding.SeverityMedium,
		Description: "Change file ownership. Can take ownership of any file, bypassing normal permission checks.",
	},

	// CAP 1 - DAC Override
	"CAP_DAC_OVERRIDE": {
		Severity:    finding.SeverityHigh,
		Description: "Bypass file read, write, and execute permission checks. Complete filesystem access.",
	},

	// CAP 2 - DAC Read Search
	"CAP_DAC_READ_SEARCH": {
		Severity:    finding.SeverityHigh,
		Description: "Bypass file read permission checks and directory read/execute checks. Read any file.",
	},

	// CAP 3 - File Owner Override
	"CAP_FOWNER": {
		Severity:    finding.SeverityHigh,
		Description: "Bypass permission checks on operations requiring file owner UID match. Modify any file metadata.",
	},

	// CAP 4 - File Set-ID
	"CAP_FSETID": {
		Severity:    finding.SeverityMedium,
		Description: "Don't clear set-user-ID and set-group-ID bits when a file is modified. Preserve SUID/SGID.",
	},

	// CAP 5 - Kill Processes
	"CAP_KILL": {
		Severity:    finding.SeverityMedium,
		Description: "Send signals to arbitrary processes. Bypass permission checks for kill().",
	},

	// CAP 6 - Set GID
	"CAP_SETGID": {
		Severity:    finding.SeverityHigh,
		Description: "Make arbitrary manipulations of process GIDs. Privilege escalation risk via group changes.",
	},

	// CAP 7 - Set UID
	"CAP_SETUID": {
		Severity:    finding.SeverityHigh,
		Description: "Make arbitrary manipulations of process UIDs. Direct privilege escalation to root.",
	},

	// CAP 8 - Set Process Capabilities
	"CAP_SETPCAP": {
		Severity:    finding.SeverityHigh,
		Description: "Modify process capabilities. Can grant new capabilities to self or child processes.",
	},

	// CAP 9 - Linux Immutable
	"CAP_LINUX_IMMUTABLE": {
		Severity:    finding.SeverityMedium,
		Description: "Set the immutable and append-only file attributes. Can prevent file modification/deletion.",
	},

	// CAP 10 - Bind Privileged Ports
	"CAP_NET_BIND_SERVICE": {
		Severity:    finding.SeverityLow,
		Description: "Bind to privileged ports (below 1024). Required for most server applications.",
	},

	// CAP 11 - Network Broadcast
	"CAP_NET_BROADCAST": {
		Severity:    finding.SeverityLow,
		Description: "Send broadcast packets and listen to multicast. Can flood network segments.",
	},

	// CAP 12 - Network Administration
	"CAP_NET_ADMIN": {
		Severity:    finding.SeverityHigh,
		Description: "Perform network administration operations. Modify routing, firewall rules, sniff traffic, MITM attacks.",
	},

	// CAP 13 - Raw Network Access
	"CAP_NET_RAW": {
		Severity:    finding.SeverityMedium,
		Description: "Use RAW and PACKET sockets. Craft arbitrary packets, ARP/DNS spoofing, packet sniffing.",
	},

	// CAP 14 - IPC Lock Memory
	"CAP_IPC_LOCK": {
		Severity:    finding.SeverityLow,
		Description: "Lock memory (mlock, mlockall). Prevent swapping of sensitive data, DoS via memory exhaustion.",
	},

	// CAP 15 - IPC Owner Override
	"CAP_IPC_OWNER": {
		Severity:    finding.SeverityMedium,
		Description: "Bypass permission checks for IPC operations. Access any shared memory, semaphores, message queues.",
	},

	// CAP 16 - Kernel Module Operations
	"CAP_SYS_MODULE": {
		Severity:    finding.SeverityCritical,
		Description: "Load and unload kernel modules. Full kernel access, rootkit installation, complete system compromise.",
	},

	// CAP 17 - Raw I/O Operations
	"CAP_SYS_RAWIO": {
		Severity:    finding.SeverityCritical,
		Description: "Perform raw I/O port operations and access /dev/mem, /dev/kmem. Direct hardware and kernel memory access.",
	},

	// CAP 18 - Chroot
	"CAP_SYS_CHROOT": {
		Severity:    finding.SeverityMedium,
		Description: "Use chroot. Essential for container operations but can be used in escape techniques.",
	},

	// CAP 19 - Process Trace
	"CAP_SYS_PTRACE": {
		Severity:    finding.SeverityCritical,
		Description: "Trace arbitrary processes using ptrace. Read/write memory of any process, inject code, steal secrets.",
	},

	// CAP 20 - Process Accounting
	"CAP_SYS_PACCT": {
		Severity:    finding.SeverityLow,
		Description: "Configure process accounting. Enable/disable accounting, access accounting data.",
	},

	// CAP 21 - System Administration
	"CAP_SYS_ADMIN": {
		Severity:    finding.SeverityCritical,
		Description: "Perform a range of system administration operations. Effectively root - mount filesystems, quotas, namespaces, etc.",
	},

	// CAP 22 - System Reboot
	"CAP_SYS_BOOT": {
		Severity:    finding.SeverityHigh,
		Description: "Reboot the system and use kexec_load. DoS via system restart.",
	},

	// CAP 23 - Process Scheduling
	"CAP_SYS_NICE": {
		Severity:    finding.SeverityMedium,
		Description: "Modify process nice values, scheduling policy, and CPU affinity. DoS via resource starvation, RT priority escalation.",
	},

	// CAP 24 - Resource Limits Override
	"CAP_SYS_RESOURCE": {
		Severity:    finding.SeverityMedium,
		Description: "Override resource limits (RLIMIT_*). Exhaust system resources, bypass quotas and limits.",
	},

	// CAP 25 - System Time
	"CAP_SYS_TIME": {
		Severity:    finding.SeverityMedium,
		Description: "Set system clock and real-time hardware clock. Break logging, certificates, time-based authentication.",
	},

	// CAP 26 - TTY Configuration
	"CAP_SYS_TTY_CONFIG": {
		Severity:    finding.SeverityLow,
		Description: "Configure tty devices using vhangup. Limited security impact.",
	},

	// CAP 27 - Create Special Files
	"CAP_MKNOD": {
		Severity:    finding.SeverityHigh,
		Description: "Create special files using mknod. Create device nodes for /dev/mem, /dev/sda access.",
	},

	// CAP 28 - File Leases
	"CAP_LEASE": {
		Severity:    finding.SeverityLow,
		Description: "Establish leases on arbitrary files. Limited security impact.",
	},

	// CAP 29 - Audit Write
	"CAP_AUDIT_WRITE": {
		Severity:    finding.SeverityMedium,
		Description: "Write records to kernel audit log. Inject false audit entries to cover tracks.",
	},

	// CAP 30 - Audit Control
	"CAP_AUDIT_CONTROL": {
		Severity:    finding.SeverityHigh,
		Description: "Enable/disable kernel auditing and modify audit rules. Hide malicious activity completely.",
	},

	// CAP 31 - File Capabilities
	"CAP_SETFCAP": {
		Severity:    finding.SeverityHigh,
		Description: "Set file capabilities on executables. Grant elevated privileges to any binary.",
	},

	// CAP 32 - MAC Override
	"CAP_MAC_OVERRIDE": {
		Severity:    finding.SeverityCritical,
		Description: "Override Mandatory Access Control for specific operations. Bypass SELinux/AppArmor policies.",
	},

	// CAP 33 - MAC Administration
	"CAP_MAC_ADMIN": {
		Severity:    finding.SeverityCritical,
		Description: "Configure or modify MAC policy (SELinux, AppArmor, Smack). Disable mandatory access controls entirely.",
	},

	// CAP 34 - Syslog Operations
	"CAP_SYSLOG": {
		Severity:    finding.SeverityMedium,
		Description: "Perform privileged syslog operations. Read kernel ring buffer, clear logs, information disclosure.",
	},

	// CAP 35 - Wake Alarm
	"CAP_WAKE_ALARM": {
		Severity:    finding.SeverityLow,
		Description: "Trigger system wake events using RTC timers. Limited security impact.",
	},

	// CAP 36 - Block System Suspend
	"CAP_BLOCK_SUSPEND": {
		Severity:    finding.SeverityLow,
		Description: "Block system suspend and hibernation. DoS via power management interference.",
	},

	// CAP 37 - Audit Read
	"CAP_AUDIT_READ": {
		Severity:    finding.SeverityMedium,
		Description: "Read kernel audit logs. Information disclosure of security events and user activity.",
	},

	// CAP 38 - Performance Monitoring
	"CAP_PERFMON": {
		Severity:    finding.SeverityMedium,
		Description: "Access performance monitoring and observability operations. Profile system behavior, side-channel attacks.",
	},

	// CAP 39 - BPF Operations
	"CAP_BPF": {
		Severity:    finding.SeverityCritical,
		Description: "Load BPF programs and create BPF maps. Trace all syscalls, modify network traffic, kernel-level monitoring.",
	},

	// CAP 40 - Checkpoint/Restore
	"CAP_CHECKPOINT_RESTORE": {
		Severity:    finding.SeverityHigh,
		Description: "Checkpoint and restore processes using CRIU. Access process memory, file descriptors, and state.",
	},
}

// Pre computed sets for fast lookup
var dangerousCapabilities = func() map[string]struct{} {
	m := make(map[string]struct{})
	for cap, info := range Capabilities {
		if info.Severity >= finding.SeverityHigh {
			m[cap] = struct{}{}
			m[strings.TrimPrefix(cap, "CAP_")] = struct{}{}
		}
	}
	return m
}()

var criticalCapabilities = func() map[string]struct{} {
	m := make(map[string]struct{})
	for cap, info := range Capabilities {
		if info.Severity == finding.SeverityCritical {
			m[cap] = struct{}{}
			m[strings.TrimPrefix(cap, "CAP_")] = struct{}{}
		}
	}
	return m
}()

func normalizeCapability(cap string) string {
	normalized := strings.ToUpper(strings.TrimSpace(cap))
	if !strings.HasPrefix(normalized, "CAP_") {
		normalized = "CAP_" + normalized
	}
	return normalized
}

func IsDangerousCapability(cap string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(cap))
	_, exists := dangerousCapabilities[normalized]
	return exists
}

func IsCriticalCapability(cap string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(cap))
	_, exists := criticalCapabilities[normalized]
	return exists
}

func GetCapabilityInfo(cap string) (CapabilityInfo, bool) {
	info, ok := Capabilities[normalizeCapability(cap)]
	return info, ok
}

func GetCapabilitySeverity(cap string) finding.Severity {
	if info, ok := GetCapabilityInfo(cap); ok {
		return info.Severity
	}
	return finding.SeverityLow
}
