/*
AngelaMos | 2026
controls.go
*/

package benchmark

import "github.com/CarterPerez-dev/docksec/internal/finding"

type Control struct {
	ID          string
	Section     string
	Title       string
	Description string
	Remediation string
	Severity    finding.Severity
	Scored      bool
	Level       int
	References  []string
}

func (c Control) ToCISControl() *finding.CISControl {
	return &finding.CISControl{
		ID:          c.ID,
		Section:     c.Section,
		Title:       c.Title,
		Description: c.Description,
		Scored:      c.Scored,
		Level:       c.Level,
	}
}

var controlRegistry = make(map[string]Control)

func Register(c Control) {
	controlRegistry[c.ID] = c
}

func Get(id string) (Control, bool) {
	c, ok := controlRegistry[id]
	return c, ok
}

func All() []Control {
	controls := make([]Control, 0, len(controlRegistry))
	for _, c := range controlRegistry {
		controls = append(controls, c)
	}
	return controls
}

func BySection(section string) []Control {
	var controls []Control
	for _, c := range controlRegistry {
		if c.Section == section {
			controls = append(controls, c)
		}
	}
	return controls
}

func init() {
	registerHostControls()
	registerDaemonControls()
	registerDaemonFilesControls()
	registerImageControls()
	registerContainerRuntimeControls()
	registerSecurityOperationsControls()
	registerSwarmControls()
}

func registerHostControls() {
	Register(Control{
		ID:          "1.1.1",
		Section:     "Host Configuration",
		Title:       "Ensure a separate partition for containers has been created",
		Severity:    finding.SeverityMedium,
		Description: "All Docker containers and their data and metadata are stored under /var/lib/docker directory. By default, this directory is stored on the same partition as the root filesystem. A separate partition provides isolation and prevents DoS attacks from filling up the host filesystem.",
		Remediation: "Create a separate partition for /var/lib/docker. Use LVM or partition management tools during system installation or configuration.",
		Scored:      true,
		Level:       1,
		References:  []string{"https://docs.docker.com/storage/"},
	})

	Register(Control{
		ID:          "1.1.2",
		Section:     "Host Configuration",
		Title:       "Ensure only trusted users are allowed to control Docker daemon",
		Severity:    finding.SeverityHigh,
		Description: "The Docker daemon runs as root and provides root-equivalent access to the host. Only trusted users should be members of the docker group or have access to the Docker socket.",
		Remediation: "Remove untrusted users from the docker group. Regularly audit docker group membership. Use sudo for Docker access where appropriate.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/security/#docker-daemon-attack-surface",
		},
	})

	Register(Control{
		ID:          "1.1.3",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker daemon",
		Severity:    finding.SeverityMedium,
		Description: "Audit all Docker daemon activities to capture security-relevant events. This helps with forensics and compliance requirements.",
		Remediation: "Install auditd and add rules to audit the Docker daemon: -w /usr/bin/dockerd -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.4",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - /run/containerd",
		Severity:    finding.SeverityMedium,
		Description: "Audit /run/containerd directory to capture file operations and system calls related to containerd runtime.",
		Remediation: "Add audit rule: -w /run/containerd -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.5",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - /var/lib/docker",
		Severity:    finding.SeverityMedium,
		Description: "Audit /var/lib/docker directory which contains all Docker data including containers, images, volumes, and metadata.",
		Remediation: "Add audit rule: -w /var/lib/docker -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.6",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - /etc/docker",
		Severity:    finding.SeverityMedium,
		Description: "Audit /etc/docker directory which contains Docker daemon configuration files and certificates.",
		Remediation: "Add audit rule: -w /etc/docker -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.7",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - docker.service",
		Severity:    finding.SeverityMedium,
		Description: "Audit docker.service systemd unit file to track changes to Docker daemon service configuration.",
		Remediation: "Add audit rule: -w /usr/lib/systemd/system/docker.service -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.8",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - containerd.sock",
		Severity:    finding.SeverityMedium,
		Description: "Audit containerd socket file which is the communication endpoint for containerd.",
		Remediation: "Add audit rule: -w /run/containerd/containerd.sock -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.9",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - docker.socket",
		Severity:    finding.SeverityMedium,
		Description: "Audit docker.socket systemd unit file which manages Docker socket activation.",
		Remediation: "Add audit rule: -w /usr/lib/systemd/system/docker.socket -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.10",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - /etc/default/docker",
		Severity:    finding.SeverityMedium,
		Description: "Audit /etc/default/docker file which may contain Docker daemon startup options.",
		Remediation: "Add audit rule: -w /etc/default/docker -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.11",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - /etc/docker/daemon.json",
		Severity:    finding.SeverityMedium,
		Description: "Audit /etc/docker/daemon.json which is the primary Docker daemon configuration file.",
		Remediation: "Add audit rule: -w /etc/docker/daemon.json -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.12",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - /etc/containerd/config.toml",
		Severity:    finding.SeverityMedium,
		Description: "Audit containerd configuration file to track changes to container runtime settings.",
		Remediation: "Add audit rule: -w /etc/containerd/config.toml -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.13",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - /etc/sysconfig/docker",
		Severity:    finding.SeverityMedium,
		Description: "Audit /etc/sysconfig/docker file which may contain Docker daemon configuration on Red Hat-based systems.",
		Remediation: "Add audit rule: -w /etc/sysconfig/docker -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.14",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - /usr/bin/containerd",
		Severity:    finding.SeverityMedium,
		Description: "Audit containerd binary to detect unauthorized changes or execution.",
		Remediation: "Add audit rule: -w /usr/bin/containerd -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.15",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - /usr/bin/containerd-shim",
		Severity:    finding.SeverityMedium,
		Description: "Audit containerd-shim binary which manages container lifecycle operations.",
		Remediation: "Add audit rule: -w /usr/bin/containerd-shim -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.16",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - /usr/bin/containerd-shim-runc-v1",
		Severity:    finding.SeverityMedium,
		Description: "Audit containerd-shim-runc-v1 binary which is the runc v1 runtime shim.",
		Remediation: "Add audit rule: -w /usr/bin/containerd-shim-runc-v1 -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.17",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - /usr/bin/containerd-shim-runc-v2",
		Severity:    finding.SeverityMedium,
		Description: "Audit containerd-shim-runc-v2 binary which is the runc v2 runtime shim.",
		Remediation: "Add audit rule: -w /usr/bin/containerd-shim-runc-v2 -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.1.18",
		Section:     "Host Configuration",
		Title:       "Ensure auditing is configured for Docker files and directories - /usr/bin/runc",
		Severity:    finding.SeverityMedium,
		Description: "Audit runc binary which is the low-level container runtime.",
		Remediation: "Add audit rule: -w /usr/bin/runc -k docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-defining_audit_rules_and_controls",
		},
	})

	Register(Control{
		ID:          "1.2.1",
		Section:     "Host Configuration",
		Title:       "Ensure the container host has been hardened",
		Severity:    finding.SeverityHigh,
		Description: "Container hosts should be hardened according to security best practices including minimal installations, regular patching, firewall configuration, and removal of unnecessary services.",
		Remediation: "Follow CIS benchmarks for the host operating system. Implement security hardening guides for your distribution. Remove unnecessary packages and services. Enable and configure host firewall. Keep the system patched and updated.",
		Scored:      false,
		Level:       1,
		References:  []string{"https://www.cisecurity.org/cis-benchmarks/"},
	})

	Register(Control{
		ID:          "1.2.2",
		Section:     "Host Configuration",
		Title:       "Ensure that the version of Docker is up to date",
		Severity:    finding.SeverityMedium,
		Description: "Running outdated Docker versions may expose the system to known vulnerabilities. Regularly update Docker to receive security patches and bug fixes.",
		Remediation: "Regularly check for Docker updates and apply them following your organization's change management process. Subscribe to Docker security announcements.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/install/",
			"https://github.com/moby/moby/releases",
		},
	})
}

func registerDaemonControls() {
	Register(Control{
		ID:          "2.1",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure network traffic is restricted between containers on the default bridge",
		Severity:    finding.SeverityMedium,
		Description: "By default, all network traffic is allowed between containers on the default bridge network. Containers should not be able to communicate with each other unless explicitly allowed.",
		Remediation: "Run the Docker daemon with --icc=false flag: dockerd --icc=false. Use docker network or links for explicit container communication.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/network/packet-filtering-firewalls/",
		},
	})

	Register(Control{
		ID:          "2.2",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure the logging level is set to 'info'",
		Severity:    finding.SeverityMedium,
		Description: "Setting the logging level to 'info' provides a reasonable balance between verbosity and security visibility. Debug mode generates excessive logs while error/fatal modes may miss important events.",
		Remediation: "Run the Docker daemon with --log-level=info or set log-level: info in daemon.json.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/config/daemon/",
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "2.3",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure Docker is allowed to make changes to iptables",
		Severity:    finding.SeverityMedium,
		Description: "Docker needs to make changes to iptables to set up networking. Disabling this breaks container networking but may be required in specialized environments.",
		Remediation: "Do not run Docker daemon with --iptables=false unless required. Default is --iptables=true.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/network/packet-filtering-firewalls/",
		},
	})

	Register(Control{
		ID:          "2.4",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure insecure registries are not used",
		Severity:    finding.SeverityHigh,
		Description: "Insecure registries use unencrypted HTTP connections, allowing man-in-the-middle attacks and image tampering.",
		Remediation: "Do not use --insecure-registry flag. Configure registries to use TLS certificates. Use private registries with proper authentication.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/certificates/",
		},
	})

	Register(Control{
		ID:          "2.5",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure aufs storage driver is not used",
		Severity:    finding.SeverityLow,
		Description: "The aufs storage driver is deprecated and has known security issues. Modern alternatives like overlay2 should be used.",
		Remediation: "Use overlay2 storage driver instead: dockerd --storage-driver overlay2 or set storage-driver: overlay2 in daemon.json.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/storage/storagedriver/select-storage-driver/",
		},
	})

	Register(Control{
		ID:          "2.6",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure TLS authentication for Docker daemon is configured",
		Severity:    finding.SeverityHigh,
		Description: "Docker daemon listens on a Unix socket by default. If exposed over TCP, it must use TLS to prevent unauthorized access.",
		Remediation: "Configure TLS: dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem --tlskey=server-key.pem -H=0.0.0.0:2376",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/protect-access/",
		},
	})

	Register(Control{
		ID:          "2.7",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure the default ulimit is configured appropriately",
		Severity:    finding.SeverityMedium,
		Description: "Default ulimits control resource usage for containers. Proper limits prevent resource exhaustion attacks.",
		Remediation: "Set appropriate ulimits: dockerd --default-ulimit nproc=1024:2048 --default-ulimit nofile=100:200",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/#default-ulimit-settings",
		},
	})

	Register(Control{
		ID:          "2.8",
		Section:     "Docker Daemon Configuration",
		Title:       "Enable user namespace support",
		Severity:    finding.SeverityHigh,
		Description: "User namespace remapping maps container root to an unprivileged user on the host, providing defense in depth against container escape.",
		Remediation: "Enable user namespaces: dockerd --userns-remap=default or configure in daemon.json with userns-remap: default.",
		Scored:      true,
		Level:       2,
		References: []string{
			"https://docs.docker.com/engine/security/userns-remap/",
		},
	})

	Register(Control{
		ID:          "2.9",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure the default cgroup usage has been confirmed",
		Severity:    finding.SeverityMedium,
		Description: "Cgroups control resource allocation for containers. The default cgroupfs driver should be used unless systemd integration is required.",
		Remediation: "Use default cgroup driver or explicitly set: dockerd --exec-opt native.cgroupdriver=cgroupfs",
		Scored:      true,
		Level:       2,
		References: []string{
			"https://docs.docker.com/config/containers/resource_constraints/",
		},
	})

	Register(Control{
		ID:          "2.10",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure base device size is not changed until needed",
		Severity:    finding.SeverityLow,
		Description: "The default base device size of 10GB is suitable for most use cases. Increasing it unnecessarily wastes resources.",
		Remediation: "Do not set --storage-opt dm.basesize unless required. Evaluate actual container storage needs first.",
		Scored:      true,
		Level:       2,
		References: []string{
			"https://docs.docker.com/storage/storagedriver/device-mapper-driver/",
		},
	})

	Register(Control{
		ID:          "2.11",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure that authorization for Docker client commands is enabled",
		Severity:    finding.SeverityHigh,
		Description: "Authorization plugins provide fine-grained access control for Docker commands, enforcing policies beyond basic authentication.",
		Remediation: "Use authorization plugin: dockerd --authorization-plugin=<plugin_name>",
		Scored:      true,
		Level:       2,
		References: []string{
			"https://docs.docker.com/engine/extend/plugins_authorization/",
		},
	})

	Register(Control{
		ID:          "2.12",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure centralized and remote logging is configured",
		Severity:    finding.SeverityMedium,
		Description: "Centralized logging enables security monitoring, incident response, and compliance. Logs should be sent to a remote system.",
		Remediation: "Configure remote logging driver: dockerd --log-driver=syslog --log-opt syslog-address=tcp://192.x.x.x:514",
		Scored:      true,
		Level:       2,
		References: []string{
			"https://docs.docker.com/config/containers/logging/configure/",
		},
	})

	Register(Control{
		ID:          "2.13",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure live restore is enabled",
		Severity:    finding.SeverityLow,
		Description: "Live restore keeps containers running when the Docker daemon is unavailable, improving availability.",
		Remediation: "Enable live restore: dockerd --live-restore or set live-restore: true in daemon.json.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/config/containers/live-restore/",
		},
	})

	Register(Control{
		ID:          "2.14",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure Userland Proxy is Disabled",
		Severity:    finding.SeverityLow,
		Description: "The userland proxy is slower than hairpin NAT mode and not needed in most environments.",
		Remediation: "Disable userland proxy: dockerd --userland-proxy=false or set userland-proxy: false in daemon.json.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/network/packet-filtering-firewalls/",
		},
	})

	Register(Control{
		ID:          "2.15",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure that a daemon-wide custom seccomp profile is applied if appropriate",
		Severity:    finding.SeverityMedium,
		Description: "Custom seccomp profiles can further restrict syscalls beyond Docker's default profile based on application needs.",
		Remediation: "Apply custom seccomp profile: dockerd --seccomp-profile=/path/to/seccomp/profile.json",
		Scored:      false,
		Level:       2,
		References: []string{
			"https://docs.docker.com/engine/security/seccomp/",
		},
	})

	Register(Control{
		ID:          "2.16",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure that experimental features are not used in production",
		Severity:    finding.SeverityMedium,
		Description: "Experimental features may be unstable and have security vulnerabilities. They should not be used in production.",
		Remediation: "Do not enable experimental features: Ensure experimental: false in daemon.json or no --experimental flag.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "2.17",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure containers are restricted from acquiring new privileges",
		Severity:    finding.SeverityHigh,
		Description: "The no-new-privileges flag prevents privilege escalation through setuid binaries and other mechanisms.",
		Remediation: "Set daemon-wide: dockerd --no-new-privileges or in daemon.json: no-new-privileges: true",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "2.18",
		Section:     "Docker Daemon Configuration",
		Title:       "Ensure that a daemon-wide custom AppArmor profile is applied if appropriate",
		Severity:    finding.SeverityMedium,
		Description: "Custom AppArmor profiles provide mandatory access control tailored to specific application requirements.",
		Remediation: "Load custom AppArmor profile and reference in daemon configuration if application requirements warrant it.",
		Scored:      false,
		Level:       2,
		References: []string{
			"https://docs.docker.com/engine/security/apparmor/",
		},
	})
}

func registerDaemonFilesControls() {
	Register(Control{
		ID:          "3.1",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the docker.service file ownership is set to root:root",
		Severity:    finding.SeverityHigh,
		Description: "The docker.service file contains Docker daemon configuration. Incorrect ownership could allow unauthorized modifications.",
		Remediation: "Set ownership to root:root: chown root:root /usr/lib/systemd/system/docker.service",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "3.2",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that docker.service file permissions are appropriately set",
		Severity:    finding.SeverityHigh,
		Description: "The docker.service file should not be writable by non-root users to prevent tampering.",
		Remediation: "Set permissions to 644 or more restrictive: chmod 644 /usr/lib/systemd/system/docker.service",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "3.3",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that docker.socket file ownership is set to root:root",
		Severity:    finding.SeverityHigh,
		Description: "The docker.socket file manages Docker socket activation. Incorrect ownership allows unauthorized modifications.",
		Remediation: "Set ownership to root:root: chown root:root /usr/lib/systemd/system/docker.socket",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "3.4",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that docker.socket file permissions are set to 644 or more restrictive",
		Severity:    finding.SeverityHigh,
		Description: "The docker.socket file should not be writable by non-root users.",
		Remediation: "Set permissions to 644 or more restrictive: chmod 644 /usr/lib/systemd/system/docker.socket",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "3.5",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the /etc/docker directory ownership is set to root:root",
		Severity:    finding.SeverityHigh,
		Description: "The /etc/docker directory contains Docker configuration including certificates and daemon configuration.",
		Remediation: "Set ownership to root:root: chown root:root /etc/docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "3.6",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that /etc/docker directory permissions are set to 755 or more restrictive",
		Severity:    finding.SeverityHigh,
		Description: "The /etc/docker directory should not be writable by non-root users.",
		Remediation: "Set permissions to 755 or more restrictive: chmod 755 /etc/docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "3.7",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that registry certificate file ownership is set to root:root",
		Severity:    finding.SeverityHigh,
		Description: "Registry certificates authenticate communication with container registries and must be protected.",
		Remediation: "Set ownership to root:root for certificate files: chown root:root /etc/docker/certs.d/<registry>/*",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/certificates/",
		},
	})

	Register(Control{
		ID:          "3.8",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that registry certificate file permissions are set to 444 or more restrictive",
		Severity:    finding.SeverityHigh,
		Description: "Registry certificates should be readable but not writable to prevent tampering.",
		Remediation: "Set permissions to 444 or more restrictive: chmod 444 /etc/docker/certs.d/<registry>/*",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/certificates/",
		},
	})

	Register(Control{
		ID:          "3.9",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that TLS CA certificate file ownership is set to root:root",
		Severity:    finding.SeverityHigh,
		Description: "The TLS CA certificate validates Docker daemon TLS connections and must be protected.",
		Remediation: "Set ownership to root:root: chown root:root <CA_certificate_file>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/protect-access/",
		},
	})

	Register(Control{
		ID:          "3.10",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that TLS CA certificate file permissions are set to 444 or more restrictive",
		Severity:    finding.SeverityHigh,
		Description: "The TLS CA certificate should be readable but not writable.",
		Remediation: "Set permissions to 444 or more restrictive: chmod 444 <CA_certificate_file>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/protect-access/",
		},
	})

	Register(Control{
		ID:          "3.11",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that Docker server certificate file ownership is set to root:root",
		Severity:    finding.SeverityHigh,
		Description: "The Docker server certificate authenticates the daemon and must be protected.",
		Remediation: "Set ownership to root:root: chown root:root <server_certificate_file>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/protect-access/",
		},
	})

	Register(Control{
		ID:          "3.12",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the Docker server certificate file permissions are set to 444 or more restrictive",
		Severity:    finding.SeverityHigh,
		Description: "The Docker server certificate should be readable but not writable.",
		Remediation: "Set permissions to 444 or more restrictive: chmod 444 <server_certificate_file>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/protect-access/",
		},
	})

	Register(Control{
		ID:          "3.13",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the Docker server certificate key file ownership is set to root:root",
		Severity:    finding.SeverityCritical,
		Description: "The Docker server private key must be protected with strict ownership to prevent unauthorized access.",
		Remediation: "Set ownership to root:root: chown root:root <server_key_file>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/protect-access/",
		},
	})

	Register(Control{
		ID:          "3.14",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the Docker server certificate key file permissions are set to 400",
		Severity:    finding.SeverityCritical,
		Description: "The Docker server private key should only be readable by root.",
		Remediation: "Set permissions to 400: chmod 400 <server_key_file>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/protect-access/",
		},
	})

	Register(Control{
		ID:          "3.15",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the Docker socket file ownership is set to root:docker",
		Severity:    finding.SeverityHigh,
		Description: "The Docker socket file grants access to the Docker daemon and must have proper ownership.",
		Remediation: "Set ownership to root:docker: chown root:docker /var/run/docker.sock",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/install/linux-postinstall/",
		},
	})

	Register(Control{
		ID:          "3.16",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the Docker socket file permissions are set to 660 or more restrictive",
		Severity:    finding.SeverityHigh,
		Description: "The Docker socket should only be accessible by root and docker group members.",
		Remediation: "Set permissions to 660 or more restrictive: chmod 660 /var/run/docker.sock",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/install/linux-postinstall/",
		},
	})

	Register(Control{
		ID:          "3.17",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the daemon.json file ownership is set to root:root",
		Severity:    finding.SeverityHigh,
		Description: "The daemon.json file contains Docker daemon configuration and must be protected.",
		Remediation: "Set ownership to root:root: chown root:root /etc/docker/daemon.json",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-file",
		},
	})

	Register(Control{
		ID:          "3.18",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that daemon.json file permissions are set to 644 or more restrictive",
		Severity:    finding.SeverityHigh,
		Description: "The daemon.json file should not be writable by non-root users.",
		Remediation: "Set permissions to 644 or more restrictive: chmod 644 /etc/docker/daemon.json",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-file",
		},
	})

	Register(Control{
		ID:          "3.19",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the /etc/default/docker file ownership is set to root:root",
		Severity:    finding.SeverityHigh,
		Description: "The /etc/default/docker file may contain Docker daemon startup configuration.",
		Remediation: "Set ownership to root:root: chown root:root /etc/default/docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "3.20",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the /etc/default/docker file permissions are set to 644 or more restrictive",
		Severity:    finding.SeverityHigh,
		Description: "The /etc/default/docker file should not be writable by non-root users.",
		Remediation: "Set permissions to 644 or more restrictive: chmod 644 /etc/default/docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "3.21",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the /etc/sysconfig/docker file ownership is set to root:root",
		Severity:    finding.SeverityHigh,
		Description: "On Red Hat-based systems, /etc/sysconfig/docker may contain daemon configuration.",
		Remediation: "Set ownership to root:root: chown root:root /etc/sysconfig/docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "3.22",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the /etc/sysconfig/docker file permissions are set to 644 or more restrictive",
		Severity:    finding.SeverityHigh,
		Description: "The /etc/sysconfig/docker file should not be writable by non-root users.",
		Remediation: "Set permissions to 644 or more restrictive: chmod 644 /etc/sysconfig/docker",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/dockerd/",
		},
	})

	Register(Control{
		ID:          "3.23",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the Containerd socket file ownership is set to root:root",
		Severity:    finding.SeverityHigh,
		Description: "The containerd socket provides access to the container runtime and must be protected.",
		Remediation: "Set ownership to root:root: chown root:root /run/containerd/containerd.sock",
		Scored:      true,
		Level:       1,
		References:  []string{"https://containerd.io/docs/"},
	})

	Register(Control{
		ID:          "3.24",
		Section:     "Docker Daemon Configuration Files",
		Title:       "Ensure that the Containerd socket file permissions are set to 660 or more restrictive",
		Severity:    finding.SeverityHigh,
		Description: "The containerd socket should have restrictive permissions to prevent unauthorized access.",
		Remediation: "Set permissions to 660 or more restrictive: chmod 660 /run/containerd/containerd.sock",
		Scored:      true,
		Level:       1,
		References:  []string{"https://containerd.io/docs/"},
	})
}

func registerImageControls() {
	Register(Control{
		ID:          "4.1",
		Section:     "Container Images and Build Files",
		Title:       "Ensure that a user for the container has been created",
		Severity:    finding.SeverityHigh,
		Description: "Running containers as root increases the risk of container escape and host compromise. A dedicated non-root user should be created for the container.",
		Remediation: "Add USER instruction to Dockerfile: RUN useradd -r -u 1000 appuser && USER appuser",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
		},
	})

	Register(Control{
		ID:          "4.2",
		Section:     "Container Images and Build Files",
		Title:       "Ensure that containers use only trusted base images",
		Severity:    finding.SeverityHigh,
		Description: "Base images from untrusted sources may contain malware, backdoors, or vulnerabilities. Use official images or build from scratch.",
		Remediation: "Use official images from Docker Hub or build your own base images. Implement image scanning and approval processes.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/docker-hub/official_images/",
		},
	})

	Register(Control{
		ID:          "4.3",
		Section:     "Container Images and Build Files",
		Title:       "Ensure that unnecessary packages are not installed in the container",
		Severity:    finding.SeverityMedium,
		Description: "Every package increases the attack surface. Install only required packages and remove package managers after installation.",
		Remediation: "Use minimal base images like alpine. Remove unnecessary packages. Use multi-stage builds to exclude build dependencies.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#minimize-the-number-of-layers",
		},
	})

	Register(Control{
		ID:          "4.4",
		Section:     "Container Images and Build Files",
		Title:       "Ensure images are scanned and rebuilt to include security patches",
		Severity:    finding.SeverityHigh,
		Description: "Container images should be regularly scanned for vulnerabilities and rebuilt with security patches.",
		Remediation: "Implement automated image scanning in CI/CD pipelines. Rebuild images regularly with updated base images. Use tools like Trivy, Clair, or Docker Scan.",
		Scored:      false,
		Level:       1,
		References:  []string{"https://docs.docker.com/engine/scan/"},
	})

	Register(Control{
		ID:          "4.5",
		Section:     "Container Images and Build Files",
		Title:       "Ensure Content trust for Docker is Enabled",
		Severity:    finding.SeverityHigh,
		Description: "Content trust uses digital signatures to ensure image integrity and publisher authentication.",
		Remediation: "Enable Docker Content Trust: export DOCKER_CONTENT_TRUST=1. Sign images before pushing: docker trust sign <image>",
		Scored:      true,
		Level:       2,
		References: []string{
			"https://docs.docker.com/engine/security/trust/",
		},
	})

	Register(Control{
		ID:          "4.6",
		Section:     "Container Images and Build Files",
		Title:       "Ensure that HEALTHCHECK instructions have been added to container images",
		Severity:    finding.SeverityLow,
		Description: "Health checks allow Docker to detect when containers become unresponsive and restart them automatically.",
		Remediation: "Add HEALTHCHECK instruction to Dockerfile: HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/builder/#healthcheck",
		},
	})

	Register(Control{
		ID:          "4.7",
		Section:     "Container Images and Build Files",
		Title:       "Ensure update instructions are not used alone in Dockerfiles",
		Severity:    finding.SeverityLow,
		Description: "Separating update and install instructions can lead to caching issues and outdated packages being used.",
		Remediation: "Combine update and install in single RUN instruction: RUN apt-get update && apt-get install -y package && rm -rf /var/lib/apt/lists/*",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
		},
	})

	Register(Control{
		ID:          "4.8",
		Section:     "Container Images and Build Files",
		Title:       "Ensure setuid and setgid permissions are removed",
		Severity:    finding.SeverityMedium,
		Description: "Setuid and setgid binaries can be exploited for privilege escalation. Remove these permissions if not required.",
		Remediation: "Remove setuid/setgid bits: RUN find / -perm /6000 -type f -exec chmod a-s {} \\; || true",
		Scored:      false,
		Level:       2,
		References: []string{
			"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
		},
	})

	Register(Control{
		ID:          "4.9",
		Section:     "Container Images and Build Files",
		Title:       "Ensure that COPY is used instead of ADD in Dockerfiles",
		Severity:    finding.SeverityLow,
		Description: "ADD has implicit behavior with URLs and tar archives that can introduce security risks. COPY is more predictable.",
		Remediation: "Use COPY instead of ADD unless you need ADD's tar extraction or URL fetching features.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy",
		},
	})

	Register(Control{
		ID:          "4.10",
		Section:     "Container Images and Build Files",
		Title:       "Ensure secrets are not stored in Dockerfiles",
		Severity:    finding.SeverityCritical,
		Description: "Secrets in Dockerfiles are stored in image layers and can be extracted even after deletion. This exposes sensitive credentials.",
		Remediation: "Use Docker BuildKit secrets: RUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret. Or use runtime secrets via environment variables or volume mounts.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/develop/develop-images/build_enhancements/#new-docker-build-secret-information",
		},
	})

	Register(Control{
		ID:          "4.11",
		Section:     "Container Images and Build Files",
		Title:       "Ensure only verified packages are installed",
		Severity:    finding.SeverityHigh,
		Description: "Installing unverified packages can introduce malware or vulnerabilities. Always verify package signatures.",
		Remediation: "Use package manager verification features. For apt: apt-get install -y --no-install-recommends. For yum: check gpgcheck=1 in yum.conf.",
		Scored:      false,
		Level:       2,
		References: []string{
			"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
		},
	})
}

func registerContainerRuntimeControls() {
	Register(Control{
		ID:          "5.1",
		Section:     "Container Runtime",
		Title:       "Ensure that, if applicable, an AppArmor Profile is enabled",
		Severity:    finding.SeverityHigh,
		Description: "AppArmor protects the host OS and applications from security threats by restricting container capabilities and access to resources.",
		Remediation: "Run containers with an AppArmor profile: docker run --security-opt apparmor=docker-default <image>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/apparmor/",
		},
	})

	Register(Control{
		ID:          "5.2",
		Section:     "Container Runtime",
		Title:       "Ensure that, if applicable, SELinux security options are set",
		Severity:    finding.SeverityHigh,
		Description: "SELinux provides mandatory access control for containers. Security options should be configured when SELinux is enabled.",
		Remediation: "Run containers with SELinux options: docker run --security-opt label=level:s0:c100,c200 <image>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/run/#security-configuration",
		},
	})

	Register(Control{
		ID:          "5.3",
		Section:     "Container Runtime",
		Title:       "Ensure that Linux kernel capabilities are restricted within containers",
		Severity:    finding.SeverityHigh,
		Description: "By default, Docker starts containers with a restricted set of Linux kernel capabilities. Additional capabilities should not be added unless explicitly required.",
		Remediation: "Remove all capabilities and add only required ones: docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE <image>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
		},
	})

	Register(Control{
		ID:          "5.4",
		Section:     "Container Runtime",
		Title:       "Ensure that privileged containers are not used",
		Severity:    finding.SeverityCritical,
		Description: "Privileged containers have all Linux kernel capabilities and can access host devices. This effectively disables all security features and allows full host access.",
		Remediation: "Do not run containers with --privileged flag. Use specific capabilities or device access instead.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
		},
	})

	Register(Control{
		ID:          "5.5",
		Section:     "Container Runtime",
		Title:       "Ensure sensitive host system directories are not mounted on containers",
		Severity:    finding.SeverityCritical,
		Description: "Mounting sensitive host directories like /, /boot, /dev, /etc, /lib, /proc, /sys, or /usr can allow container escape and host compromise.",
		Remediation: "Do not mount sensitive host directories. Use Docker volumes for data persistence instead.",
		Scored:      true,
		Level:       1,
		References:  []string{"https://docs.docker.com/storage/volumes/"},
	})

	Register(Control{
		ID:          "5.6",
		Section:     "Container Runtime",
		Title:       "Ensure sshd is not run within containers",
		Severity:    finding.SeverityMedium,
		Description: "Running SSH daemon in containers contradicts container design principles and increases attack surface. Use docker exec for access instead.",
		Remediation: "Do not run sshd in containers. Use docker exec for administrative access. For multiple processes, use supervisord or similar.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/exec/",
		},
	})

	Register(Control{
		ID:          "5.7",
		Section:     "Container Runtime",
		Title:       "Ensure privileged ports are not mapped within containers",
		Severity:    finding.SeverityLow,
		Description: "Mapping privileged ports (below 1024) may require containers to run with elevated privileges, increasing risk.",
		Remediation: "Use non-privileged ports (1024+) and configure port forwarding externally if needed.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/config/containers/container-networking/",
		},
	})

	Register(Control{
		ID:          "5.8",
		Section:     "Container Runtime",
		Title:       "Ensure that only needed ports are open on the container",
		Severity:    finding.SeverityMedium,
		Description: "Every exposed port increases attack surface. Only expose ports that are actually required.",
		Remediation: "Review and minimize exposed ports. Remove unnecessary EXPOSE directives from Dockerfile. Use -p flag judiciously.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/builder/#expose",
		},
	})

	Register(Control{
		ID:          "5.9",
		Section:     "Container Runtime",
		Title:       "Ensure that the host's network namespace is not shared",
		Severity:    finding.SeverityHigh,
		Description: "Sharing the host's network namespace allows the container to access host network interfaces and listen on any port, bypassing network isolation.",
		Remediation: "Do not run containers with --network=host. Use bridge networking instead.",
		Scored:      true,
		Level:       1,
		References:  []string{"https://docs.docker.com/network/host/"},
	})

	Register(Control{
		ID:          "5.10",
		Section:     "Container Runtime",
		Title:       "Ensure that the memory usage for containers is limited",
		Severity:    finding.SeverityMedium,
		Description: "Without memory limits, a container can exhaust all available host memory, causing denial of service.",
		Remediation: "Run containers with --memory flag: docker run --memory 512m <image>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/config/containers/resource_constraints/#memory",
		},
	})

	Register(Control{
		ID:          "5.11",
		Section:     "Container Runtime",
		Title:       "Ensure that CPU priority is set appropriately on containers",
		Severity:    finding.SeverityMedium,
		Description: "Without CPU limits, a container can consume all available CPU resources, starving other containers and host processes.",
		Remediation: "Run containers with CPU constraints: docker run --cpus=0.5 <image> or --cpu-shares=512 <image>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/config/containers/resource_constraints/#cpu",
		},
	})

	Register(Control{
		ID:          "5.12",
		Section:     "Container Runtime",
		Title:       "Ensure that the container's root filesystem is mounted as read only",
		Severity:    finding.SeverityMedium,
		Description: "A read-only root filesystem prevents attackers from modifying container binaries or adding malware after compromise.",
		Remediation: "Run containers with --read-only flag: docker run --read-only --tmpfs /tmp <image>",
		Scored:      true,
		Level:       1,
		References:  []string{"https://docs.docker.com/storage/tmpfs/"},
	})

	Register(Control{
		ID:          "5.13",
		Section:     "Container Runtime",
		Title:       "Ensure that incoming container traffic is bound to a specific host interface",
		Severity:    finding.SeverityMedium,
		Description: "Binding to 0.0.0.0 exposes containers on all network interfaces. Bind to specific interfaces to reduce exposure.",
		Remediation: "Bind to specific interface: docker run -p 127.0.0.1:8080:80 <image>",
		Scored:      true,
		Level:       2,
		References: []string{
			"https://docs.docker.com/config/containers/container-networking/",
		},
	})

	Register(Control{
		ID:          "5.14",
		Section:     "Container Runtime",
		Title:       "Ensure that the 'on-failure' container restart policy is set to '5'",
		Severity:    finding.SeverityLow,
		Description: "Unlimited restart attempts can mask underlying issues and enable denial of service. Limit restart attempts.",
		Remediation: "Set restart policy: docker run --restart=on-failure:5 <image>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/config/containers/start-containers-automatically/",
		},
	})

	Register(Control{
		ID:          "5.15",
		Section:     "Container Runtime",
		Title:       "Ensure that the host's process namespace is not shared",
		Severity:    finding.SeverityHigh,
		Description: "Sharing the PID namespace with the host allows the container to see and send signals to all host processes, enabling attacks.",
		Remediation: "Do not run containers with --pid=host.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/run/#pid-settings---pid",
		},
	})

	Register(Control{
		ID:          "5.16",
		Section:     "Container Runtime",
		Title:       "Ensure that the host's IPC namespace is not shared",
		Severity:    finding.SeverityHigh,
		Description: "Sharing the IPC namespace with the host allows the container to access shared memory and semaphores on the host, enabling information disclosure.",
		Remediation: "Do not run containers with --ipc=host.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/run/#ipc-settings---ipc",
		},
	})

	Register(Control{
		ID:          "5.17",
		Section:     "Container Runtime",
		Title:       "Ensure that host devices are not directly exposed to containers",
		Severity:    finding.SeverityHigh,
		Description: "Exposing host devices to containers with --device gives containers direct hardware access, which can be exploited.",
		Remediation: "Avoid using --device flag unless absolutely necessary. Use character device whitelisting.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
		},
	})

	Register(Control{
		ID:          "5.18",
		Section:     "Container Runtime",
		Title:       "Ensure that the default ulimit is overwritten at runtime if needed",
		Severity:    finding.SeverityLow,
		Description: "Default ulimits may not be appropriate for all applications. Override them when necessary.",
		Remediation: "Set ulimits at runtime: docker run --ulimit nofile=1024:2048 <image>",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/run/#set-ulimits-in-container---ulimit",
		},
	})

	Register(Control{
		ID:          "5.19",
		Section:     "Container Runtime",
		Title:       "Ensure mount propagation mode is not set to shared",
		Severity:    finding.SeverityMedium,
		Description: "Shared mount propagation allows containers to modify host mounts, which can be exploited for container escape.",
		Remediation: "Use private or slave mount propagation: docker run -v /host:/container:slave <image>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/storage/bind-mounts/#configure-bind-propagation",
		},
	})

	Register(Control{
		ID:          "5.20",
		Section:     "Container Runtime",
		Title:       "Ensure that the host's UTS namespace is not shared",
		Severity:    finding.SeverityMedium,
		Description: "Sharing the UTS namespace with the host allows the container to change the hostname and domain name of the host system.",
		Remediation: "Do not run containers with --uts=host.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/run/#uts-settings---uts",
		},
	})

	Register(Control{
		ID:          "5.21",
		Section:     "Container Runtime",
		Title:       "Ensure the default seccomp profile is not Disabled",
		Severity:    finding.SeverityHigh,
		Description: "Seccomp filters restrict the system calls that can be made from a container, significantly reducing the attack surface.",
		Remediation: "Do not run containers with --security-opt seccomp=unconfined. Use default or custom seccomp profiles.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/seccomp/",
		},
	})

	Register(Control{
		ID:          "5.22",
		Section:     "Container Runtime",
		Title:       "Ensure that docker exec commands are not used with the privileged option",
		Severity:    finding.SeverityHigh,
		Description: "Using docker exec with --privileged grants full privileges inside the container, bypassing security controls.",
		Remediation: "Do not use docker exec --privileged. Use specific capabilities if needed.",
		Scored:      true,
		Level:       2,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/exec/",
		},
	})

	Register(Control{
		ID:          "5.23",
		Section:     "Container Runtime",
		Title:       "Ensure that docker exec commands are not used with the user=root option",
		Severity:    finding.SeverityMedium,
		Description: "Executing commands as root in containers should be avoided unless absolutely necessary.",
		Remediation: "Avoid docker exec --user=root. Use non-privileged users for exec operations.",
		Scored:      false,
		Level:       2,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/exec/",
		},
	})

	Register(Control{
		ID:          "5.24",
		Section:     "Container Runtime",
		Title:       "Ensure that cgroup usage is confirmed",
		Severity:    finding.SeverityLow,
		Description: "Cgroups should be properly configured to ensure resource limits are enforced.",
		Remediation: "Verify cgroup configuration: docker info | grep -i cgroup",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/config/containers/resource_constraints/",
		},
	})

	Register(Control{
		ID:          "5.25",
		Section:     "Container Runtime",
		Title:       "Ensure that the container is restricted from acquiring additional privileges",
		Severity:    finding.SeverityHigh,
		Description: "A process can gain new privileges through setuid/setgid binaries. The no-new-privileges flag prevents this escalation.",
		Remediation: "Run containers with --security-opt no-new-privileges: docker run --security-opt=no-new-privileges <image>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/run/#security-configuration",
		},
	})

	Register(Control{
		ID:          "5.26",
		Section:     "Container Runtime",
		Title:       "Ensure that container health is checked at runtime",
		Severity:    finding.SeverityLow,
		Description: "Health checks enable automatic detection and recovery from container failures.",
		Remediation: "Use --health-cmd at runtime or HEALTHCHECK in Dockerfile: docker run --health-cmd='curl -f http://localhost/ || exit 1' <image>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/run/#healthcheck",
		},
	})

	Register(Control{
		ID:          "5.27",
		Section:     "Container Runtime",
		Title:       "Ensure that Docker commands always make use of the latest version of their image",
		Severity:    finding.SeverityLow,
		Description: "Using specific image tags or digests ensures reproducibility and prevents unexpected changes from 'latest' tag updates.",
		Remediation: "Use specific image tags: docker run nginx:1.19 or image digests: docker run nginx@sha256:abc123...",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/pull/",
		},
	})

	Register(Control{
		ID:          "5.28",
		Section:     "Container Runtime",
		Title:       "Ensure that the PIDs cgroup limit is used",
		Severity:    finding.SeverityMedium,
		Description: "Without PID limits, a container can fork-bomb and exhaust the host's process table, causing denial of service.",
		Remediation: "Run containers with --pids-limit flag: docker run --pids-limit=100 <image>",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/config/containers/resource_constraints/#limit-a-containers-pids-resources",
		},
	})

	Register(Control{
		ID:          "5.29",
		Section:     "Container Runtime",
		Title:       "Ensure that Docker's default bridge 'docker0' is not used",
		Severity:    finding.SeverityMedium,
		Description: "The default docker0 bridge allows all containers to communicate. Use user-defined networks for better isolation and DNS resolution.",
		Remediation: "Create user-defined networks: docker network create mynet && docker run --network=mynet <image>",
		Scored:      false,
		Level:       2,
		References:  []string{"https://docs.docker.com/network/bridge/"},
	})

	Register(Control{
		ID:          "5.30",
		Section:     "Container Runtime",
		Title:       "Ensure that the host's user namespaces are not shared",
		Severity:    finding.SeverityHigh,
		Description: "Disabling user namespace remapping runs containers with host user IDs, increasing risk of container escape.",
		Remediation: "Do not run containers with --userns=host. Use user namespace remapping.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/userns-remap/",
		},
	})

	Register(Control{
		ID:          "5.31",
		Section:     "Container Runtime",
		Title:       "Ensure that the Docker socket is not mounted inside any containers",
		Severity:    finding.SeverityCritical,
		Description: "Mounting the Docker socket gives containers full control over the Docker daemon, enabling trivial container escape and host compromise.",
		Remediation: "Do not mount /var/run/docker.sock inside containers. Use alternative approaches like Docker-in-Docker or buildkit.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/security/security/#docker-daemon-attack-surface",
		},
	})
}

func registerSecurityOperationsControls() {
	Register(Control{
		ID:          "6.1",
		Section:     "Docker Security Operations",
		Title:       "Ensure that image sprawl is avoided",
		Severity:    finding.SeverityLow,
		Description: "Unused images waste disk space and may contain unpatched vulnerabilities. Regularly prune unused images.",
		Remediation: "Remove unused images regularly: docker image prune -a. Implement automated cleanup policies.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/image_prune/",
		},
	})

	Register(Control{
		ID:          "6.2",
		Section:     "Docker Security Operations",
		Title:       "Ensure that container sprawl is avoided",
		Severity:    finding.SeverityLow,
		Description: "Stopped containers consume disk space and may contain sensitive data in their filesystems. Regularly remove stopped containers.",
		Remediation: "Remove stopped containers: docker container prune. Implement automated cleanup policies.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/container_prune/",
		},
	})
}

func registerSwarmControls() {
	Register(Control{
		ID:          "7.1",
		Section:     "Docker Swarm Configuration",
		Title:       "Ensure swarm mode is not Enabled, if not needed",
		Severity:    finding.SeverityMedium,
		Description: "Docker Swarm mode introduces additional attack surface. Disable it if not required for orchestration.",
		Remediation: "Leave swarm if not needed: docker swarm leave --force",
		Scored:      true,
		Level:       1,
		References:  []string{"https://docs.docker.com/engine/swarm/"},
	})

	Register(Control{
		ID:          "7.2",
		Section:     "Docker Swarm Configuration",
		Title:       "Ensure that the minimum number of manager nodes have been created in a swarm",
		Severity:    finding.SeverityMedium,
		Description: "Manager nodes maintain swarm state. Use an odd number (3 or 5) for quorum and high availability.",
		Remediation: "Deploy 3 or 5 manager nodes for production swarms to ensure fault tolerance and quorum.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/swarm/admin_guide/",
		},
	})

	Register(Control{
		ID:          "7.3",
		Section:     "Docker Swarm Configuration",
		Title:       "Ensure that swarm services are bound to a specific host interface",
		Severity:    finding.SeverityMedium,
		Description: "Binding swarm services to all interfaces may expose them unnecessarily. Bind to specific interfaces.",
		Remediation: "Bind services to specific interfaces using --listen-addr when initializing or joining swarm.",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/swarm/swarm-tutorial/create-swarm/",
		},
	})

	Register(Control{
		ID:          "7.4",
		Section:     "Docker Swarm Configuration",
		Title:       "Ensure that data exchanged between containers is encrypted",
		Severity:    finding.SeverityHigh,
		Description: "Swarm overlay networks should use encryption to protect data in transit between nodes.",
		Remediation: "Enable overlay network encryption: docker network create --opt encrypted --driver overlay mynet",
		Scored:      false,
		Level:       1,
		References:  []string{"https://docs.docker.com/network/overlay/"},
	})

	Register(Control{
		ID:          "7.5",
		Section:     "Docker Swarm Configuration",
		Title:       "Ensure that Docker's secret management commands are used for managing secrets in a swarm cluster",
		Severity:    finding.SeverityHigh,
		Description: "Docker secrets provide secure secret distribution to swarm services. Use them instead of environment variables.",
		Remediation: "Create and use secrets: docker secret create my_secret secret.txt && docker service create --secret my_secret myimage",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/swarm/secrets/",
		},
	})

	Register(Control{
		ID:          "7.6",
		Section:     "Docker Swarm Configuration",
		Title:       "Ensure that swarm manager is run in auto-lock mode",
		Severity:    finding.SeverityHigh,
		Description: "Auto-lock mode protects swarm encryption keys at rest by requiring an unlock key to start the manager.",
		Remediation: "Enable auto-lock: docker swarm init --autolock or docker swarm update --autolock=true",
		Scored:      true,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/swarm/swarm_manager_locking/",
		},
	})

	Register(Control{
		ID:          "7.7",
		Section:     "Docker Swarm Configuration",
		Title:       "Ensure that the swarm manager auto-lock key is rotated periodically",
		Severity:    finding.SeverityMedium,
		Description: "Regular key rotation limits the impact of key compromise.",
		Remediation: "Rotate unlock key: docker swarm unlock-key --rotate",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/swarm/swarm_manager_locking/",
		},
	})

	Register(Control{
		ID:          "7.8",
		Section:     "Docker Swarm Configuration",
		Title:       "Ensure that node certificates are rotated as appropriate",
		Severity:    finding.SeverityMedium,
		Description: "Node certificates authenticate swarm nodes. Regular rotation limits exposure from compromised certificates.",
		Remediation: "Set certificate expiry: docker swarm update --cert-expiry 720h",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/swarm/how-swarm-mode-works/pki/",
		},
	})

	Register(Control{
		ID:          "7.9",
		Section:     "Docker Swarm Configuration",
		Title:       "Ensure that CA certificates are rotated as appropriate",
		Severity:    finding.SeverityHigh,
		Description: "The swarm CA certificate signs all node certificates. Rotate it periodically or after compromise.",
		Remediation: "Rotate CA certificate: docker swarm ca --rotate",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/swarm/how-swarm-mode-works/pki/",
		},
	})

	Register(Control{
		ID:          "7.10",
		Section:     "Docker Swarm Configuration",
		Title:       "Ensure that management plane traffic is separated from data plane traffic",
		Severity:    finding.SeverityMedium,
		Description: "Separating management and data plane traffic improves security and performance.",
		Remediation: "Use separate networks for management (--advertise-addr) and data plane traffic.",
		Scored:      false,
		Level:       1,
		References: []string{
			"https://docs.docker.com/engine/swarm/swarm-tutorial/",
		},
	})
}
