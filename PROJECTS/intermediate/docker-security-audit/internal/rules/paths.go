/*
AngelaMos | 2026
paths.go
*/

package rules

import (
	"strings"

	"github.com/CarterPerez-dev/docksec/internal/finding"
)

type PathInfo struct {
	Severity    finding.Severity
	Description string
}

var DockerSocketPaths = map[string]PathInfo{
	// Docker sockets
	"/var/run/docker.sock": {
		Severity:    finding.SeverityCritical,
		Description: "Docker daemon socket. Full control over Docker, container escape possible.",
	},
	"/run/docker.sock": {
		Severity:    finding.SeverityCritical,
		Description: "Docker daemon socket (alternate path). Full control over Docker.",
	},
	"/var/run/docker": {
		Severity:    finding.SeverityCritical,
		Description: "Docker runtime directory. May contain socket or sensitive data.",
	},
	"/run/docker": {
		Severity:    finding.SeverityCritical,
		Description: "Docker runtime directory (alternate path).",
	},

	// Containerd sockets
	"/var/run/containerd/containerd.sock": {
		Severity:    finding.SeverityCritical,
		Description: "Containerd socket. Direct container runtime access.",
	},
	"/run/containerd/containerd.sock": {
		Severity:    finding.SeverityCritical,
		Description: "Containerd socket (alternate path).",
	},

	// CRI-O sockets
	"/var/run/crio/crio.sock": {
		Severity:    finding.SeverityCritical,
		Description: "CRI-O socket. Direct container runtime access.",
	},
	"/run/crio/crio.sock": {
		Severity:    finding.SeverityCritical,
		Description: "CRI-O socket (alternate path).",
	},

	// Podman sockets
	"/var/run/podman/podman.sock": {
		Severity:    finding.SeverityCritical,
		Description: "Podman socket. Container management access.",
	},
	"/run/podman/podman.sock": {
		Severity:    finding.SeverityCritical,
		Description: "Podman socket (alternate path).",
	},
	"/var/run/user/1000/podman/podman.sock": {
		Severity:    finding.SeverityCritical,
		Description: "Rootless Podman socket. Container management access.",
	},

	// Additional container runtimes
	"/var/run/cri-dockerd.sock": {
		Severity:    finding.SeverityCritical,
		Description: "CRI-dockerd socket. Docker CRI implementation.",
	},
	"/run/cri-dockerd.sock": {
		Severity:    finding.SeverityCritical,
		Description: "CRI-dockerd socket (alternate path).",
	},
	"/var/run/rkt/api-service.sock": {
		Severity:    finding.SeverityCritical,
		Description: "rkt container runtime socket.",
	},
}

var SensitiveHostPaths = map[string]PathInfo{
	// Root and core system directories
	"/": {
		Severity:    finding.SeverityCritical,
		Description: "Host root filesystem. Complete host access.",
	},

	// System configuration
	"/etc": {
		Severity:    finding.SeverityCritical,
		Description: "Host configuration directory. Contains passwords, keys, configs.",
	},
	"/etc/passwd": {
		Severity:    finding.SeverityHigh,
		Description: "User account information.",
	},
	"/etc/shadow": {
		Severity:    finding.SeverityCritical,
		Description: "Password hashes. Direct credential access.",
	},
	"/etc/group": {
		Severity:    finding.SeverityHigh,
		Description: "Group membership information.",
	},
	"/etc/gshadow": {
		Severity:    finding.SeverityCritical,
		Description: "Group password hashes.",
	},
	"/etc/sudoers": {
		Severity:    finding.SeverityCritical,
		Description: "Sudo configuration. Privilege escalation risk.",
	},
	"/etc/sudoers.d": {
		Severity:    finding.SeverityCritical,
		Description: "Additional sudo configuration files.",
	},
	"/etc/pam.d": {
		Severity:    finding.SeverityCritical,
		Description: "PAM authentication configuration.",
	},
	"/etc/security": {
		Severity:    finding.SeverityCritical,
		Description: "Security policies and limits configuration.",
	},
	"/etc/ssh": {
		Severity:    finding.SeverityCritical,
		Description: "SSH configuration and host keys.",
	},
	"/etc/ssl": {
		Severity:    finding.SeverityCritical,
		Description: "SSL certificates and private keys.",
	},
	"/etc/pki": {
		Severity:    finding.SeverityCritical,
		Description: "PKI certificates and keys.",
	},

	// Container and orchestration configs
	"/etc/kubernetes": {
		Severity:    finding.SeverityCritical,
		Description: "Kubernetes configuration files.",
	},
	"/etc/kubernetes/pki": {
		Severity:    finding.SeverityCritical,
		Description: "Kubernetes PKI certificates and keys. Cluster compromise possible.",
	},
	"/etc/kubernetes/manifests": {
		Severity:    finding.SeverityCritical,
		Description: "Static pod manifests. Control plane component access.",
	},
	"/etc/kubernetes/admin.conf": {
		Severity:    finding.SeverityCritical,
		Description: "Kubernetes admin kubeconfig. Full cluster access.",
	},
	"/etc/kubernetes/kubelet.conf": {
		Severity:    finding.SeverityCritical,
		Description: "Kubelet authentication configuration.",
	},
	"/etc/kubernetes/controller-manager.conf": {
		Severity:    finding.SeverityCritical,
		Description: "Controller manager authentication configuration.",
	},
	"/etc/kubernetes/scheduler.conf": {
		Severity:    finding.SeverityCritical,
		Description: "Scheduler authentication configuration.",
	},
	"/etc/docker": {
		Severity:    finding.SeverityHigh,
		Description: "Docker daemon configuration.",
	},
	"/etc/containerd": {
		Severity:    finding.SeverityHigh,
		Description: "Containerd runtime configuration.",
	},
	"/etc/crio": {
		Severity:    finding.SeverityHigh,
		Description: "CRI-O runtime configuration.",
	},
	"/etc/podman": {
		Severity:    finding.SeverityHigh,
		Description: "Podman configuration directory.",
	},

	// Service mesh configurations
	"/etc/istio": {
		Severity:    finding.SeverityCritical,
		Description: "Istio service mesh configuration.",
	},
	"/etc/consul": {
		Severity:    finding.SeverityCritical,
		Description: "Consul configuration and secrets.",
	},
	"/etc/linkerd": {
		Severity:    finding.SeverityCritical,
		Description: "Linkerd service mesh configuration.",
	},
	"/etc/envoy": {
		Severity:    finding.SeverityHigh,
		Description: "Envoy proxy configuration.",
	},

	// Cloud provider agent configs
	"/etc/amazon": {
		Severity:    finding.SeverityCritical,
		Description: "AWS agent configurations.",
	},
	"/etc/google": {
		Severity:    finding.SeverityCritical,
		Description: "GCP agent configurations.",
	},
	"/etc/azure": {
		Severity:    finding.SeverityCritical,
		Description: "Azure agent configurations.",
	},

	// Systemd and init
	"/etc/systemd": {
		Severity:    finding.SeverityHigh,
		Description: "Systemd configuration. Service manipulation possible.",
	},
	"/etc/init.d": {
		Severity:    finding.SeverityHigh,
		Description: "Init scripts. Service manipulation possible.",
	},
	"/etc/rc.d": {
		Severity:    finding.SeverityHigh,
		Description: "Runlevel configuration scripts.",
	},

	// Cron and scheduled tasks
	"/etc/cron.d": {
		Severity:    finding.SeverityHigh,
		Description: "Cron job definitions. Scheduled code execution.",
	},
	"/etc/cron.daily": {
		Severity:    finding.SeverityHigh,
		Description: "Daily cron scripts.",
	},
	"/etc/cron.hourly": {
		Severity:    finding.SeverityHigh,
		Description: "Hourly cron scripts.",
	},
	"/etc/cron.weekly": {
		Severity:    finding.SeverityHigh,
		Description: "Weekly cron scripts.",
	},
	"/etc/cron.monthly": {
		Severity:    finding.SeverityHigh,
		Description: "Monthly cron scripts.",
	},
	"/etc/crontab": {
		Severity:    finding.SeverityHigh,
		Description: "System crontab file.",
	},

	// Root user directories
	"/root": {
		Severity:    finding.SeverityCritical,
		Description: "Root user home directory. May contain credentials and keys.",
	},
	"/root/.ssh": {
		Severity:    finding.SeverityCritical,
		Description: "Root SSH keys and configuration.",
	},
	"/root/.aws": {
		Severity:    finding.SeverityCritical,
		Description: "AWS credentials and configuration.",
	},
	"/root/.config/gcloud": {
		Severity:    finding.SeverityCritical,
		Description: "GCP credentials and configuration.",
	},
	"/root/.azure": {
		Severity:    finding.SeverityCritical,
		Description: "Azure credentials and configuration.",
	},
	"/root/.kube": {
		Severity:    finding.SeverityCritical,
		Description: "Kubernetes credentials and configuration.",
	},
	"/root/.docker": {
		Severity:    finding.SeverityHigh,
		Description: "Docker credentials and configuration.",
	},
	"/root/.gnupg": {
		Severity:    finding.SeverityCritical,
		Description: "GnuPG keys and configuration.",
	},
	"/root/.vault-token": {
		Severity:    finding.SeverityCritical,
		Description: "HashiCorp Vault authentication token.",
	},
	"/root/.npmrc": {
		Severity:    finding.SeverityHigh,
		Description: "NPM configuration. May contain auth tokens.",
	},
	"/root/.pypirc": {
		Severity:    finding.SeverityHigh,
		Description: "PyPI configuration. May contain auth tokens.",
	},
	"/root/.gem": {
		Severity:    finding.SeverityHigh,
		Description: "Ruby gem credentials.",
	},
	"/root/.netrc": {
		Severity:    finding.SeverityCritical,
		Description: "Network authentication credentials.",
	},
	"/root/.gitconfig": {
		Severity:    finding.SeverityMedium,
		Description: "Git configuration. May contain credentials.",
	},
	"/root/.git-credentials": {
		Severity:    finding.SeverityCritical,
		Description: "Git stored credentials.",
	},

	// Home directories
	"/home": {
		Severity:    finding.SeverityHigh,
		Description: "User home directories. May contain credentials.",
	},

	// Boot and kernel
	"/boot": {
		Severity:    finding.SeverityHigh,
		Description: "Boot configuration and kernel images.",
	},
	"/boot/grub": {
		Severity:    finding.SeverityHigh,
		Description: "GRUB bootloader configuration.",
	},
	"/boot/efi": {
		Severity:    finding.SeverityHigh,
		Description: "EFI boot configuration.",
	},

	// System libraries
	"/lib": {
		Severity:    finding.SeverityHigh,
		Description: "System libraries. Tampering enables code injection.",
	},
	"/lib64": {
		Severity:    finding.SeverityHigh,
		Description: "64-bit system libraries.",
	},
	"/lib32": {
		Severity:    finding.SeverityHigh,
		Description: "32-bit system libraries.",
	},
	"/usr": {
		Severity:    finding.SeverityHigh,
		Description: "User programs and data. Wide attack surface.",
	},
	"/usr/lib": {
		Severity:    finding.SeverityHigh,
		Description: "System libraries.",
	},
	"/usr/lib64": {
		Severity:    finding.SeverityHigh,
		Description: "64-bit system libraries.",
	},
	"/usr/bin": {
		Severity:    finding.SeverityHigh,
		Description: "User binaries. Tampering enables backdoors.",
	},
	"/usr/sbin": {
		Severity:    finding.SeverityHigh,
		Description: "System binaries.",
	},
	"/usr/local": {
		Severity:    finding.SeverityHigh,
		Description: "Locally installed software.",
	},
	"/bin": {
		Severity:    finding.SeverityHigh,
		Description: "Essential binaries. Tampering enables backdoors.",
	},
	"/sbin": {
		Severity:    finding.SeverityHigh,
		Description: "System binaries.",
	},

	// Proc and sys filesystems
	"/proc": {
		Severity:    finding.SeverityCritical,
		Description: "Process information. Can access other process memory and info.",
	},
	"/proc/1": {
		Severity:    finding.SeverityCritical,
		Description: "Init process. Host PID 1 access.",
	},
	"/proc/sys": {
		Severity:    finding.SeverityCritical,
		Description: "Kernel parameters. System configuration access.",
	},
	"/proc/sysrq-trigger": {
		Severity:    finding.SeverityCritical,
		Description: "System request trigger. Can crash or reboot host.",
	},
	"/proc/kcore": {
		Severity:    finding.SeverityCritical,
		Description: "Kernel memory image. Full kernel memory access.",
	},
	"/proc/kmsg": {
		Severity:    finding.SeverityHigh,
		Description: "Kernel message buffer.",
	},
	"/proc/kallsyms": {
		Severity:    finding.SeverityHigh,
		Description: "Kernel symbol table. Aids in exploitation.",
	},
	"/proc/modules": {
		Severity:    finding.SeverityHigh,
		Description: "Loaded kernel modules.",
	},
	"/sys": {
		Severity:    finding.SeverityCritical,
		Description: "Sysfs. Kernel and device configuration.",
	},
	"/sys/kernel": {
		Severity:    finding.SeverityCritical,
		Description: "Kernel parameters and configuration.",
	},
	"/sys/kernel/debug": {
		Severity:    finding.SeverityCritical,
		Description: "Kernel debugging interface.",
	},
	"/sys/fs/cgroup": {
		Severity:    finding.SeverityHigh,
		Description: "Cgroup filesystem. Container escape possible.",
	},
	"/sys/fs/bpf": {
		Severity:    finding.SeverityHigh,
		Description: "BPF filesystem. Kernel tracing and filtering.",
	},
	"/sys/class": {
		Severity:    finding.SeverityHigh,
		Description: "Device class information.",
	},
	"/sys/block": {
		Severity:    finding.SeverityHigh,
		Description: "Block device information.",
	},

	// Device files
	"/dev": {
		Severity:    finding.SeverityCritical,
		Description: "Device files. Direct hardware access.",
	},
	"/dev/mem": {
		Severity:    finding.SeverityCritical,
		Description: "Physical memory access.",
	},
	"/dev/kmem": {
		Severity:    finding.SeverityCritical,
		Description: "Kernel memory access.",
	},
	"/dev/sda": {
		Severity:    finding.SeverityCritical,
		Description: "Raw disk access.",
	},
	"/dev/sdb": {
		Severity:    finding.SeverityCritical,
		Description: "Raw disk access (secondary).",
	},
	"/dev/nvme0n1": {
		Severity:    finding.SeverityCritical,
		Description: "NVMe raw disk access.",
	},
	"/dev/disk": {
		Severity:    finding.SeverityCritical,
		Description: "Disk devices.",
	},
	"/dev/mapper": {
		Severity:    finding.SeverityCritical,
		Description: "Device mapper. Encrypted volume access.",
	},
	"/dev/dm-0": {
		Severity:    finding.SeverityCritical,
		Description: "Device mapper volume.",
	},
	"/dev/loop": {
		Severity:    finding.SeverityHigh,
		Description: "Loop devices. Mount filesystem images.",
	},
	"/dev/tty": {
		Severity:    finding.SeverityMedium,
		Description: "Terminal devices.",
	},
	"/dev/console": {
		Severity:    finding.SeverityHigh,
		Description: "System console device.",
	},
	"/dev/null": {
		Severity:    finding.SeverityLow,
		Description: "Null device (typically safe).",
	},
	"/dev/zero": {
		Severity:    finding.SeverityLow,
		Description: "Zero device (typically safe).",
	},
	"/dev/random": {
		Severity:    finding.SeverityLow,
		Description: "Random number generator (typically safe).",
	},
	"/dev/urandom": {
		Severity:    finding.SeverityLow,
		Description: "Urandom device (typically safe).",
	},
	"/dev/fuse": {
		Severity:    finding.SeverityHigh,
		Description: "FUSE device. Userspace filesystem mounting.",
	},
	"/dev/kvm": {
		Severity:    finding.SeverityCritical,
		Description: "KVM device. Hypervisor access.",
	},

	// Var directories
	"/var": {
		Severity:    finding.SeverityMedium,
		Description: "Variable data directory.",
	},
	"/var/log": {
		Severity:    finding.SeverityMedium,
		Description: "System logs. Information disclosure, log tampering.",
	},
	"/var/log/audit": {
		Severity:    finding.SeverityHigh,
		Description: "Audit logs. Security event tampering possible.",
	},
	"/var/log/journal": {
		Severity:    finding.SeverityHigh,
		Description: "Systemd journal logs.",
	},
	"/var/log/kern.log": {
		Severity:    finding.SeverityHigh,
		Description: "Kernel logs.",
	},
	"/var/log/auth.log": {
		Severity:    finding.SeverityHigh,
		Description: "Authentication logs.",
	},
	"/var/log/syslog": {
		Severity:    finding.SeverityMedium,
		Description: "System logs.",
	},

	// Docker data directories
	"/var/lib/docker": {
		Severity:    finding.SeverityCritical,
		Description: "Docker data directory. Access to all container data.",
	},
	"/var/lib/docker/volumes": {
		Severity:    finding.SeverityCritical,
		Description: "Docker volumes. Access to persistent container data.",
	},
	"/var/lib/docker/containers": {
		Severity:    finding.SeverityCritical,
		Description: "Docker container metadata and logs.",
	},
	"/var/lib/docker/overlay2": {
		Severity:    finding.SeverityCritical,
		Description: "Docker overlay2 storage driver data.",
	},
	"/var/lib/docker/image": {
		Severity:    finding.SeverityHigh,
		Description: "Docker image metadata.",
	},
	"/var/lib/docker/network": {
		Severity:    finding.SeverityHigh,
		Description: "Docker network configuration.",
	},

	// Container runtime data
	"/var/lib/containerd": {
		Severity:    finding.SeverityCritical,
		Description: "Containerd data directory.",
	},
	"/var/lib/crio": {
		Severity:    finding.SeverityCritical,
		Description: "CRI-O data directory.",
	},
	"/var/lib/containers": {
		Severity:    finding.SeverityCritical,
		Description: "Container storage directory (Podman/Buildah).",
	},

	// Kubernetes data directories
	"/var/lib/kubelet": {
		Severity:    finding.SeverityCritical,
		Description: "Kubelet data. Kubernetes node secrets.",
	},
	"/var/lib/kubelet/pods": {
		Severity:    finding.SeverityCritical,
		Description: "Kubelet pod data. Access to all pod volumes and secrets.",
	},
	"/var/lib/kubelet/pki": {
		Severity:    finding.SeverityCritical,
		Description: "Kubelet PKI certificates.",
	},
	"/var/lib/kubelet/kubeconfig": {
		Severity:    finding.SeverityCritical,
		Description: "Kubelet authentication configuration.",
	},
	"/var/lib/kubelet/config.yaml": {
		Severity:    finding.SeverityHigh,
		Description: "Kubelet configuration file.",
	},
	"/var/lib/etcd": {
		Severity:    finding.SeverityCritical,
		Description: "Etcd data. Kubernetes cluster state and secrets.",
	},
	"/var/lib/rancher": {
		Severity:    finding.SeverityCritical,
		Description: "Rancher data directory.",
	},
	"/var/lib/k0s": {
		Severity:    finding.SeverityCritical,
		Description: "k0s Kubernetes distribution data.",
	},
	"/var/lib/k3s": {
		Severity:    finding.SeverityCritical,
		Description: "k3s Kubernetes distribution data.",
	},
	"/var/lib/microk8s": {
		Severity:    finding.SeverityCritical,
		Description: "MicroK8s data directory.",
	},

	// Kubernetes runtime paths
	"/var/run/secrets": {
		Severity:    finding.SeverityCritical,
		Description: "Kubernetes pod secrets mount point.",
	},
	"/var/run/secrets/kubernetes.io": {
		Severity:    finding.SeverityCritical,
		Description: "Kubernetes service account tokens.",
	},
	"/var/run/secrets/kubernetes.io/serviceaccount": {
		Severity:    finding.SeverityCritical,
		Description: "Service account token, CA cert, and namespace.",
	},
	"/run/secrets": {
		Severity:    finding.SeverityCritical,
		Description: "Secrets mount point (alternate path).",
	},
	"/run/secrets/kubernetes.io": {
		Severity:    finding.SeverityCritical,
		Description: "Kubernetes service account tokens (alternate path).",
	},

	// CI/CD runner directories
	"/home/runner": {
		Severity:    finding.SeverityCritical,
		Description: "GitHub Actions runner home directory.",
	},
	"/home/runner/work": {
		Severity:    finding.SeverityHigh,
		Description: "GitHub Actions workspace.",
	},
	"/home/runner/.credentials": {
		Severity:    finding.SeverityCritical,
		Description: "GitHub Actions runner credentials.",
	},
	"/opt/actions-runner": {
		Severity:    finding.SeverityCritical,
		Description: "GitHub Actions runner installation.",
	},
	"/home/gitlab-runner": {
		Severity:    finding.SeverityCritical,
		Description: "GitLab Runner home directory.",
	},
	"/etc/gitlab-runner": {
		Severity:    finding.SeverityCritical,
		Description: "GitLab Runner configuration.",
	},
	"/opt/gitlab-runner": {
		Severity:    finding.SeverityCritical,
		Description: "GitLab Runner installation.",
	},
	"/var/lib/jenkins": {
		Severity:    finding.SeverityCritical,
		Description: "Jenkins data directory. Build secrets and credentials.",
	},
	"/var/jenkins_home": {
		Severity:    finding.SeverityCritical,
		Description: "Jenkins home directory (containerized).",
	},
	"/var/lib/buildkite-agent": {
		Severity:    finding.SeverityCritical,
		Description: "Buildkite agent data directory.",
	},
	"/var/lib/circleci": {
		Severity:    finding.SeverityCritical,
		Description: "CircleCI runner data directory.",
	},
	"/opt/circleci": {
		Severity:    finding.SeverityCritical,
		Description: "CircleCI runner installation.",
	},

	// Cloud provider agent paths
	"/var/lib/amazon": {
		Severity:    finding.SeverityCritical,
		Description: "AWS agent data directory.",
	},
	"/var/lib/amazon/ssm": {
		Severity:    finding.SeverityCritical,
		Description: "AWS Systems Manager agent data.",
	},
	"/opt/aws": {
		Severity:    finding.SeverityCritical,
		Description: "AWS tools and agents installation.",
	},
	"/opt/aws/ssm": {
		Severity:    finding.SeverityCritical,
		Description: "AWS Systems Manager agent.",
	},
	"/snap/amazon-ssm-agent": {
		Severity:    finding.SeverityCritical,
		Description: "AWS SSM agent (snap package).",
	},
	"/var/lib/google": {
		Severity:    finding.SeverityCritical,
		Description: "GCP agent data directory.",
	},
	"/var/lib/google-guest-agent": {
		Severity:    finding.SeverityCritical,
		Description: "GCP guest agent data.",
	},
	"/opt/google": {
		Severity:    finding.SeverityCritical,
		Description: "GCP tools installation.",
	},
	"/opt/google-cloud-sdk": {
		Severity:    finding.SeverityCritical,
		Description: "GCP SDK installation.",
	},
	"/var/lib/waagent": {
		Severity:    finding.SeverityCritical,
		Description: "Azure VM agent data.",
	},
	"/opt/microsoft": {
		Severity:    finding.SeverityCritical,
		Description: "Microsoft tools installation.",
	},
	"/opt/azure": {
		Severity:    finding.SeverityCritical,
		Description: "Azure tools installation.",
	},

	// Secrets managers and vaults
	"/var/lib/vault": {
		Severity:    finding.SeverityCritical,
		Description: "HashiCorp Vault data directory.",
	},
	"/etc/vault.d": {
		Severity:    finding.SeverityCritical,
		Description: "Vault configuration directory.",
	},
	"/opt/vault": {
		Severity:    finding.SeverityCritical,
		Description: "Vault installation directory.",
	},
	"/var/lib/conjur": {
		Severity:    finding.SeverityCritical,
		Description: "CyberArk Conjur data directory.",
	},
	"/etc/conjur": {
		Severity:    finding.SeverityCritical,
		Description: "Conjur configuration.",
	},
	"/var/run/secrets-store-csi": {
		Severity:    finding.SeverityCritical,
		Description: "Secrets Store CSI driver mount point.",
	},

	// Service mesh data directories
	"/var/lib/istio": {
		Severity:    finding.SeverityCritical,
		Description: "Istio data directory.",
	},
	"/var/run/secrets/istio": {
		Severity:    finding.SeverityCritical,
		Description: "Istio service mesh certificates and tokens.",
	},
	"/var/lib/consul": {
		Severity:    finding.SeverityCritical,
		Description: "Consul data directory. Service mesh secrets.",
	},
	"/opt/consul": {
		Severity:    finding.SeverityCritical,
		Description: "Consul installation directory.",
	},
	"/var/lib/linkerd": {
		Severity:    finding.SeverityCritical,
		Description: "Linkerd data directory.",
	},
	"/var/lib/envoy": {
		Severity:    finding.SeverityHigh,
		Description: "Envoy proxy data directory.",
	},

	// Logging and monitoring agents
	"/var/lib/fluent": {
		Severity:    finding.SeverityMedium,
		Description: "Fluentd data directory.",
	},
	"/etc/fluent": {
		Severity:    finding.SeverityMedium,
		Description: "Fluentd configuration.",
	},
	"/etc/td-agent": {
		Severity:    finding.SeverityMedium,
		Description: "td-agent (Fluentd) configuration.",
	},
	"/var/log/td-agent": {
		Severity:    finding.SeverityMedium,
		Description: "td-agent logs.",
	},
	"/etc/fluent-bit": {
		Severity:    finding.SeverityMedium,
		Description: "Fluent Bit configuration.",
	},
	"/var/lib/fluent-bit": {
		Severity:    finding.SeverityMedium,
		Description: "Fluent Bit data directory.",
	},
	"/etc/datadog-agent": {
		Severity:    finding.SeverityHigh,
		Description: "Datadog agent configuration. May contain API keys.",
	},
	"/opt/datadog-agent": {
		Severity:    finding.SeverityHigh,
		Description: "Datadog agent installation.",
	},
	"/var/lib/datadog-agent": {
		Severity:    finding.SeverityHigh,
		Description: "Datadog agent data directory.",
	},
	"/etc/newrelic": {
		Severity:    finding.SeverityHigh,
		Description: "New Relic agent configuration.",
	},
	"/var/lib/newrelic": {
		Severity:    finding.SeverityMedium,
		Description: "New Relic agent data.",
	},
	"/etc/prometheus": {
		Severity:    finding.SeverityMedium,
		Description: "Prometheus configuration.",
	},
	"/var/lib/prometheus": {
		Severity:    finding.SeverityMedium,
		Description: "Prometheus data directory.",
	},
	"/etc/grafana": {
		Severity:    finding.SeverityHigh,
		Description: "Grafana configuration. May contain credentials.",
	},
	"/var/lib/grafana": {
		Severity:    finding.SeverityHigh,
		Description: "Grafana data directory.",
	},
	"/var/log/elasticsearch": {
		Severity:    finding.SeverityMedium,
		Description: "Elasticsearch logs.",
	},
	"/var/lib/elasticsearch": {
		Severity:    finding.SeverityHigh,
		Description: "Elasticsearch data directory.",
	},
	"/etc/elasticsearch": {
		Severity:    finding.SeverityHigh,
		Description: "Elasticsearch configuration.",
	},
	"/var/lib/logstash": {
		Severity:    finding.SeverityMedium,
		Description: "Logstash data directory.",
	},
	"/etc/logstash": {
		Severity:    finding.SeverityMedium,
		Description: "Logstash configuration.",
	},
	"/var/lib/splunk": {
		Severity:    finding.SeverityHigh,
		Description: "Splunk data directory.",
	},
	"/opt/splunk": {
		Severity:    finding.SeverityHigh,
		Description: "Splunk installation directory.",
	},
	"/opt/splunkforwarder": {
		Severity:    finding.SeverityHigh,
		Description: "Splunk forwarder installation.",
	},

	// APM and tracing agents
	"/etc/jaeger": {
		Severity:    finding.SeverityMedium,
		Description: "Jaeger tracing configuration.",
	},
	"/var/lib/jaeger": {
		Severity:    finding.SeverityMedium,
		Description: "Jaeger data directory.",
	},
	"/etc/zipkin": {
		Severity:    finding.SeverityMedium,
		Description: "Zipkin tracing configuration.",
	},

	// Network and security tools
	"/var/lib/calico": {
		Severity:    finding.SeverityHigh,
		Description: "Calico CNI data directory.",
	},
	"/etc/cni": {
		Severity:    finding.SeverityHigh,
		Description: "CNI plugin configuration.",
	},
	"/opt/cni": {
		Severity:    finding.SeverityHigh,
		Description: "CNI plugin binaries.",
	},
	"/var/lib/cni": {
		Severity:    finding.SeverityHigh,
		Description: "CNI plugin data.",
	},
	"/etc/falco": {
		Severity:    finding.SeverityMedium,
		Description: "Falco runtime security configuration.",
	},
	"/var/lib/falco": {
		Severity:    finding.SeverityMedium,
		Description: "Falco data directory.",
	},
	"/var/lib/suricata": {
		Severity:    finding.SeverityMedium,
		Description: "Suricata IDS data.",
	},
	"/etc/suricata": {
		Severity:    finding.SeverityMedium,
		Description: "Suricata configuration.",
	},

	// Database directories (commonly mounted)
	"/var/lib/mysql": {
		Severity:    finding.SeverityHigh,
		Description: "MySQL/MariaDB data directory.",
	},
	"/var/lib/postgresql": {
		Severity:    finding.SeverityHigh,
		Description: "PostgreSQL data directory.",
	},
	"/var/lib/mongodb": {
		Severity:    finding.SeverityHigh,
		Description: "MongoDB data directory.",
	},
	"/var/lib/redis": {
		Severity:    finding.SeverityHigh,
		Description: "Redis data directory.",
	},

	// Systemd directories
	"/run/systemd": {
		Severity:    finding.SeverityHigh,
		Description: "Systemd runtime directory.",
	},
	"/var/lib/systemd": {
		Severity:    finding.SeverityHigh,
		Description: "Systemd data directory.",
	},
	"/usr/lib/systemd": {
		Severity:    finding.SeverityHigh,
		Description: "Systemd unit files and libraries.",
	},

	// Mount points
	"/mnt": {
		Severity:    finding.SeverityMedium,
		Description: "Mount points. May expose host filesystems.",
	},
	"/media": {
		Severity:    finding.SeverityMedium,
		Description: "Removable media. May expose external storage.",
	},
	"/mnt/wsl": {
		Severity:    finding.SeverityHigh,
		Description: "WSL mount point. Windows filesystem access from WSL.",
	},

	// Temporary directories
	"/tmp": {
		Severity:    finding.SeverityMedium,
		Description: "Temporary files. Information disclosure, privilege escalation.",
	},
	"/var/tmp": {
		Severity:    finding.SeverityMedium,
		Description: "Persistent temporary files.",
	},

	// SELinux and AppArmor
	"/etc/selinux": {
		Severity:    finding.SeverityHigh,
		Description: "SELinux configuration. Security policy manipulation.",
	},
	"/sys/fs/selinux": {
		Severity:    finding.SeverityHigh,
		Description: "SELinux filesystem.",
	},
	"/etc/apparmor": {
		Severity:    finding.SeverityHigh,
		Description: "AppArmor profiles.",
	},
	"/etc/apparmor.d": {
		Severity:    finding.SeverityHigh,
		Description: "AppArmor profile definitions.",
	},
	"/sys/kernel/security/apparmor": {
		Severity:    finding.SeverityHigh,
		Description: "AppArmor kernel interface.",
	},

	// Kernel modules
	"/lib/modules": {
		Severity:    finding.SeverityHigh,
		Description: "Kernel modules. Code execution in kernel space.",
	},
	"/usr/lib/modules": {
		Severity:    finding.SeverityHigh,
		Description: "Kernel modules (alternate path).",
	},

	// Firmware
	"/lib/firmware": {
		Severity:    finding.SeverityHigh,
		Description: "Hardware firmware files.",
	},
	"/usr/lib/firmware": {
		Severity:    finding.SeverityHigh,
		Description: "Hardware firmware files (alternate path).",
	},

	// Audit system
	"/var/log/audit/audit.log": {
		Severity:    finding.SeverityHigh,
		Description: "Linux audit log file.",
	},
	"/etc/audit": {
		Severity:    finding.SeverityHigh,
		Description: "Audit system configuration.",
	},

	// Swap and hibernation
	"/swap.img": {
		Severity:    finding.SeverityHigh,
		Description: "Swap file. May contain sensitive data from memory.",
	},
	"/swapfile": {
		Severity:    finding.SeverityHigh,
		Description: "Swap file (alternate name).",
	},
}

var sensitivePathLookup = func() map[string]struct{} {
	m := make(map[string]struct{})
	for path := range DockerSocketPaths {
		m[path] = struct{}{}
	}
	for path := range SensitiveHostPaths {
		m[path] = struct{}{}
	}
	return m
}()

var dockerSocketLookup = func() map[string]struct{} {
	m := make(map[string]struct{})
	for path := range DockerSocketPaths {
		m[path] = struct{}{}
	}
	return m
}()

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return "/"
	}
	return path
}

func IsSensitivePath(path string) bool {
	normalized := normalizePath(path)
	if _, exists := sensitivePathLookup[normalized]; exists {
		return true
	}
	for sensitivePath := range sensitivePathLookup {
		if strings.HasPrefix(normalized, sensitivePath+"/") {
			return true
		}
		if strings.HasPrefix(sensitivePath, normalized+"/") &&
			normalized != "/" {
			return true
		}
	}
	return false
}

func IsDockerSocket(path string) bool {
	normalized := normalizePath(path)
	if _, exists := dockerSocketLookup[normalized]; exists {
		return true
	}
	for socketPath := range dockerSocketLookup {
		if strings.HasPrefix(normalized, socketPath) {
			return true
		}
	}
	return false
}

func GetPathInfo(path string) (PathInfo, bool) {
	normalized := normalizePath(path)
	if info, ok := DockerSocketPaths[normalized]; ok {
		return info, true
	}
	if info, ok := SensitiveHostPaths[normalized]; ok {
		return info, true
	}
	return PathInfo{}, false
}

func GetPathSeverity(path string) finding.Severity {
	normalized := normalizePath(path)
	if info, ok := DockerSocketPaths[normalized]; ok {
		return info.Severity
	}
	if info, ok := SensitiveHostPaths[normalized]; ok {
		return info.Severity
	}
	for sensitivePath, info := range SensitiveHostPaths {
		if strings.HasPrefix(normalized, sensitivePath+"/") {
			return info.Severity
		}
	}
	for socketPath, info := range DockerSocketPaths {
		if strings.HasPrefix(normalized, socketPath) {
			return info.Severity
		}
	}
	return finding.SeverityLow
}
