// ©AngelaMos | 2026
// target.go

package dockerx

const (
	LabelConsent = "khaos.target"
	ConsentValue = "true"

	LabelComposeProject = "com.docker.compose.project"
	LabelComposeService = "com.docker.compose.service"
)

const (
	NetworkModeHost         = "host"
	NetworkModeContainerPfx = "container:"
	ModeHost                = "host"
)

const capPrefix = "CAP_"

var dangerousCapabilities = map[string]string{
	"ALL":             "every capability the kernel offers",
	"SYS_ADMIN":       "mount, namespace and cgroup control, which is close to root on the host",
	"SYS_MODULE":      "loading kernel modules, which is root on the host",
	"SYS_RAWIO":       "raw I/O port and memory access",
	"SYS_PTRACE":      "tracing and injecting into other processes",
	"DAC_READ_SEARCH": "reading any file on the host regardless of permissions",
	"BPF":             "loading BPF programs into the kernel",
	"NET_ADMIN":       "reconfiguring networking beyond its own namespace",
	"NET_RAW":         "raw sockets, which also lets it observe the probe traffic khaos measures",
}

const (
	DockerSocketPath = "/var/run/docker.sock"
	runSocketPath    = "/run/docker.sock"
	daemonStatePath  = "/var/lib/docker"
	daemonVolumePath = "/var/lib/docker/volumes"
	volumeDataDir    = "_data"
	tmpfsType        = "tmpfs"
	socketBaseName   = "docker.sock"
)

const ShortIDLen = 12

type Target struct {
	ID           string
	Name         string
	Image        string
	ImageID      string
	Project      string
	Service      string
	Labels       map[string]string
	Running      bool
	NetworkMode  string
	PidMode      string
	IpcMode      string
	UsernsMode   string
	Privileged   bool
	Capabilities []string
	Devices      []string
	SecurityOpt  []string
	BindSources  []string

	// Mounts is every mount with its type and destination, which is what the
	// mutator tier needs to reach a file inside one. BindSources carries only
	// the sources, because the refusal predicates judge by resolved path.
	Mounts         []Mount
	NamespacePeers []string
	Inspected      bool
}

func (t Target) Consented() bool {
	return t.Labels[LabelConsent] == ConsentValue
}

func (t Target) Short() string {
	return ShortID(t.ID)
}

func ShortID(id string) string {
	if len(id) > ShortIDLen {
		return id[:ShortIDLen]
	}
	return id
}

type Filter struct {
	Project string
}

type Guard struct {
	Project    string
	SelfID     string
	ExpectedID string
}
