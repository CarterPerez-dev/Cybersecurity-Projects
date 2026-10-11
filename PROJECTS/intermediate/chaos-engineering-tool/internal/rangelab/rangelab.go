// ©AngelaMos | 2026
// rangelab.go

package rangelab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
)

const (
	ProjectName         = "khaos-range"
	GatewayName         = "khaos-range-gateway"
	ProxiedGatewayName  = "khaos-range-gateway-proxied"
	VerifierGatewayName = "khaos-range-gateway-verifier"
	IDPName             = "khaos-range-idp"
	LabelRange          = "khaos.range"
	FailModeOpen        = "open"
	FailModeShut        = "closed"
	FailModeStaleRearm  = "stale-rearm"

	EnvGatewayPort  = "KHAOS_RANGE_GATEWAY_PORT"
	EnvProxiedPort  = "KHAOS_RANGE_PROXIED_PORT"
	EnvProxyPort    = "KHAOS_RANGE_PROXY_PORT"
	EnvVerifierPort = "KHAOS_RANGE_VERIFIER_PORT"
	EnvIdPPort      = "KHAOS_RANGE_IDP_PORT"
	EnvIssuer       = "KHAOS_RANGE_ISSUER"
	EnvFailMode     = "KHAOS_RANGE_FAIL_MODE"
	EnvCacheTTL     = "KHAOS_RANGE_CACHE_TTL"

	composeDir  = "range"
	composeFile = "compose.yml"

	dockerBinary = "docker"
	loopback     = "127.0.0.1"

	// Every host port khaos binds is a randomly chosen high one. The port a
	// service conventionally uses is the one most likely already taken.
	portFloor = 30000
	portCeil  = 60000
	portTries = 40

	readyTimeout  = 90 * time.Second
	readyInterval = 500 * time.Millisecond
	probeTimeout  = time.Second

	healthPath    = "/health"
	protectedPath = "/protected"
	tokenPath     = "/token"

	errNoCompose  = "cannot find the range compose file; run khaos from the project directory, or set %s to the directory holding khaos's own range/compose.yml"
	errUnreadable = "%w: %s could not be read: %v"
	errForeign    = "%w: %s declares the compose project %s, and khaos only ever acts on %s"

	commentMarker = "#"
	nameKey       = "name:"
	quoteChars    = "\"' "
	noProjectName = "no project name"
	projectFlag   = "-p"
	errNoPort     = "could not find a free host port between %d and %d"
	errNotReady   = "the range did not become ready within %s"
	errCompose    = "docker compose %s failed: %s (%w)"
	errPortTaken  = "port is already allocated"
	stderrLines   = 4
	teardownPort  = 1

	EnvComposeDir = "KHAOS_RANGE_DIR"
	EnvUpstream   = "KHAOS_RANGE_UPSTREAM"

	NetworkName = "khaos-range"

	errNoUpstream        = "%w: %s does not carry %s, so khaos cannot tell where that gateway looks for its dependency"
	errBadUpstream       = "%w: %s addresses its dependency as %q, which khaos cannot read as a host and port (%v)"
	errNoProxiedGateway  = "%w: this experiment injects through khaos's fault proxy, and the running range has no %s; bring the range down and up again to create it"
	errNoIssuer          = "%w: %s does not carry %s, so khaos cannot tell which issuer that gateway trusts"
	errBadIssuer         = "%w: %s trusts the issuer %q, which khaos cannot read as a host and port (%v)"
	errNoVerifierGateway = "%w: this experiment arms khaos's own identity provider, and the running range has no %s; bring the range down and up again to create it"
)

// Port is the direct gateway's published port. ProxiedPort is the second
// gateway's, the one whose upstream runs through khaos's fault proxy, and
// ProxyPort is where that gateway expects to find the proxy on the host.
// VerifierPort is the third gateway's, the one whose identity provider is khaos
// itself, and IdPPort is where that gateway expects to find khaos's in-process
// provider.
//
// Both khaos-side ports are chosen at `range up` rather than at run time,
// because extra_hosts and environment are fixed at container creation and
// cannot be changed on a running container. khaos then reads each one back out
// of the container that will dial it, because the container is the only
// authority on where it will actually look.
type Lab struct {
	Dir          string
	Port         int
	ProxiedPort  int
	ProxyPort    int
	VerifierPort int
	IdPPort      int

	// Issuer is the EXACT string the verifier gateway was configured with, read
	// back from its environment. khaos has to mint tokens whose `iss` matches it
	// character for character: khaos binds the bridge gateway's address and the
	// container addresses `host.docker.internal`, so the address khaos listens
	// on is never the string the target expects.
	Issuer string
}

func Locate(ports Ports) (Lab, error) {
	dir, err := composePath()
	if err != nil {
		return Lab{}, err
	}
	return Lab{
		Dir:          dir,
		Port:         ports.Gateway,
		ProxiedPort:  ports.Proxied,
		ProxyPort:    ports.Proxy,
		VerifierPort: ports.Verifier,
		IdPPort:      ports.IdP,
	}, nil
}

type Ports struct {
	Gateway  int
	Proxied  int
	Proxy    int
	Verifier int
	IdP      int
}

// FreePorts picks every host port the range needs in one go, all distinct. Each
// one is a random high port: the port a service conventionally uses is the one
// most likely already taken.
func FreePorts() (Ports, error) {
	taken := map[int]bool{}

	pick := func() (int, error) {
		for range portTries {
			port, err := FreePort()
			if err != nil {
				return 0, err
			}
			if taken[port] {
				continue
			}
			taken[port] = true
			return port, nil
		}
		return 0, fmt.Errorf(errNoPort, portFloor, portCeil)
	}

	chosen := Ports{}

	for _, into := range []*int{&chosen.Gateway, &chosen.Proxied, &chosen.Proxy, &chosen.Verifier, &chosen.IdP} {
		port, err := pick()
		if err != nil {
			return Ports{}, err
		}
		*into = port
	}

	return chosen, nil
}

func composePath() (string, error) {
	if dir := os.Getenv(EnvComposeDir); dir != "" {
		if err := VerifyOwned(filepath.Join(dir, composeFile)); err != nil {
			return "", err
		}
		return dir, nil
	}

	working, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for dir := working; ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, composeDir, composeFile)
		if err := VerifyOwned(candidate); err == nil {
			return filepath.Join(dir, composeDir), nil
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}

	return "", fmt.Errorf(errNoCompose, EnvComposeDir)
}

// VerifyOwned refuses any compose file that is not khaos's own. Without it,
// pointing KHAOS_RANGE_DIR at another project turns `khaos range down` into
// `docker compose down --volumes` against that project, which destroys its
// named volumes and reports success. khaos's own "set KHAOS_RANGE_DIR" error
// message is what teaches an operator to set that variable.
func VerifyOwned(path string) error {
	// This read IS the ownership guard. Refusing to open an operator-supplied
	// path here would mean khaos could never check whether it owns one.
	//nolint:gosec // reading it is the whole point of this function
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf(errUnreadable, ErrNotOurs, path, err)
	}

	declared := declaredProject(raw)
	if declared != ProjectName {
		return fmt.Errorf(
			errForeign,
			ErrNotOurs,
			path,
			orNone(declared),
			ProjectName,
		)
	}

	return nil
}

func declaredProject(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, commentMarker) {
			continue
		}
		value, ok := strings.CutPrefix(line, nameKey)
		if !ok {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), quoteChars)
	}
	return ""
}

func orNone(declared string) string {
	if declared == "" {
		return noProjectName
	}
	return declared
}

func FreePort() (int, error) {
	for range portTries {
		// A candidate, not a secret: the next statement actually binds it, and
		// an unpredictable guess is no likelier to be free than any other.
		//nolint:gosec // a bind candidate, immediately tested
		port := portFloor + rand.IntN(portCeil-portFloor)

		listener, err := net.Listen(
			"tcp",
			net.JoinHostPort(loopback, strconv.Itoa(port)),
		)
		if err != nil {
			continue
		}

		if err := listener.Close(); err != nil {
			continue
		}

		return port, nil
	}

	return 0, fmt.Errorf(errNoPort, portFloor, portCeil)
}

func (l Lab) GatewayURL() string {
	return "http://" + net.JoinHostPort(loopback, strconv.Itoa(l.Port))
}

func (l Lab) ProtectedURL() string {
	return l.GatewayURL() + protectedPath
}

// ProxiedGatewayURL addresses the gateway whose own upstream runs through khaos's
// fault proxy. A proxy-tier experiment probes this one, because it is the only
// service in the range whose dependency khaos sits in front of.
func (l Lab) ProxiedGatewayURL() string {
	return "http://" + net.JoinHostPort(loopback, strconv.Itoa(l.ProxiedPort))
}

func (l Lab) ProxiedProtectedURL() string {
	return l.ProxiedGatewayURL() + protectedPath
}

func (l Lab) Up(
	ctx context.Context,
	out io.Writer,
	failMode, cacheTTL string,
) error {
	environ := append(os.Environ(),
		EnvGatewayPort+"="+strconv.Itoa(l.Port),
		EnvProxiedPort+"="+strconv.Itoa(l.ProxiedPort),
		EnvProxyPort+"="+strconv.Itoa(l.ProxyPort),
		EnvVerifierPort+"="+strconv.Itoa(l.VerifierPort),
		EnvIdPPort+"="+strconv.Itoa(l.IdPPort),
		EnvFailMode+"="+failMode,
		EnvCacheTTL+"="+cacheTTL,
	)

	if err := l.compose(
		ctx,
		out,
		environ,
		"up",
		"--build",
		"--detach",
		"--wait",
	); err != nil {
		return err
	}

	return l.awaitReady(ctx)
}

func (l Lab) Down(ctx context.Context, out io.Writer) error {
	// The compose file requires every port variable so a bare `docker compose up`
	// cannot bind a fixed one. Tearing down binds nothing, so any value parses,
	// but every required variable must still be present or compose refuses to
	// read the file at all and the teardown fails for a reason that has nothing
	// to do with the teardown.
	environ := append(os.Environ(),
		EnvGatewayPort+"="+strconv.Itoa(teardownPort),
		EnvProxiedPort+"="+strconv.Itoa(teardownPort),
		EnvProxyPort+"="+strconv.Itoa(teardownPort),
		EnvVerifierPort+"="+strconv.Itoa(teardownPort),
		EnvIdPPort+"="+strconv.Itoa(teardownPort),
	)

	return l.compose(
		ctx,
		out,
		environ,
		"down",
		"--volumes",
		"--remove-orphans",
		"--rmi",
		"local",
	)
}

func (l Lab) compose(
	ctx context.Context,
	out io.Writer,
	environ []string,
	args ...string,
) error {
	// The project name is passed explicitly as well as declared in the file, so
	// no edit to the file can make these commands act on another project.
	full := append([]string{
		"compose",
		projectFlag, ProjectName,
		"-f", filepath.Join(l.Dir, composeFile),
	}, args...)

	var stderr bytes.Buffer

	//nolint:gosec // khaos driving its own compose file as the operator
	cmd := exec.CommandContext(ctx, dockerBinary, full...)
	cmd.Dir = l.Dir
	cmd.Env = environ
	cmd.Stdout = out
	// The diagnostic never goes to the progress stream: --quiet discards that,
	// and the one time an operator needs the cause is the time it failed.
	cmd.Stderr = io.MultiWriter(out, &stderr)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf(errCompose, args[0], lastLines(stderr.String()), err)
	}

	return nil
}

// PortTaken reports whether compose refused because the chosen host port was
// bound between khaos testing it and compose binding it.
func PortTaken(err error) bool {
	return err != nil && strings.Contains(err.Error(), errPortTaken)
}

func lastLines(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) > stderrLines {
		lines = lines[len(lines)-stderrLines:]
	}
	return strings.Join(lines, "; ")
}

func (l Lab) awaitReady(ctx context.Context) error {
	deadline := time.Now().Add(readyTimeout)
	client := &http.Client{Timeout: probeTimeout}

	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		response, err := client.Get(l.GatewayURL() + healthPath)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}

		time.Sleep(readyInterval)
	}

	return fmt.Errorf(errNotReady, readyTimeout)
}

// IssueToken asks the range for a credential its gateway will accept, so an
// experiment against the range needs no flags at all.
func (l Lab) IssueToken(ctx context.Context) (string, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		l.GatewayURL()+tokenPath,
		nil,
	)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: probeTimeout}

	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()

	var body struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return "", err
	}

	if body.Token == "" {
		return "", ErrNoToken
	}

	return body.Token, nil
}

var ErrNotOurs = errors.New("that compose file does not belong to khaos")

var ErrNoToken = errors.New("the range identity provider did not issue a token")

const GatewayInternalPort = 8080

type PortReader interface {
	Targets(
		ctx context.Context,
		filter dockerx.Filter,
	) ([]dockerx.Target, error)
	PublishedPort(
		ctx context.Context,
		containerID string,
		internal int,
	) (int, error)
	ContainerEnv(
		ctx context.Context,
		containerID string,
	) (map[string]string, error)
	NetworkAddress(
		ctx context.Context,
		containerID, networkName string,
	) (string, error)
	BridgeGateway(ctx context.Context) (string, error)
}

// Discover finds a running range and the host port it ended up on, so khaos can
// point an experiment at it without the operator repeating what khaos already
// knows.
func Discover(ctx context.Context, reader PortReader) (Lab, error) {
	targets, err := reader.Targets(ctx, dockerx.Filter{Project: ProjectName})
	if err != nil {
		return Lab{}, err
	}

	running := map[string]dockerx.Target{}
	for _, target := range targets {
		if target.Running {
			running[target.Name] = target
		}
	}

	gateway, ok := running[GatewayName]
	if !ok {
		return Lab{}, ErrNoRange
	}

	port, err := reader.PublishedPort(ctx, gateway.ID, GatewayInternalPort)
	if err != nil {
		return Lab{}, err
	}

	lab := Lab{Port: port}

	// The proxied gateway is discovered separately and its absence is not fatal:
	// a Docker-native experiment has no use for it, and failing the whole
	// discovery over it would break every experiment that does not need a proxy.
	proxied, ok := running[ProxiedGatewayName]
	if !ok {
		return lab, nil
	}

	if lab.ProxiedPort, err = reader.PublishedPort(
		ctx,
		proxied.ID,
		GatewayInternalPort,
	); err != nil {
		return Lab{}, err
	}

	if lab.ProxyPort, err = proxyPortOf(ctx, reader, proxied.ID); err != nil {
		return Lab{}, err
	}

	// The verifier gateway is discovered on the same terms: absent is not fatal,
	// because every experiment that does not arm khaos's own provider has no use
	// for it and failing the whole discovery over it would break all of them.
	verifierGateway, ok := running[VerifierGatewayName]
	if !ok {
		return lab, nil
	}

	if lab.VerifierPort, err = reader.PublishedPort(
		ctx,
		verifierGateway.ID,
		GatewayInternalPort,
	); err != nil {
		return Lab{}, err
	}

	if lab.Issuer, lab.IdPPort, err = issuerOf(
		ctx,
		reader,
		verifierGateway.ID,
	); err != nil {
		return Lab{}, err
	}

	return lab, nil
}

// issuerOf reads the issuer out of the verifier gateway's own environment rather
// than remembering what `range up` chose, for the same reason proxyPortOf does:
// the container is the only authority on what it will actually dial and on what
// `iss` it will accept.
//
// Both halves matter. The port is where khaos has to bind, and the STRING is
// what khaos has to put in every token it mints, character for character. khaos
// binds the bridge gateway's numeric address while the container addresses
// `host.docker.internal`, so khaos's own listener address is never the issuer
// the target expects, and minting under it would get every token refused on
// `iss` for a reason that has nothing to do with the trap under test.
func issuerOf(
	ctx context.Context,
	reader PortReader,
	containerID string,
) (string, int, error) {
	environ, err := reader.ContainerEnv(ctx, containerID)
	if err != nil {
		return "", 0, err
	}

	issuer := environ[EnvIssuer]
	if issuer == "" {
		return "", 0, fmt.Errorf(
			errNoIssuer,
			ErrRangeIncomplete,
			VerifierGatewayName,
			EnvIssuer,
		)
	}

	parsed, err := url.Parse(issuer)
	if err != nil {
		return "", 0, fmt.Errorf(
			errBadIssuer,
			ErrRangeIncomplete,
			VerifierGatewayName,
			issuer,
			err,
		)
	}

	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port <= 0 {
		return "", 0, fmt.Errorf(
			errBadIssuer,
			ErrRangeIncomplete,
			VerifierGatewayName,
			issuer,
			err,
		)
	}

	return strings.TrimSuffix(issuer, "/"), port, nil
}

// VerifierGatewayURL addresses the gateway whose identity provider is khaos
// itself. Every experiment that arms khaos's provider probes this one, because
// it is the only service in the range that resolves keys from khaos.
func (l Lab) VerifierGatewayURL() string {
	return "http://" + net.JoinHostPort(loopback, strconv.Itoa(l.VerifierPort))
}

func (l Lab) VerifierProtectedURL() string {
	return l.VerifierGatewayURL() + protectedPath
}

// IdPEndpoint says where khaos must bind its in-process identity provider and
// which issuer string it must mint under.
//
// The listen address is the DEFAULT bridge's gateway, discovered rather than
// assumed, which is the same measured fact the fault proxy rests on: a container
// reaches a host listener there, a listener on the target network's own gateway
// is unreachable, and binding only loopback leaves the provider dead to every
// container.
func (l Lab) IdPEndpoint(
	ctx context.Context,
	reader PortReader,
) (string, string, error) {
	if l.IdPPort == 0 || l.Issuer == "" {
		return "", "", fmt.Errorf(
			errNoVerifierGateway,
			ErrRangeIncomplete,
			VerifierGatewayName,
		)
	}

	gatewayIP, err := reader.BridgeGateway(ctx)
	if err != nil {
		return "", "", err
	}

	return net.JoinHostPort(gatewayIP, strconv.Itoa(l.IdPPort)), l.Issuer, nil
}

// proxyPortOf reads the port out of the proxied gateway's own upstream setting,
// rather than remembering what `range up` chose. The container's environment is
// the only authority on where that gateway will actually look for the proxy, and
// khaos has to bind the port the target is already addressing, not the port khaos
// would have picked.
func proxyPortOf(
	ctx context.Context,
	reader PortReader,
	containerID string,
) (int, error) {
	environ, err := reader.ContainerEnv(ctx, containerID)
	if err != nil {
		return 0, err
	}

	upstream := environ[EnvUpstream]
	if upstream == "" {
		return 0, fmt.Errorf(
			errNoUpstream,
			ErrRangeIncomplete,
			ProxiedGatewayName,
			EnvUpstream,
		)
	}

	parsed, err := url.Parse(upstream)
	if err != nil {
		return 0, fmt.Errorf(
			errBadUpstream,
			ErrRangeIncomplete,
			ProxiedGatewayName,
			upstream,
			err,
		)
	}

	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port <= 0 {
		return 0, fmt.Errorf(
			errBadUpstream,
			ErrRangeIncomplete,
			ProxiedGatewayName,
			upstream,
			err,
		)
	}

	return port, nil
}

// AuthorityURL is khaos's OWN path to the identity provider, bypassing whatever
// the target uses. It is the container's address on the range network, reachable
// from the host directly.
//
// This is what makes a revocation real and unreachable at the same time, and it
// is the reason an identity experiment severs the target's path with khaos's
// proxy rather than pausing the provider. A paused provider is unreachable by
// khaos too, so the change khaos needs to make at the authority could not be made
// at all, and the research is explicit that the revocation has to be real while
// the target cannot see it.
func (l Lab) AuthorityURL(
	ctx context.Context,
	reader PortReader,
) (string, error) {
	targets, err := reader.Targets(ctx, dockerx.Filter{Project: ProjectName})
	if err != nil {
		return "", err
	}

	for _, target := range targets {
		if target.Name != IDPName || !target.Running {
			continue
		}

		address, err := reader.NetworkAddress(ctx, target.ID, NetworkName)
		if err != nil {
			return "", err
		}

		return "http://" + net.JoinHostPort(
			address,
			strconv.Itoa(GatewayInternalPort),
		), nil
	}

	return "", ErrNoRange
}

// ProxyEndpoint says where khaos must bind its fault proxy and what that proxy
// must forward to.
//
// The listen address is the DEFAULT bridge's gateway, which is measured: a
// container reaches a host listener there, a listener on the target network's own
// gateway is unreachable, and binding that one address leaves the proxy dead on
// loopback and dead on the host's LAN address. A wildcard bind would put a fault
// proxy for a deliberately vulnerable stack on the operator's network.
func (l Lab) ProxyEndpoint(
	ctx context.Context,
	reader PortReader,
) (string, string, error) {
	if l.ProxyPort == 0 {
		return "", "", fmt.Errorf(
			errNoProxiedGateway,
			ErrRangeIncomplete,
			ProxiedGatewayName,
		)
	}

	gatewayIP, err := reader.BridgeGateway(ctx)
	if err != nil {
		return "", "", err
	}

	targets, err := reader.Targets(ctx, dockerx.Filter{Project: ProjectName})
	if err != nil {
		return "", "", err
	}

	for _, target := range targets {
		if target.Name != IDPName || !target.Running {
			continue
		}

		address, err := reader.NetworkAddress(ctx, target.ID, NetworkName)
		if err != nil {
			return "", "", err
		}

		listen := net.JoinHostPort(gatewayIP, strconv.Itoa(l.ProxyPort))
		upstream := net.JoinHostPort(address, strconv.Itoa(GatewayInternalPort))

		return listen, upstream, nil
	}

	return "", "", ErrNoRange
}

var ErrRangeIncomplete = errors.New(
	"the running range is missing the part this experiment needs",
)

var ErrNoRange = errors.New(
	"no running khaos range was found; start one with `khaos range up`, or point khaos at your own stack instead",
)
