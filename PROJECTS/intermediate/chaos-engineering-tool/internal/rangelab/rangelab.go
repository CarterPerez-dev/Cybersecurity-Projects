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

	TLSGatewayName = "khaos-range-gateway-tls"

	DNSGatewayName = "khaos-range-gateway-dns"
	RogueName      = "khaos-range-rogue"
	ResolverName   = "khaos-range-resolver"

	// Pinned because `dns:` on the gateway and the resolver's zone are fixed at
	// container creation, so neither can be filled from a discovered address.
	ResolverAddress   = "10.244.244.5"
	DependencyAddress = "10.244.244.10"
	RogueAddress      = "10.244.244.20"

	// NOT a container name or a network alias: the target's own embedded
	// resolver answers those from its own table and never forwards them.
	DNSDependencyName = "dependency.khaos.test."

	DNSControlName = "control.khaos.invalid."

	IDPName            = "khaos-range-idp"
	LabelRange         = "khaos.range"
	FailModeOpen       = "open"
	FailModeShut       = "closed"
	FailModeStaleRearm = "stale-rearm"

	EnvGatewayPort  = "KHAOS_RANGE_GATEWAY_PORT"
	EnvProxiedPort  = "KHAOS_RANGE_PROXIED_PORT"
	EnvProxyPort    = "KHAOS_RANGE_PROXY_PORT"
	EnvVerifierPort = "KHAOS_RANGE_VERIFIER_PORT"
	EnvIdPPort      = "KHAOS_RANGE_IDP_PORT"
	EnvIssuer       = "KHAOS_RANGE_ISSUER"
	EnvFailMode     = "KHAOS_RANGE_FAIL_MODE"
	EnvCacheTTL     = "KHAOS_RANGE_CACHE_TTL"

	EnvTLSPort = "KHAOS_RANGE_TLS_PORT"

	EnvDNSPort       = "KHAOS_RANGE_DNS_PORT"
	EnvResolverNonce = "KHAOS_RANGE_RESOLVER_NONCE"

	EnvAuthorityPort  = "KHAOS_RANGE_AUTHORITY_PORT"
	EnvDependencyPort = "KHAOS_RANGE_TLS_DEPENDENCY_PORT"

	EnvDependency    = "KHAOS_RANGE_DEPENDENCY"
	EnvAuthorityBase = "KHAOS_RANGE_AUTHORITY_BASE"

	EnvCertHost = "KHAOS_RANGE_CERT_HOST"

	EnvTLSMode = "KHAOS_RANGE_TLS_MODE"

	composeDir  = "range"
	composeFile = "compose.yml"

	dockerBinary = "docker"
	loopback     = "127.0.0.1"

	// A conventional port is the one most likely already taken on the host.
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

	// The compose file requires every variable even for a teardown that creates
	// no resolver, or `range down` fails and the range cannot be removed at all.
	teardownNonce = "teardown"

	EnvComposeDir = "KHAOS_RANGE_DIR"
	EnvUpstream   = "KHAOS_RANGE_UPSTREAM"

	NetworkName = "khaos-range"

	errNoUpstream        = "%w: %s does not carry %s, so khaos cannot tell where that gateway looks for its dependency"
	errBadUpstream       = "%w: %s addresses its dependency as %q, which khaos cannot read as a host and port (%v)"
	errNoProxiedGateway  = "%w: this experiment injects through khaos's fault proxy, and the running range has no %s; bring the range down and up again to create it"
	errNoIssuer          = "%w: %s does not carry %s, so khaos cannot tell which issuer that gateway trusts"
	errBadIssuer         = "%w: %s trusts the issuer %q, which khaos cannot read as a host and port (%v)"
	errNoVerifierGateway = "%w: this experiment arms khaos's own identity provider, and the running range has no %s; bring the range down and up again to create it"
	errNoTLSGateway      = "%w: this experiment arms khaos's own certificate authority, and the running range has no %s; bring the range down and up again to create it"
	errNoDNSGateway      = "%w: this experiment arms khaos's chaos resolver, and the running range has no %s; bring the range down and up again to create it"
	errNoRangeResolver   = "%w: this experiment arms khaos's chaos resolver, and the running range has no %s; bring the range down and up again to create it"
)

// Lab is a located range. The khaos-side ports are chosen at `range up` rather
// than at run time, because a container's environment is fixed at creation.
type Lab struct {
	Dir          string
	Port         int
	ProxiedPort  int
	ProxyPort    int
	VerifierPort int
	IdPPort      int

	TLSPort        int
	AuthorityPort  int
	DependencyPort int

	DNSPort       int
	ResolverNonce string

	// Read back from the TLS gateway's own environment, never remembered.
	Dependency    string
	AuthorityBase string
	CertHost      string

	TLSMode string

	// Issuer is the EXACT string the gateway was configured with, which khaos
	// mints `iss` to match; the address khaos listens on is never that string.
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

		TLSPort:        ports.TLS,
		AuthorityPort:  ports.Authority,
		DependencyPort: ports.Dependency,

		DNSPort: ports.DNS,
	}, nil
}

type Ports struct {
	Gateway  int
	Proxied  int
	Proxy    int
	Verifier int
	IdP      int

	TLS        int
	Authority  int
	Dependency int

	// The resolver publishes NOTHING: it listens on 53 inside its own network
	// namespace, which is why that tier needs no capability.
	DNS int
}

// FreePorts picks every host port the range needs in one go, all distinct.
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

	for _, into := range []*int{
		&chosen.Gateway,
		&chosen.Proxied,
		&chosen.Proxy,
		&chosen.Verifier,
		&chosen.IdP,
		&chosen.TLS,
		&chosen.Authority,
		&chosen.Dependency,
		&chosen.DNS,
	} {
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

// VerifyOwned refuses any compose file that is not khaos's own, or pointing
// KHAOS_RANGE_DIR elsewhere makes `range down` destroy another project.
func VerifyOwned(path string) error {
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

func (l Lab) ProxiedGatewayURL() string {
	return "http://" + net.JoinHostPort(loopback, strconv.Itoa(l.ProxiedPort))
}

func (l Lab) ProxiedProtectedURL() string {
	return l.ProxiedGatewayURL() + protectedPath
}

func (l Lab) Up(
	ctx context.Context,
	out io.Writer,
	failMode, cacheTTL, tlsMode string,
) error {
	environ := append(os.Environ(),
		EnvGatewayPort+"="+strconv.Itoa(l.Port),
		EnvProxiedPort+"="+strconv.Itoa(l.ProxiedPort),
		EnvProxyPort+"="+strconv.Itoa(l.ProxyPort),
		EnvVerifierPort+"="+strconv.Itoa(l.VerifierPort),
		EnvIdPPort+"="+strconv.Itoa(l.IdPPort),
		EnvTLSPort+"="+strconv.Itoa(l.TLSPort),
		EnvAuthorityPort+"="+strconv.Itoa(l.AuthorityPort),
		EnvDependencyPort+"="+strconv.Itoa(l.DependencyPort),
		EnvDNSPort+"="+strconv.Itoa(l.DNSPort),
		EnvResolverNonce+"="+l.ResolverNonce,
		EnvFailMode+"="+failMode,
		EnvCacheTTL+"="+cacheTTL,
		EnvTLSMode+"="+tlsMode,
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
	environ := append(os.Environ(),
		EnvGatewayPort+"="+strconv.Itoa(teardownPort),
		EnvProxiedPort+"="+strconv.Itoa(teardownPort),
		EnvProxyPort+"="+strconv.Itoa(teardownPort),
		EnvVerifierPort+"="+strconv.Itoa(teardownPort),
		EnvIdPPort+"="+strconv.Itoa(teardownPort),
		EnvTLSPort+"="+strconv.Itoa(teardownPort),
		EnvDNSPort+"="+strconv.Itoa(teardownPort),
		EnvResolverNonce+"="+teardownNonce,
		EnvAuthorityPort+"="+strconv.Itoa(teardownPort),
		EnvDependencyPort+"="+strconv.Itoa(teardownPort),
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
	// Passed explicitly as well as declared, so no edit to the file can point
	// these commands at another project.
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
	cmd.Stderr = io.MultiWriter(out, &stderr)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf(errCompose, args[0], lastLines(stderr.String()), err)
	}

	return nil
}

// PortTaken reports whether a host port was bound between khaos testing it and
// compose binding it.
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

	// Each further gateway is discovered separately and its absence is not
	// fatal, because the experiments that do not need it must still work.
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

	tlsGateway, ok := running[TLSGatewayName]
	if !ok {
		return lab, nil
	}

	if lab.TLSPort, err = reader.PublishedPort(
		ctx,
		tlsGateway.ID,
		GatewayInternalPort,
	); err != nil {
		return Lab{}, err
	}

	if err = lab.readAuthorityWiring(
		ctx,
		reader,
		tlsGateway.ID,
	); err != nil {
		return Lab{}, err
	}

	if err = lab.readDNSTier(ctx, reader, running); err != nil {
		return Lab{}, err
	}

	return lab, nil
}

func (l *Lab) readDNSTier(
	ctx context.Context,
	reader PortReader,
	running map[string]dockerx.Target,
) error {
	dnsGateway, ok := running[DNSGatewayName]
	if !ok {
		return nil
	}

	port, err := reader.PublishedPort(ctx, dnsGateway.ID, GatewayInternalPort)
	if err != nil {
		return err
	}

	l.DNSPort = port

	return nil
}

func (l *Lab) readAuthorityWiring(
	ctx context.Context,
	reader PortReader,
	containerID string,
) error {
	environ, err := reader.ContainerEnv(ctx, containerID)
	if err != nil {
		return err
	}

	for _, want := range []struct {
		key  string
		into *string
	}{
		{EnvDependency, &l.Dependency},
		{EnvAuthorityBase, &l.AuthorityBase},
		{EnvCertHost, &l.CertHost},
	} {
		value := environ[want.key]
		if value == "" {
			return fmt.Errorf(
				errNoIssuer,
				ErrRangeIncomplete,
				TLSGatewayName,
				want.key,
			)
		}

		*want.into = value
	}

	// Optional: the gateway has a working default for this one.
	l.TLSMode = environ[EnvTLSMode]

	return nil
}

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

func (l Lab) VerifierGatewayURL() string {
	return "http://" + net.JoinHostPort(loopback, strconv.Itoa(l.VerifierPort))
}

func (l Lab) VerifierProtectedURL() string {
	return l.VerifierGatewayURL() + protectedPath
}

func (l Lab) TLSGatewayURL() string {
	return "http://" + net.JoinHostPort(loopback, strconv.Itoa(l.TLSPort))
}

// RequireDNSTier refuses by name, because a missing gateway otherwise surfaces
// as a published port of zero and the run blames the target for not enforcing.
func (l Lab) RequireDNSTier() error {
	if l.DNSPort == 0 {
		return fmt.Errorf(
			errNoDNSGateway,
			ErrRangeIncomplete,
			DNSGatewayName,
		)
	}

	return nil
}

func (l Lab) DNSGatewayURL() string {
	return "http://" + net.JoinHostPort(loopback, strconv.Itoa(l.DNSPort))
}

func (l Lab) DNSProtectedURL() string {
	return l.DNSGatewayURL() + protectedPath
}

func (l Lab) RogueURL() string {
	return "http://" + net.JoinHostPort(RogueAddress, "8080")
}

func (l Lab) TLSProtectedURL() string {
	return l.TLSGatewayURL() + protectedPath
}

// AuthorityEndpoint binds on the DEFAULT bridge's gateway, since the range
// network's own gateway and loopback are both unreachable from a container.
func (l Lab) AuthorityEndpoint(
	ctx context.Context,
	reader PortReader,
) (AuthorityWiring, error) {
	if l.TLSPort == 0 || l.AuthorityBase == "" || l.CertHost == "" {
		return AuthorityWiring{}, fmt.Errorf(
			errNoTLSGateway,
			ErrRangeIncomplete,
			TLSGatewayName,
		)
	}

	gatewayIP, err := reader.BridgeGateway(ctx)
	if err != nil {
		return AuthorityWiring{}, err
	}

	dependencyPort, err := portOfURL(l.Dependency)
	if err != nil {
		return AuthorityWiring{}, err
	}

	basePort, err := portOfURL(l.AuthorityBase)
	if err != nil {
		return AuthorityWiring{}, err
	}

	return AuthorityWiring{
		Listen: net.JoinHostPort(gatewayIP, strconv.Itoa(basePort)),
		TLS:    net.JoinHostPort(gatewayIP, strconv.Itoa(dependencyPort)),
		Base:   l.AuthorityBase,
		Host:   l.CertHost,
	}, nil
}

// AuthorityWiring stands khaos's authority up where the gateway already looks.
type AuthorityWiring struct {
	Listen string
	TLS    string

	// The TARGET's own revocation URL and hostname, not derived from the above.
	Base string
	Host string
}

func portOfURL(raw string) (int, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return 0, fmt.Errorf(
			errBadUpstream,
			ErrRangeIncomplete,
			TLSGatewayName,
			raw,
			err,
		)
	}

	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port <= 0 {
		return 0, fmt.Errorf(
			errBadUpstream,
			ErrRangeIncomplete,
			TLSGatewayName,
			raw,
			err,
		)
	}

	return port, nil
}

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

// AuthorityURL is khaos's OWN path to the provider, which is why an identity
// experiment severs the target's path instead of pausing the provider.
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

// ProxyEndpoint says where khaos binds its fault proxy, never a wildcard: that
// would expose a deliberately vulnerable stack on the operator's network.
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
