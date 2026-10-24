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

	"github.com/CarterPerez-dev/khaos"
	"github.com/CarterPerez-dev/khaos/internal/dbx"
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

	IDPName = "khaos-range-idp"

	// The stateful tier, opt-in behind `range up --with-db`. These are the only
	// range services khaos does not implement itself.
	PostgresName      = "khaos-range-postgres"
	MySQLName         = "khaos-range-mysql"
	MariaDBName       = "khaos-range-mariadb"
	RedisName         = "khaos-range-redis"
	DBGatewayName     = "khaos-range-gateway-db"
	SecretGatewayName = "khaos-range-gateway-secret"
	EnvGatewayName    = "khaos-range-gateway-env"

	// The CALLER in the service-to-service experiment. It is the only fixture
	// whose dependency is not a container: khaos plays that itself.
	AuthzGatewayName = "khaos-range-gateway-authz"

	// The backend publishes nothing: khaos forwards to it by its address on
	// the range network.
	ControlGatewayName = "khaos-range-gateway-control"
	ControldName       = "khaos-range-controld"

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

	// Minted per `range up` rather than written into the compose file, so the
	// public repo carries no credential and khaos reads it back out of the
	// container that holds it.
	EnvDBPassword = "KHAOS_RANGE_DB_PASSWORD"

	// A SECOND secret for the role the pooled fixture authenticates with, so
	// rotating that role cannot touch the administrative credential khaos
	// performs the rotation with.
	EnvDBAppPassword = "KHAOS_RANGE_DB_APP_PASSWORD"
	EnvDBGatewayPort = "KHAOS_RANGE_DB_GATEWAY_PORT"
	EnvPoolMode      = "KHAOS_RANGE_POOL_MODE"
	EnvSecretPort    = "KHAOS_RANGE_SECRET_PORT"
	EnvSecretMode    = "KHAOS_RANGE_SECRET_MODE"
	EnvSecretValue   = "KHAOS_RANGE_SECRET_VALUE"
	EnvEnvPort       = "KHAOS_RANGE_ENV_PORT"

	// The caller's own port, and the port khaos's authorization dependency is
	// addressed on. The second is read back out of the container rather than
	// remembered, like every other address a fixture was created with.
	EnvAuthzPort = "KHAOS_RANGE_AUTHZ_PORT"
	EnvAuthzDep  = "KHAOS_RANGE_AUTHZ_DEP_PORT"
	EnvAuthzBase = "KHAOS_RANGE_AUTHZ_BASE"

	// One published port and one dependency port per control, read back out
	// of the gateway's own environment rather than remembered: the container
	// is the only authority on where it will actually dial.
	EnvControlPort       = "KHAOS_RANGE_CONTROL_PORT"
	EnvControlStorePort  = "KHAOS_RANGE_CONTROL_STORE_PORT"
	EnvControlPolicyPort = "KHAOS_RANGE_CONTROL_POLICY_PORT"
	EnvControlRulesPort  = "KHAOS_RANGE_CONTROL_RULES_PORT"

	EnvLimitStore  = "KHAOS_RANGE_LIMIT_STORE"
	EnvPolicyStore = "KHAOS_RANGE_POLICY_STORE"
	EnvRulesStore  = "KHAOS_RANGE_RULES_STORE"

	// The control gateway authenticates by SIGNATURE against this key rather
	// than from a set it remembers, because the cold-start experiment
	// restarts it and an in-memory set does not survive that.
	EnvControlSecret = "KHAOS_RANGE_CONTROL_SECRET"
	EnvAuthzMode     = "KHAOS_RANGE_AUTHZ_MODE"

	AuthzDistinguishes = "distinguishes"
	AuthzCollapses     = "collapses"
	AuthzRetries       = "retries"
	AuthzCached        = "cached"

	// EnvReresolve is whether the DNS gateway resolves its dependency's name on
	// every request. Both values are real target shapes: `reresolve` is a
	// client that opens a fresh connection per call, and `pinned` is the
	// DEFAULT behaviour of a Go service -- http.Transport resolves once when it
	// opens a connection and never again while that connection lives, measured
	// at two queries across forty-six requests. The rotation fault needs both.
	EnvReresolve = "KHAOS_RANGE_RERESOLVE"

	DNSReresolve = "reresolve"
	DNSPinned    = "pinned"

	// SecretVariable is the variable the environment faults take away, which
	// khaos names rather than discovers: the fixture is configured to read its
	// secret from exactly this one.
	SecretVariable = "KHAOS_RANGE_SECRET_VALUE"

	// AppRole is created by `range up` rather than by the engine's init hook,
	// because the hook needs a file in the image and the data directory is a
	// tmpfs. khaos has a SQL client of its own, so the fixture is seeded with
	// it.
	AppRole     = "appuser"
	AppDatabase = "appdb"

	// The secret the HMAC fixture verifies with, and the mount it arrives on.
	// khaos never reads the file: it asks the fixture for a credential.
	SecretPath = "/run/khaos-secrets/hmac"

	SecretValidated = "validated"
	SecretUnchecked = "unchecked"

	SecretsName = "khaos-range-secrets"

	secretTokenPath = "/secret-token"

	// Pinned in the compose file, which is also what lets khaos seed the role
	// before anything has read a published port.
	PostgresAddress = "10.244.244.30"
	postgresPort    = "5432"
	redisPort       = "6379"
	adminRole       = "postgres"

	PoolUnbounded = "unbounded"
	PoolBounded   = "bounded"
	PoolHeld      = "held"

	profileFlag = "--profile"
	dbProfile   = "db"

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
	readyPath     = "/ready"
	protectedPath = "/protected"
	tokenPath     = "/token"

	flaggedTokenPath = "/flagged-token"

	// The endpoint each control guards, which is also the only endpoint whose
	// answer that control decides.
	LimitedPath  = "/limited"
	GovernedPath = "/governed"
	FilteredPath = "/filtered"

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

	// The compose file requires the database password even for a teardown that
	// creates no database, for the same reason as the nonce above.
	teardownPassword = "teardown"

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

	errSeedRole = "khaos could not create the range's %s role on its own engine: %w"

	errNoEnvGateway = "%w: this experiment replaces a container to break its ENVIRONMENT, and the running range has no %s; bring the range down and up again to create it"

	errNoSecretGateway = "%w: this experiment breaks a secret FILE, and the running range has no %s; bring the range down and up again to create it"

	errNoAuthzGateway = "%w: this experiment answers a service's own authorization call, and the running range has no %s; bring the range down and up again to create it"

	errNoAuthzBase = "%w: this experiment answers a service's own authorization call, and %s does not carry %s, so khaos cannot tell where that service looks for its dependency; bring the range down and up again to recreate it"

	errNoControlGateway = "%w: this experiment severs one of a gateway's security controls from its dependency, and the running range has no %s; bring the range down and up again to create it"

	errNoControlAddr = "%w: this experiment severs %s, and %s does not carry %s, so khaos cannot tell where that control looks for it; bring the range down and up again to recreate it"

	errNoStatefulTier = "%w: this experiment acts on a real stateful dependency -- a database engine, or the datastore a rate limiter counts in -- and the running range has none. khaos does not replace these with its own code, because the finding IS what correct ones do, so the stack has to be brought up with them: `khaos range down && khaos range up --with-db`"
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

	// Stateful is whether `range up --with-db` created the database tier. The
	// password is minted per up and read back from the containers, never
	// remembered from what khaos chose.
	Stateful      bool
	DBPassword    string
	DBAppPassword string
	DBGatewayPort int
	SecretPort    int
	EnvPort       int
	SecretValue   string

	// AuthzPort is the caller's published port, AuthzDepPort is where that
	// caller was told to find its authorization dependency, and AuthzBase is
	// the URL it was created with, read back out of its own environment so
	// khaos binds where it is already being called.
	AuthzPort    int
	AuthzDepPort int
	AuthzBase    string

	// ControlPort is the gateway's published port; the three that follow are
	// where it was told to find each control's dependency. The three Addr
	// fields are read back out of its own environment.
	ControlPort       int
	ControlStorePort  int
	ControlPolicyPort int
	ControlRulesPort  int

	ControlStoreAddr  string
	ControlPolicyAddr string
	ControlRulesAddr  string

	ControlSecret string

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

		DBGatewayPort: ports.DBGateway,
		SecretPort:    ports.Secret,
		EnvPort:       ports.Env,
		AuthzPort:     ports.Authz,
		AuthzDepPort:  ports.AuthzDep,

		ControlPort:       ports.Control,
		ControlStorePort:  ports.ControlStore,
		ControlPolicyPort: ports.ControlPolicy,
		ControlRulesPort:  ports.ControlRules,
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

	DBGateway int
	Secret    int
	Env       int

	// Two for the service-to-service tier: one the caller publishes, and one
	// khaos's own authorization dependency is reached on from inside the
	// range. The second is not published by anything, and it is still chosen
	// here because the caller's environment names it at creation.
	Authz    int
	AuthzDep int

	// The control gateway's published port, and the address each of its three
	// controls dials its own dependency on. Three rather than one is what
	// lets khaos sever the datastore while the other two keep answering.
	Control       int
	ControlStore  int
	ControlPolicy int
	ControlRules  int
}

// FreePorts picks every host port the range needs in one go, all distinct.
// `also` is every further address a tier will bind one of them on, which the
// caller discovers from the daemon: four tiers bind the bridge gateway rather
// than loopback.
func FreePorts(also ...string) (Ports, error) {
	taken := map[int]bool{}

	pick := func() (int, error) {
		for range portTries {
			port, err := FreePort(also...)
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
		&chosen.DBGateway,
		&chosen.Secret,
		&chosen.Env,
		&chosen.Authz,
		&chosen.AuthzDep,
		&chosen.Control,
		&chosen.ControlStore,
		&chosen.ControlPolicy,
		&chosen.ControlRules,
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

	return khaos.RangeDirectory()
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

// FreePort proves a candidate is free on every address a tier might bind it on,
// and `also` is what makes that true. Testing loopback alone was weaker than it
// read: the published container ports go to 127.0.0.1, but the proxy, the
// identity provider, the certificate authority and the authorization dependency
// all bind the DOCKER BRIDGE GATEWAY, and a port free on 127.0.0.1 is not
// evidence it is free on 172.17.0.1.
//
// A wildcard bind would answer the same question in one call and is not used:
// khaos refuses to bind a wildcard anywhere else, and a probe is not a good
// enough reason to make an exception an operator would find in `ss` output.
func FreePort(also ...string) (int, error) {
	for range portTries {
		//nolint:gosec // a bind candidate, immediately tested
		port := portFloor + rand.IntN(portCeil-portFloor)

		if freeOn(port, append([]string{loopback}, also...)) {
			return port, nil
		}
	}

	return 0, fmt.Errorf(errNoPort, portFloor, portCeil)
}

// freeOn requires EVERY address, because a port taken on any one of them is a
// port a tier can fail to bind.
func freeOn(port int, addresses []string) bool {
	for _, address := range addresses {
		listener, err := net.Listen(
			"tcp",
			net.JoinHostPort(address, strconv.Itoa(port)),
		)
		if err != nil {
			return false
		}

		if err := listener.Close(); err != nil {
			return false
		}
	}

	return true
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

// Up brings the range up. withDB adds the stateful tier, which is opt-in
// because those four containers are the only ones khaos does not implement
// itself and they cost real startup time.
func (l Lab) Up(
	ctx context.Context,
	out io.Writer,
	failMode, cacheTTL, tlsMode, poolMode, secretMode, authzMode string,
	reresolve string,
	withDB bool,
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
		EnvDBPassword+"="+l.DBPassword,
		EnvDBAppPassword+"="+l.DBAppPassword,
		EnvDBGatewayPort+"="+strconv.Itoa(l.DBGatewayPort),
		EnvPoolMode+"="+poolMode,
		EnvSecretPort+"="+strconv.Itoa(l.SecretPort),
		EnvSecretMode+"="+secretMode,
		EnvSecretValue+"="+l.SecretValue,
		EnvEnvPort+"="+strconv.Itoa(l.EnvPort),
		EnvAuthzPort+"="+strconv.Itoa(l.AuthzPort),
		EnvAuthzDep+"="+strconv.Itoa(l.AuthzDepPort),
		EnvAuthzMode+"="+authzMode,
		EnvControlPort+"="+strconv.Itoa(l.ControlPort),
		EnvControlStorePort+"="+strconv.Itoa(l.ControlStorePort),
		EnvControlPolicyPort+"="+strconv.Itoa(l.ControlPolicyPort),
		EnvControlRulesPort+"="+strconv.Itoa(l.ControlRulesPort),
		EnvControlSecret+"="+l.ControlSecret,
		EnvReresolve+"="+reresolve,
	)

	if err := l.compose(ctx, out, environ, "build", "idp"); err != nil {
		return err
	}

	args := []string{"up", "--no-build", "--detach", "--wait"}
	if withDB {
		args = append([]string{profileFlag, dbProfile}, args...)
	}

	if err := l.compose(ctx, out, environ, args...); err != nil {
		return err
	}

	if withDB {
		if err := l.seedAppRole(ctx); err != nil {
			return err
		}
	}

	return l.awaitReady(ctx)
}

// seedAppRole creates the role the pooled fixture authenticates with. It is
// khaos's own SQL client rather than the engine's init hook, because the hook
// reads a file from the image and the data directory is a tmpfs - and because
// khaos needs the role to be a DIFFERENT one from the administrative
// credential it performs rotations with.
func (l Lab) seedAppRole(ctx context.Context) error {
	client, err := dbx.Open(dbx.Config{
		Engine:   dbx.Postgres,
		Address:  net.JoinHostPort(PostgresAddress, postgresPort),
		Database: AppDatabase,
		Admin:    dbx.Credential{Role: adminRole, Password: l.DBPassword},
	})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	deadline := time.Now().Add(readyTimeout)

	for {
		err = client.Ping(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf(errSeedRole, AppRole, err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(readyInterval):
		}
	}

	if err := client.CreateRole(ctx, dbx.Credential{
		Role:     AppRole,
		Password: l.DBAppPassword,
	}); err != nil {
		// Already there is success: the engine's data directory is a tmpfs, so
		// this only happens when `range up` ran twice without a `down`.
		if err := client.Rotate(ctx, dbx.Credential{
			Role:     AppRole,
			Password: l.DBAppPassword,
		}); err != nil {
			return fmt.Errorf(errSeedRole, AppRole, err)
		}
	}

	return nil
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
		EnvDBPassword+"="+teardownPassword,
		EnvDBAppPassword+"="+teardownPassword,
		EnvDBGatewayPort+"="+strconv.Itoa(teardownPort),
		EnvSecretPort+"="+strconv.Itoa(teardownPort),
		EnvSecretValue+"="+teardownPassword,
		EnvEnvPort+"="+strconv.Itoa(teardownPort),
		EnvAuthzPort+"="+strconv.Itoa(teardownPort),
		EnvAuthzDep+"="+strconv.Itoa(teardownPort),
		EnvControlPort+"="+strconv.Itoa(teardownPort),
		EnvControlStorePort+"="+strconv.Itoa(teardownPort),
		EnvControlPolicyPort+"="+strconv.Itoa(teardownPort),
		EnvControlRulesPort+"="+strconv.Itoa(teardownPort),
		EnvControlSecret+"="+teardownPassword,
	)

	// The profile is ALWAYS passed on the way down. Compose only removes the
	// services in the active profile set, so a teardown without it leaves the
	// database tier running and `range down` would report a range that is down
	// while four containers of it are up.
	return l.compose(
		ctx,
		out,
		environ,
		profileFlag, dbProfile,
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
	resolvedEnv, err := dockerx.ComposeEnvironment(environ)
	if err != nil {
		return err
	}
	full := append([]string{
		"compose",
		projectFlag, ProjectName,
		"-f", filepath.Join(l.Dir, composeFile),
	}, args...)

	var stderr bytes.Buffer

	//nolint:gosec // khaos driving its own compose file as the operator
	cmd := exec.CommandContext(ctx, dockerBinary, full...)
	cmd.Dir = l.Dir
	cmd.Env = resolvedEnv
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
	return l.issueFrom(ctx, l.GatewayURL()+tokenPath)
}

func (l Lab) issueFrom(ctx context.Context, url string) (string, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		url,
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

	if err := lab.readProxyTier(ctx, reader, running); err != nil {
		return Lab{}, err
	}
	if err := lab.readIdentityTier(ctx, reader, running); err != nil {
		return Lab{}, err
	}
	if _, err := lab.readTLSTier(ctx, reader, running); err != nil {
		return Lab{}, err
	}
	if err := lab.readDNSTier(ctx, reader, running); err != nil {
		return Lab{}, err
	}
	lab.readStatefulTier(running)
	if err := lab.readCredentialGateways(ctx, reader, running); err != nil {
		return Lab{}, err
	}
	return lab, nil
}

func (l *Lab) readProxyTier(
	ctx context.Context,
	reader PortReader,
	running map[string]dockerx.Target,
) error {
	proxied, ok := running[ProxiedGatewayName]
	if !ok {
		return nil
	}

	var err error
	if l.ProxiedPort, err = reader.PublishedPort(
		ctx,
		proxied.ID,
		GatewayInternalPort,
	); err != nil {
		return err
	}

	l.ProxyPort, err = proxyPortOf(ctx, reader, proxied.ID)
	return err
}

func (l *Lab) readIdentityTier(
	ctx context.Context,
	reader PortReader,
	running map[string]dockerx.Target,
) error {
	verifierGateway, ok := running[VerifierGatewayName]
	if !ok {
		return nil
	}

	var err error
	if l.VerifierPort, err = reader.PublishedPort(
		ctx,
		verifierGateway.ID,
		GatewayInternalPort,
	); err != nil {
		return err
	}

	l.Issuer, l.IdPPort, err = issuerOf(
		ctx,
		reader,
		verifierGateway.ID,
	)
	return err
}

func (l *Lab) readCredentialGateways(
	ctx context.Context,
	reader PortReader,
	running map[string]dockerx.Target,
) error {
	for name, into := range map[string]*int{
		DBGatewayName:      &l.DBGatewayPort,
		SecretGatewayName:  &l.SecretPort,
		EnvGatewayName:     &l.EnvPort,
		AuthzGatewayName:   &l.AuthzPort,
		ControlGatewayName: &l.ControlPort,
	} {
		gateway, ok := running[name]
		if !ok {
			continue
		}

		port, err := reader.PublishedPort(ctx, gateway.ID, GatewayInternalPort)
		if err != nil {
			return err
		}

		*into = port
	}

	caller, ok := running[AuthzGatewayName]
	if !ok {
		return l.readControlTier(ctx, reader, running)
	}

	environ, err := reader.ContainerEnv(ctx, caller.ID)
	if err != nil {
		return err
	}

	// The address the CALLER was created with, which is the one khaos has to
	// bind. A container's environment is fixed at creation, so this is read
	// back rather than recomputed from whatever ports this khaos chose.
	//
	// A container of that name carrying no such address is the tier being
	// ABSENT rather than an error, and that distinction is load-bearing: this
	// runs inside Discover, which every experiment calls, so returning an
	// error here would take every unrelated run down over one stale container.
	// RequireAuthzTier refuses by name for the experiments that need it.
	l.AuthzBase = environ[EnvAuthzBase]

	return l.readControlTier(ctx, reader, running)
}

// readControlTier reads the three dependency addresses out of the gateway that
// dials them. A container of that name carrying none of them is the tier being
// ABSENT rather than an error: this runs inside Discover, which every
// experiment calls, so a hard error here would take unrelated runs down over
// one stale container. RequireControlTier refuses by name instead.
func (l *Lab) readControlTier(
	ctx context.Context,
	reader PortReader,
	running map[string]dockerx.Target,
) error {
	gateway, ok := running[ControlGatewayName]
	if !ok {
		return nil
	}

	environ, err := reader.ContainerEnv(ctx, gateway.ID)
	if err != nil {
		return err
	}

	l.ControlStoreAddr = environ[EnvLimitStore]
	l.ControlPolicyAddr = environ[EnvPolicyStore]
	l.ControlRulesAddr = environ[EnvRulesStore]

	return nil
}

func (l Lab) AuthzGatewayURL() string {
	return "http://" + net.JoinHostPort(loopback, strconv.Itoa(l.AuthzPort))
}

func (l Lab) AuthzProtectedURL() string {
	return l.AuthzGatewayURL() + protectedPath
}

// IssueAuthzToken asks the caller for a credential it will AUTHENTICATE. The
// fixture authenticates locally and correctly in all three of its modes, which is
// what gives the experiment a baseline: a service that allows on any non-200
// from its authorization dependency refuses nothing at all, and khaos's own
// guard would void the run rather than measure one.
func (l Lab) IssueAuthzToken(ctx context.Context) (string, error) {
	return l.issueFrom(ctx, l.AuthzGatewayURL()+tokenPath)
}

// RequireAuthzTier separates the two ways this tier can be missing, because
// they need different fixes: no caller at all means bring the range up, and a
// caller carrying no dependency address means that container predates the
// variable and has to be recreated.
func (l Lab) RequireAuthzTier() error {
	if l.AuthzPort == 0 {
		return fmt.Errorf(
			errNoAuthzGateway,
			ErrRangeIncomplete,
			AuthzGatewayName,
		)
	}

	if l.AuthzBase == "" {
		return fmt.Errorf(
			errNoAuthzBase,
			ErrRangeIncomplete,
			AuthzGatewayName,
			EnvAuthzBase,
		)
	}

	return nil
}

// AuthzListenAddr is where khaos binds the dependency the caller already asks.
// It is the DEFAULT bridge's gateway for the same measured reason as every
// other in-process tier: a listener on the range network's own gateway is
// unreachable from a container on it, and a container's loopback is its own.
func (l Lab) AuthzListenAddr(
	ctx context.Context,
	reader PortReader,
) (string, error) {
	if err := l.RequireAuthzTier(); err != nil {
		return "", err
	}

	gatewayIP, err := reader.BridgeGateway(ctx)
	if err != nil {
		return "", err
	}

	port, err := portOfURL(l.AuthzBase)
	if err != nil {
		return "", err
	}

	return net.JoinHostPort(gatewayIP, strconv.Itoa(port)), nil
}

func (l Lab) EnvGatewayURL() string {
	return "http://" + net.JoinHostPort(loopback, strconv.Itoa(l.EnvPort))
}

func (l Lab) EnvProtectedURL() string {
	return l.EnvGatewayURL() + protectedPath
}

// IssueEnvToken asks the env-sourced fixture for a credential signed with
// whatever secret its environment currently holds.
func (l Lab) IssueEnvToken(ctx context.Context) (string, error) {
	return l.issueFrom(ctx, l.EnvGatewayURL()+secretTokenPath)
}

func (l Lab) RequireEnvTier() error {
	if l.EnvPort != 0 {
		return nil
	}

	return fmt.Errorf(errNoEnvGateway, ErrRangeIncomplete, EnvGatewayName)
}

// Control names one of the gateway's three controls, so a refusal and a
// listen address can both be resolved from the experiment's own subject.
type Control string

const (
	ControlLimiter Control = "the rate limiter from its datastore"
	ControlPolicy  Control = "the policy engine from its policy store"
	ControlRules   Control = "the rule matcher from its rules backend"
)

func (l Lab) ControlGatewayURL() string {
	return "http://" + net.JoinHostPort(
		loopback,
		strconv.Itoa(l.ControlPort),
	)
}

// IssueControlToken asks the gateway for a credential it will authenticate.
func (l Lab) IssueControlToken(ctx context.Context) (string, error) {
	return l.issueFrom(ctx, l.ControlGatewayURL()+tokenPath)
}

// RefusedInputURL is where khaos fetches a fresh input every control refuses,
// once per probe rather than once per run: the credential is signed, so it
// cannot carry an appended nonce, and a repeated one is answered from a
// decision cache rather than by the control.
func (l Lab) RefusedInputURL() string {
	return l.ControlGatewayURL() + flaggedTokenPath
}

func (l Lab) controlDependency(at Control) (string, string) {
	switch at {
	case ControlLimiter:
		return l.ControlStoreAddr, EnvLimitStore
	case ControlPolicy:
		return l.ControlPolicyAddr, EnvPolicyStore
	default:
		return l.ControlRulesAddr, EnvRulesStore
	}
}

func (l Lab) RequireControlTier(at Control) error {
	if l.ControlPort == 0 {
		return fmt.Errorf(
			errNoControlGateway,
			ErrRangeIncomplete,
			ControlGatewayName,
		)
	}

	address, variable := l.controlDependency(at)
	if address == "" {
		return fmt.Errorf(
			errNoControlAddr,
			ErrRangeIncomplete,
			at,
			ControlGatewayName,
			variable,
		)
	}

	return nil
}

// ControlEndpoint says where khaos binds the proxy for one control and which
// real dependency that proxy forwards to. The listen port comes from the
// gateway's own environment and the upstream from the dependency's address on
// the range network, which the host routes to.
func (l Lab) ControlEndpoint(
	ctx context.Context,
	reader PortReader,
	at Control,
) (string, string, error) {
	if err := l.RequireControlTier(at); err != nil {
		return "", "", err
	}

	gatewayIP, err := reader.BridgeGateway(ctx)
	if err != nil {
		return "", "", err
	}

	address, _ := l.controlDependency(at)

	port, err := controlPort(address)
	if err != nil {
		return "", "", err
	}

	upstream, err := l.controlUpstream(ctx, reader, at)
	if err != nil {
		return "", "", err
	}

	return net.JoinHostPort(gatewayIP, strconv.Itoa(port)), upstream, nil
}

// controlPort reads the port out of either shape the gateway holds: the
// limiter's datastore is a bare host:port and the other two are URLs.
func controlPort(address string) (int, error) {
	if strings.Contains(address, "://") {
		return portOfURL(address)
	}

	_, raw, err := net.SplitHostPort(address)
	if err != nil {
		return 0, fmt.Errorf(
			errBadUpstream,
			ErrRangeIncomplete,
			ControlGatewayName,
			address,
			err,
		)
	}

	port, err := strconv.Atoi(raw)
	if err != nil || port <= 0 {
		return 0, fmt.Errorf(
			errBadUpstream,
			ErrRangeIncomplete,
			ControlGatewayName,
			address,
			err,
		)
	}

	return port, nil
}

func (l Lab) controlUpstream(
	ctx context.Context,
	reader PortReader,
	at Control,
) (string, error) {
	name, port := ControldName, strconv.Itoa(GatewayInternalPort)
	if at == ControlLimiter {
		name, port = RedisName, redisPort
	}

	targets, err := reader.Targets(ctx, dockerx.Filter{Project: ProjectName})
	if err != nil {
		return "", err
	}

	for _, target := range targets {
		if target.Name != name || !target.Running {
			continue
		}

		address, err := reader.NetworkAddress(ctx, target.ID, NetworkName)
		if err != nil {
			return "", err
		}

		return net.JoinHostPort(address, port), nil
	}

	return "", fmt.Errorf(
		errNoControlGateway,
		ErrRangeIncomplete,
		name,
	)
}

func (l Lab) SecretGatewayURL() string {
	return "http://" + net.JoinHostPort(
		loopback,
		strconv.Itoa(l.SecretPort),
	)
}

func (l Lab) SecretProtectedURL() string {
	return l.SecretGatewayURL() + protectedPath
}

// IssueSecretToken asks the HMAC fixture for a credential signed with whatever
// secret it currently holds, so khaos never has to read the file - and so the
// credential it presents as valid is the one the target would accept.
func (l Lab) IssueSecretToken(ctx context.Context) (string, error) {
	return l.issueFrom(ctx, l.SecretGatewayURL()+secretTokenPath)
}

func (l Lab) RequireSecretTier() error {
	if l.SecretPort != 0 {
		return nil
	}

	return fmt.Errorf(errNoSecretGateway, ErrRangeIncomplete, SecretGatewayName)
}

// DBGatewayURL is the pooled fixture's entry point.
func (l Lab) DBGatewayURL() string {
	return "http://" + net.JoinHostPort(
		loopback,
		strconv.Itoa(l.DBGatewayPort),
	)
}

func (l Lab) DBProtectedURL() string {
	return l.DBGatewayURL() + protectedPath
}

func (l Lab) DBHealthURL() string {
	return l.DBGatewayURL() + healthPath
}

func (l Lab) DBReadyURL() string {
	return l.DBGatewayURL() + readyPath
}

// readTLSTier reports whether the TLS gateway was there to read, because its
// absence is not fatal: the experiments that do not need it must still work.
func (l *Lab) readTLSTier(
	ctx context.Context,
	reader PortReader,
	running map[string]dockerx.Target,
) (bool, error) {
	tlsGateway, ok := running[TLSGatewayName]
	if !ok {
		return false, nil
	}

	port, err := reader.PublishedPort(ctx, tlsGateway.ID, GatewayInternalPort)
	if err != nil {
		return false, err
	}

	l.TLSPort = port

	if err := l.readAuthorityWiring(ctx, reader, tlsGateway.ID); err != nil {
		return false, err
	}

	return true, nil
}

// readStatefulTier records whether `range up --with-db` created the database
// tier. Every engine is required rather than any one of them: the credential
// family's exit gate runs the same pair against all three, and a partial tier
// would report a missing engine as an experiment that cannot run.
func (l *Lab) readStatefulTier(running map[string]dockerx.Target) {
	for _, name := range []string{
		PostgresName,
		MySQLName,
		MariaDBName,
		RedisName,
	} {
		if _, up := running[name]; !up {
			return
		}
	}

	l.Stateful = true
}

// RequireStatefulTier refuses before the baseline rather than letting a run
// report a database that is not there as a target that was not enforcing.
func (l Lab) RequireStatefulTier() error {
	if l.Stateful {
		return nil
	}

	return fmt.Errorf(errNoStatefulTier, ErrRangeIncomplete)
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

// AuthorityEndpoint binds on the DEFAULT bridge's gateway, since a listener on
// the range network's own gateway is refused from a container on it, and a
// container's loopback is its own rather than the host's.
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
