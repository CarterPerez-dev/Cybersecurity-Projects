// ©AngelaMos | 2026
// main.go

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/pki"
	"github.com/CarterPerez-dev/khaos/internal/tlsclient"
	"github.com/CarterPerez-dev/khaos/internal/verifier"
)

const (
	roleIDP      = "idp"
	roleGateway  = "gateway"
	roleVerifier = "verifier"
	roleTLS      = "tls"
	roleRogue    = "rogue"
	roleResolver = "resolver"
	roleDB       = "db"
	roleSecret   = "secret"
	roleAuthz    = "authz"
	roleHealth   = "healthcheck"
	roleAlive    = "alivecheck"

	envListen   = "KHAOS_RANGE_LISTEN"
	envUpstream = "KHAOS_RANGE_UPSTREAM"

	// envReresolve resolves the dependency's name on EVERY request. DNS only.
	envReresolve = "KHAOS_RANGE_RERESOLVE"
	trueValue    = "true"
	envFailMode  = "KHAOS_RANGE_FAIL_MODE"

	// The pooled-credential fixture's own database credential. khaos reads the
	// password out of this container's environment, because the container is
	// the only authority on what it authenticated with, and rotates that role
	// at the engine.
	envDBHost     = "KHAOS_RANGE_DB_HOST"
	envDBUser     = "KHAOS_RANGE_DB_USER"
	envDBPassword = "KHAOS_RANGE_DB_PASSWORD"
	envDBName     = "KHAOS_RANGE_DB_NAME"
	envPoolMode   = "KHAOS_RANGE_POOL_MODE"

	defaultDBHost = "postgres:5432"
	defaultDBUser = "appuser"
	defaultDBName = "appdb"

	envSecretPath = "KHAOS_RANGE_SECRET_PATH"
	envSecretMode = "KHAOS_RANGE_SECRET_MODE"

	// Set on the fixture the environment faults target, and empty on the one
	// the file faults target: whichever is set is where the secret comes from.
	envSecretVar = "KHAOS_RANGE_SECRET_VAR"

	envAuthzMode = "KHAOS_RANGE_AUTHZ_MODE"

	// Where the service-to-service caller asks for an authorization decision,
	// which is khaos itself: no correct dependency answers a definitive deny
	// on request.
	envAuthzBase = "KHAOS_RANGE_AUTHZ_BASE"

	defaultSecretPath = "/run/khaos-secrets/hmac"
	envCacheTTL       = "KHAOS_RANGE_CACHE_TTL"

	defaultListen   = ":8080"
	defaultUpstream = "http://idp:8080"

	// Deliberately unreachable: a plausible default would let the gateway
	// start and measure nothing.
	defaultDependency    = "https://host.docker.internal:0"
	defaultAuthorityBase = "http://host.docker.internal:0"
	defaultAuthzBase     = "http://host.docker.internal:0"

	shutdownGrace = 2 * time.Second

	// Generous on purpose: a short header timeout closes the connection before
	// a longer injected delay can be observed, making the fixture's ceiling
	// look like the fault's.
	readHeaderTimeout = 120 * time.Second

	usage          = "usage: khaos-range <idp|gateway|verifier|tls|rogue|resolver|db|secret|authz|healthcheck|alivecheck>"
	selfBase       = "http://127.0.0.1:8080"
	selfHealthPath = "/health"
	selfAlivePath  = "/alive"
	healthWait     = 2 * time.Second
	errorFormat    = "khaos-range: %v\n"
	exitError      = 1
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, errorFormat, err)
		os.Exit(exitError)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New(usage)
	}

	if os.Args[1] == roleHealth {
		return selfCheck(selfHealthPath)
	}

	if os.Args[1] == roleAlive {
		return selfCheck(selfAlivePath)
	}

	// The resolver binds UDP and TCP, so it never reaches the server below.
	if os.Args[1] == roleResolver {
		return serveResolver(os.Args[2:])
	}

	handler, err := roleHandler(os.Args[1])
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              envOr(envListen, defaultListen),
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(
			context.Background(),
			shutdownGrace,
		)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()

	if err := server.ListenAndServe(); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func roleHandler(role string) (http.Handler, error) {
	switch role {
	case roleIDP:
		return newIdentityProvider().routes(), nil
	case roleGateway:
		return newGateway(
			envOr(envUpstream, defaultUpstream),
			envOr(envFailMode, FailClosed),
			durationOr(envCacheTTL, defaultCacheTTL),
			envOr(envReresolve, "") == trueValue,
		).routes(), nil
	case roleVerifier:
		return newVerifierGateway(
			envOr(envIssuer, defaultIssuer),
			envOr(envFailMode, string(verifier.Correct)),
			durationOr(envKeyTTL, verifier.DefaultKeyTTL),
			durationOr(envCacheTTL, verifier.DefaultDecisionTTL),
		).routes(), nil
	case roleRogue:
		return newRogueProvider().routes(), nil
	case roleAuthz:
		return newAuthzGateway(
			envOr(envAuthzBase, defaultAuthzBase),
			envOr(envAuthzMode, AuthzDistinguishes),
		).routes(), nil
	case roleSecret:
		return newSecretGateway(
			envOr(envSecretPath, defaultSecretPath),
			envOr(envSecretMode, SecretUnchecked),
			os.Getenv(envSecretVar),
		).routes(), nil
	case roleDB:
		return newDBGateway(
			databaseDSN(),
			envOr(envPoolMode, PoolUnbounded),
			envOr(envUpstream, defaultUpstream),
			envOr(envFailMode, FailClosed),
		).routes(), nil
	case roleTLS:
		return newTLSGateway(
			envOr(envUpstream, defaultUpstream),
			envOr(envDependency, defaultDependency),
			envOr(envAuthorityBase, defaultAuthorityBase),
			envOr(envCertHost, pki.DefaultHost),
			envOr(envFailMode, FailClosed),
			envOr(envTLSMode, string(tlsclient.Correct)),
			durationOr(envCacheTTL, defaultCacheTTL),
		).routes(), nil
	default:
		return nil, errors.New(usage)
	}
}

// databaseDSN is assembled from separate variables rather than taken as one
// string, so khaos can read the PASSWORD on its own out of this container's
// environment and put the same value back after the run.
func databaseDSN() string {
	target := url.URL{
		Scheme: "postgres",
		User: url.UserPassword(
			envOr(envDBUser, defaultDBUser),
			os.Getenv(envDBPassword),
		),
		Host:     envOr(envDBHost, defaultDBHost),
		Path:     "/" + envOr(envDBName, defaultDBName),
		RawQuery: "sslmode=disable&connect_timeout=3",
	}

	return target.String()
}

func selfCheck(path string) error {
	client := &http.Client{Timeout: healthWait}

	response, err := client.Get(selfBase + path)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health returned %d", response.StatusCode)
	}

	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func durationOr(name string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(os.Getenv(name))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
