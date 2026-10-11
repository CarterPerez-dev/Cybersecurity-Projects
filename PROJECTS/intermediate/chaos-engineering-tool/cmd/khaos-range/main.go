// ©AngelaMos | 2026
// main.go

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/verifier"
)

const (
	roleIDP      = "idp"
	roleGateway  = "gateway"
	roleVerifier = "verifier"
	roleHealth   = "healthcheck"

	envListen   = "KHAOS_RANGE_LISTEN"
	envUpstream = "KHAOS_RANGE_UPSTREAM"
	envFailMode = "KHAOS_RANGE_FAIL_MODE"
	envCacheTTL = "KHAOS_RANGE_CACHE_TTL"

	defaultListen   = ":8080"
	defaultUpstream = "http://idp:8080"

	shutdownGrace = 2 * time.Second

	// Generous on purpose. At three seconds this fixture closed khaos's upstream
	// before a `--delay` beyond that could be observed, so khaos's one graduated
	// fault had a usable window of roughly 500ms to 3s against its own range and
	// aborted above it. That ceiling belonged to the fixture, not to the fault.
	// This is a deliberately-breakable test stack, not a hardened service, so the
	// header timeout exists only to stop a wedged connection living forever.
	readHeaderTimeout = 120 * time.Second

	usage       = "usage: khaos-range <idp|gateway|verifier|healthcheck>"
	selfURL     = "http://127.0.0.1:8080/health"
	healthWait  = 2 * time.Second
	errorFormat = "khaos-range: %v\n"
	exitError   = 1
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
		return selfCheck()
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
		).routes(), nil
	case roleVerifier:
		return newVerifierGateway(
			envOr(envIssuer, defaultIssuer),
			envOr(envFailMode, string(verifier.Correct)),
			durationOr(envKeyTTL, verifier.DefaultKeyTTL),
			durationOr(envCacheTTL, verifier.DefaultDecisionTTL),
		).routes(), nil
	default:
		return nil, errors.New(usage)
	}
}

func selfCheck() error {
	client := &http.Client{Timeout: healthWait}

	response, err := client.Get(selfURL)
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
