// ©AngelaMos | 2026
// tlsgateway.go

package main

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/pki"
	"github.com/CarterPerez-dev/khaos/internal/tlsclient"
)

const (
	envDependency    = "KHAOS_RANGE_DEPENDENCY"
	envAuthorityBase = "KHAOS_RANGE_AUTHORITY_BASE"
	envCertHost      = "KHAOS_RANGE_CERT_HOST"
	envTLSMode       = "KHAOS_RANGE_TLS_MODE"

	headerTLSReason = "X-Khaos-TLS-Reason"

	dependencyTimeout = 3 * time.Second

	maxRootBytes = 64 << 10
)

// tlsGateway is the FOURTH gateway, and the only one whose dependency is
// reached over TLS from a certificate authority khaos controls.
//
// It composes the introspection gateway rather than reimplementing it, because
// the authorization half of this fixture is not what the `tls.` family is
// about: the certificate is. So the token decision, the cache and the fail mode
// are exactly the ones the other gateways use, and the only thing this adds is
// a PRECONDITION -- the dependency has to be usable before any authorization
// happens at all.
//
// That precondition is what makes the three outcomes distinguishable:
//
//   - the certificate is accepted, the dependency is reached, authorization
//     proceeds normally, and nothing looks wrong. HELD, and it means the
//     gateway talked to a dependency whose identity it could not verify.
//   - the certificate is refused and the gateway declines to serve. DENIED,
//     which is the correct outcome for a certificate fault.
//   - the certificate is refused and the gateway serves anyway. PERMITTED.
type tlsGateway struct {
	auth *gateway

	mode          tlsclient.Mode
	dependency    string
	authorityBase string
	certHost      string
	failMode      string
}

func newTLSGateway(
	upstream, dependency, authorityBase, certHost, failMode, tlsMode string,
	cacheTTL time.Duration,
) *tlsGateway {
	return &tlsGateway{
		auth: newGateway(upstream, failMode, cacheTTL),
		mode: resolveTLSMode(tlsMode),

		// Normalised to host:port, because Decide DIALS this and a URL is not
		// an address. The environment carries a URL on purpose -- it is
		// self-documenting and khaos parses the port out of it -- and handing
		// that straight to the dialer produced
		// `too many colons in address https://host.docker.internal:58520`,
		// which reached the verdict as a failed handshake and voided the
		// baseline of every certificate experiment.
		dependency: dialAddress(dependency),

		authorityBase: authorityBase,
		certHost:      certHost,
		failMode:      failMode,
	}
}

// dialAddress reduces a dependency URL to the host:port a dialer wants, and
// passes through anything that is already an address.
func dialAddress(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return raw
	}

	return parsed.Host
}

// client is built PER REQUEST, with the trust anchor re-read each time.
//
// A pool fetched once at startup would make CASwap inexpressible: that fault
// replaces the anchor after the gateway is already running, so a gateway
// holding a root from boot would never experience it and the experiment would
// report HELD over a fault that never reached it. Re-reading models what a
// substituted trust store IS -- managed out of band, changed without the
// application being asked.
//
// The client itself is configuration and no state, so building one per request
// costs nothing worth saving.
func (g *tlsGateway) client(ctx context.Context) *tlsclient.Client {
	return tlsclient.New(tlsclient.Config{
		Mode:    g.mode,
		Host:    g.certHost,
		Roots:   g.trustStore(ctx),
		Timeout: dependencyTimeout,
	})
}

// resolveTLSMode refuses an unknown mode rather than falling back to the
// correct client. A fixture that quietly became correct would report every
// experiment as fail-closed, which is the most expensive way to be wrong.
func resolveTLSMode(name string) tlsclient.Mode {
	mode, err := tlsclient.ParseMode(name)
	if err != nil {
		// The range is a fixture, so there is nobody to return an error to. It
		// picks the mode that cannot silently flatter the target: a client that
		// verifies nothing fails every experiment loudly rather than passing
		// one quietly.
		return tlsclient.SkipVerify
	}

	return mode
}

// routes builds its OWN mux rather than taking the auth gateway's and
// overriding a pattern. ServeMux PANICS on a duplicate registration, so
// mutating the composed gateway's routes crashed the container on startup with
// exit 2 and no useful message.
func (g *tlsGateway) routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc(routeHealth, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(routeProtected, g.protected)

	// Credential administration is forwarded to the identity provider so the
	// range needs exactly one host port per gateway, the same as the others.
	mux.HandleFunc(issuePath, g.auth.forward(issuePath))
	mux.HandleFunc(revokePath, g.auth.forward(revokePath))

	return mux
}

func (g *tlsGateway) protected(w http.ResponseWriter, r *http.Request) {
	token, scheme := strings.CutPrefix(
		r.Header.Get(headerAuthorization),
		bearerPrefix,
	)

	if !scheme || token == "" {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	decision := g.client(r.Context()).Decide(r.Context(), g.dependency)

	// A convenience for a human reading the fixture's responses, and khaos must
	// never consume it. khaos judges a target from the outside and a real target
	// volunteers nothing, so an experiment that read this header would pass
	// against the range and be inert against everything else.
	w.Header().Set(headerTLSReason, decision.Reason)

	if decision.Accepted {
		// The dependency is usable, so the ordinary authorization decision
		// applies and the certificate fault has changed nothing.
		g.auth.protected(w, r)

		return
	}

	if g.failMode == FailOpen {
		w.WriteHeader(http.StatusOK)

		return
	}

	w.WriteHeader(http.StatusForbidden)
}

// trustStore reads the anchor khaos's authority currently publishes.
//
// An EMPTY pool on failure, never the system roots. A nil pool would fall back
// to the host's real CAs, which cannot verify anything khaos mints, so every
// experiment would report the same refusal whether or not the fault landed and
// khaos could not tell its own plumbing failure from a target behaving
// correctly. An empty pool refuses too, but it refuses the BASELINE as well,
// which makes the run void instead of quietly wrong.
func (g *tlsGateway) trustStore(ctx context.Context) *x509.CertPool {
	pool := x509.NewCertPool()

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		strings.TrimSuffix(g.authorityBase, "/")+pki.RouteRoot,
		nil,
	)
	if err != nil {
		return pool
	}

	client := &http.Client{Timeout: dependencyTimeout}

	response, err := client.Do(request)
	if err != nil {
		return pool
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return pool
	}

	der, err := io.ReadAll(io.LimitReader(response.Body, maxRootBytes))
	if err != nil {
		return pool
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return pool
	}

	pool.AddCert(cert)

	return pool
}
