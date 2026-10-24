// ©AngelaMos | 2026
// tlsgateway.go

package main

import (
	"context"
	"crypto/tls"
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

// tlsGateway reaches its dependency over TLS and composes the introspection
// gateway for the authorization half.
type tlsGateway struct {
	auth *gateway

	mode          tlsclient.Mode
	dependency    string
	authorityBase string
	certHost      string
	failMode      string

	// One cache for the whole lifetime: resumption is what makes the
	// policy-in-peer-callback path reachable at all.
	sessions tls.ClientSessionCache
}

func newTLSGateway(
	upstream, dependency, authorityBase, certHost, failMode, tlsMode string,
	cacheTTL time.Duration,
) *tlsGateway {
	return &tlsGateway{
		auth: newGateway(upstream, failMode, cacheTTL, false),
		mode: resolveTLSMode(tlsMode),

		// The environment carries a URL, but Decide dials this.
		dependency: dialAddress(dependency),

		authorityBase: authorityBase,
		certHost:      certHost,
		failMode:      failMode,
		sessions:      tls.NewLRUClientSessionCache(0),
	}
}

// identity is the client certificate khaos is currently issuing. Nil is not a
// failure: a withheld identity is itself one of the faults.
func (g *tlsGateway) identity(ctx context.Context) *tls.Certificate {
	body, ok := g.fetch(ctx, pki.RouteIdentity)
	if !ok {
		return nil
	}

	pair, err := tls.X509KeyPair(body, body)
	if err != nil {
		return nil
	}

	return &pair
}

// dialAddress reduces a dependency URL to host:port.
func dialAddress(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return raw
	}

	return parsed.Host
}

// client is built per request, because a trust store or certificate held from
// boot could never experience a fault armed after startup.
func (g *tlsGateway) client(ctx context.Context) *tlsclient.Client {
	var sessions tls.ClientSessionCache
	if g.mode == tlsclient.PolicyInPeerCallback {
		sessions = g.sessions
	}
	return tlsclient.New(tlsclient.Config{
		Mode:     g.mode,
		Host:     g.certHost,
		Roots:    g.trustStore(ctx),
		Timeout:  dependencyTimeout,
		Identity: g.identity(ctx),
		Sessions: sessions,
	})
}

// resolveTLSMode falls back to the client that verifies nothing, never to the
// correct one, so a misconfigured fixture fails loudly.
func resolveTLSMode(name string) tlsclient.Mode {
	mode, err := tlsclient.ParseMode(name)
	if err != nil {
		return tlsclient.SkipVerify
	}

	return mode
}

// routes builds its own mux rather than overriding a pattern on the composed
// gateway's, because net/http.ServeMux panics on a duplicate registration.
func (g *tlsGateway) routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc(routeHealth, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(routeProtected, g.protected)

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

	// For a human reading the fixture's responses; khaos must never consume it.
	w.Header().Set(headerTLSReason, decision.Reason)

	if decision.Accepted {
		g.auth.protected(w, r)

		return
	}

	if g.failMode == FailOpen {
		w.WriteHeader(http.StatusOK)

		return
	}

	w.WriteHeader(http.StatusForbidden)
}

// trustStore reads the anchor khaos's authority publishes, and on failure
// returns an EMPTY pool rather than nil, which would fall back to the host's
// real CAs.
func (g *tlsGateway) trustStore(ctx context.Context) *x509.CertPool {
	pool := x509.NewCertPool()

	der, ok := g.fetch(ctx, pki.RouteRoot)
	if !ok {
		return pool
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return pool
	}

	pool.AddCert(cert)

	return pool
}

func (g *tlsGateway) fetch(
	ctx context.Context,
	route string,
) ([]byte, bool) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		strings.TrimSuffix(g.authorityBase, "/")+route,
		nil,
	)
	if err != nil {
		return nil, false
	}

	client := &http.Client{Timeout: dependencyTimeout}

	response, err := client.Do(request)
	if err != nil {
		return nil, false
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, false
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxRootBytes))
	if err != nil {
		return nil, false
	}

	return body, true
}
