// ©AngelaMos | 2026
// verifier.go

package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/verifier"
)

const (
	envIssuer = "KHAOS_RANGE_ISSUER"
	envKeyTTL = "KHAOS_RANGE_KEY_TTL"

	defaultIssuer = "http://host.docker.internal:0"

	headerVerifierReason = "X-Khaos-Reason"
)

// verifierGateway is the third gateway the range runs, and the only one whose
// identity provider is khaos itself. The other two introspect the range's own
// provider container, which khaos cannot make lie; this one resolves keys and
// introspects against khaos's in-process provider, which khaos can arm.
//
// It serves BOTH validation strategies, chosen by the shape of the credential,
// because research 07 section 3.1 establishes that local validation and
// introspection have genuinely different outage shapes and the `identity.`
// family spans both. Real gateways dispatch the same way.
type verifierGateway struct {
	verifier *verifier.Verifier
}

func newVerifierGateway(
	issuer, failMode string,
	keyTTL, decisionTTL time.Duration,
) *verifierGateway {
	issuer = strings.TrimSuffix(issuer, "/")

	return &verifierGateway{
		verifier: verifier.New(verifier.Config{
			Issuer:        issuer,
			Audience:      idp.DefaultAudience,
			JWKSURI:       issuer + idp.RouteJWKS,
			IntrospectURI: issuer + idp.RouteIntrospect,
			Mode:          verifier.Resolve(failMode),
			KeyTTL:        keyTTL,
			DecisionTTL:   decisionTTL,
			Client:        &http.Client{Timeout: upstreamTimeout},
		}),
	}
}

func (g *verifierGateway) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(routeHealth, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(routeProtected, g.protected)
	return mux
}

func (g *verifierGateway) protected(w http.ResponseWriter, r *http.Request) {
	token, scheme := strings.CutPrefix(
		r.Header.Get(headerAuthorization),
		bearerPrefix,
	)

	if !scheme || token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	decision := g.verifier.Decide(token)

	// The reason is a convenience for a human reading the fixture's responses,
	// and khaos must never consume it. khaos judges a target from the outside and
	// a real target volunteers nothing, so an experiment that read this header
	// would pass against the range and be inert against everything else.
	w.Header().Set(headerVerifierReason, decision.Reason)

	if decision.Allow {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusForbidden)
}
