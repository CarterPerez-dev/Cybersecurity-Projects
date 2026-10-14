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

// verifierGateway is the only gateway whose identity provider is khaos itself,
// so it is the only one khaos can arm. It serves both validation strategies,
// chosen by the credential's shape, as real gateways do.
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

	// For a human reading the fixture's responses; khaos must never consume it.
	w.Header().Set(headerVerifierReason, decision.Reason)

	if decision.Allow {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusForbidden)
}
