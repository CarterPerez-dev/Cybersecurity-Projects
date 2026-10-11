// ©AngelaMos | 2026
// routes.go

package idp

import (
	"encoding/json"
	"net/http"
	"time"
)

const (
	fieldIssuer        = "issuer"
	fieldJWKSURI       = "jwks_uri"
	fieldTokenEndpoint = "token_endpoint"
	fieldIntrospection = "introspection_endpoint"
	fieldRevocation    = "revocation_endpoint"
	fieldAlgsSupported = "id_token_signing_alg_values_supported"
	fieldToken         = "token"
	fieldSubject       = "sub"

	// Enough for a token and its form framing, and nowhere near enough to be a
	// memory-exhaustion surface on an endpoint that takes unauthenticated
	// requests by design.
	maxFormBytes = 64 << 10
)

// Introspection is RFC 7662's response. `active` is the only member a verifier
// may decide on, and the specification is explicit that the ABSENCE of a
// response is not `active: false`. A caller that invents one from a timeout or a
// 503 has made up a value the provider never gave it, which is taxonomy row F20
// and which three of this package's traps exist to provoke.
type Introspection struct {
	Active  bool   `json:"active"`
	Subject string `json:"sub,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

func (p *Provider) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(RouteHealth, p.health)
	mux.HandleFunc(RouteDiscovery, p.discovery)
	mux.HandleFunc(RouteJWKS, p.jwks)
	mux.HandleFunc(RouteToken, p.token)
	mux.HandleFunc(RouteIntrospect, p.introspect)
	mux.HandleFunc(RouteRevoke, p.revokeRoute)
	return mux
}

// health is never faulted. A target or an operator has to be able to tell
// "khaos's provider is gone" from "khaos's provider is lying", and a health
// endpoint that participates in the fault destroys that distinction.
func (p *Provider) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// discovery is the OIDC Discovery document. It is served so a target can be
// pointed at the issuer alone, and it is deliberately NOT faulted: research 07
// found that OIDC Discovery says nothing about rotation, nothing about `kid` and
// nothing about refetching, so every interesting fault lives at the JWK Set
// rather than at the document that points to it.
func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	issuer := p.Issuer()

	writeJSON(w, http.StatusOK, map[string]any{
		fieldIssuer:        issuer,
		fieldJWKSURI:       issuer + RouteJWKS,
		fieldTokenEndpoint: issuer + RouteToken,
		fieldIntrospection: issuer + RouteIntrospect,
		fieldRevocation:    issuer + RouteRevoke,
		fieldAlgsSupported: []string{string(RS256), string(ES256)},
	})
}

// jwks serves the published key set, and counts every fetch. The count is the
// measurement the refetch-amplification question needs and that no third-party
// provider exposes: an unknown `kid` is an attacker-controlled header field, so
// an unbounded refetch is a denial-of-service amplifier, and the only way to
// know whether a verifier bounds it is to count from the provider's side.
func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	p.jwksFetches.Add(1)

	if p.effective().Kind == JWKSUnreachable {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, http.StatusOK, p.PublishedSet())
}

// token mints under whatever is armed. khaos's own probes call mintToken
// in-process and never come through here; this exists so an operator can point
// their own client at khaos's provider, which is what makes the provider an
// instrument rather than a range fixture.
func (p *Provider) token(w http.ResponseWriter, _ *http.Request) {
	minted, err := p.TrappedToken()
	if err != nil {
		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{"error": err.Error()},
		)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		fieldToken:   minted,
		fieldSubject: DefaultSubject,
	})
}

// introspect answers about an opaque credential, and carries three of the traps.
// Each one leaves the provider REACHABLE and answering, which is the whole
// point: a caller's `err != nil` branch is never taken, so only its status
// handling, its decoder's error branch, or its timeout decides what happens.
// That is a different code path from an outage and it is reached by different
// bugs.
func (p *Provider) introspect(w http.ResponseWriter, r *http.Request) {
	p.introspects.Add(1)

	trap := p.effective()

	switch trap.Kind {
	case IntrospectionError:
		w.WriteHeader(http.StatusServiceUnavailable)
		return

	case IntrospectionMalformed:
		// A 200 with a body that starts out looking like the real thing and then
		// stops being JSON. A caller whose decode error branch returns "active"
		// has invented a value RFC 7662 never provides.
		w.Header().Set(headerContentType, mimeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(malformedBody))
		return

	case IntrospectionSlow:
		select {
		case <-time.After(trap.Delay):
		case <-r.Context().Done():
			return
		case <-p.closed:
			return
		}

	default:
		// Every other trap leaves introspection alone and the honest answer
		// below is returned. A token trap that broke this endpoint too would
		// give the target two reasons to refuse and khaos one it cannot
		// attribute.
	}

	credential := credentialFrom(r)

	p.mu.RLock()
	held, known := p.grants[credential]
	active := known && held.active
	subject := ""
	if known {
		subject = held.subject
	}
	p.mu.RUnlock()

	body := Introspection{Active: active}
	if active {
		body.Subject = subject
	}

	writeJSON(w, http.StatusOK, body)
}

// revokeRoute is the operator-facing revocation. It reports whether it actually
// revoked anything: a 404 for a credential this provider never issued, because
// answering 200 to a revocation that did not happen is how a run goes on to
// measure a credential nobody took away.
func (p *Provider) revokeRoute(w http.ResponseWriter, r *http.Request) {
	credential := credentialFrom(r)

	if err := p.revoke(credential); err != nil {
		writeJSON(
			w,
			http.StatusNotFound,
			map[string]string{"error": err.Error()},
		)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// credentialFrom reads the token the way the specifications say it is sent, and
// also the way khaos used to send it.
//
// RFC 7662 section 2.1 defines the introspection request as a POST with an
// `application/x-www-form-urlencoded` body, and RFC 7009 section 2.1 says the
// same for revocation. khaos read the token ONLY from the query string, and its
// own client sent it only that way, so the two agreed with each other and with
// nothing else: a conforming external client got `active: false` for a perfectly
// valid credential and could not establish a baseline at all.
//
// The query form is still accepted. It costs nothing, it keeps khaos's own
// read-back probes working, and a provider that is deliberately willing to be
// wrong has no reason to be strict about where it reads an input from.
func credentialFrom(r *http.Request) string {
	if token := r.URL.Query().Get(ParamToken); token != "" {
		return token
	}

	// Bounded. This is a fixture that accepts unauthenticated requests, so an
	// unbounded ParseForm is a trivial way to exhaust its memory.
	r.Body = http.MaxBytesReader(nil, r.Body, maxFormBytes)

	if err := r.ParseForm(); err != nil {
		return ""
	}

	return r.PostFormValue(ParamToken)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set(headerContentType, mimeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
