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

	maxFormBytes = 64 << 10
)

// Introspection is RFC 7662's response. `active` is the only member a verifier
// may decide on, and the ABSENCE of a response is not `active: false`.
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

// health is never faulted, or "khaos's provider is gone" stops being
// distinguishable from "khaos's provider is lying".
func (p *Provider) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// discovery is deliberately NOT faulted: OIDC Discovery says nothing about
// rotation, `kid` or refetching, so every fault lives at the JWK Set.
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

// jwks counts every fetch: `kid` is attacker-controlled, so an unbounded
// refetch is an amplifier only the provider's side can measure.
func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	p.jwksFetches.Add(1)

	if p.effective().Kind == JWKSUnreachable {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, http.StatusOK, p.PublishedSet())
}

// token exists for an operator's own client; khaos's probes call mintToken.
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

// introspect carries three traps, and each leaves the provider REACHABLE and
// answering, so a caller's `err != nil` branch is never the one that decides.
func (p *Provider) introspect(w http.ResponseWriter, r *http.Request) {
	p.introspects.Add(1)

	trap := p.effective()

	switch trap.Kind {
	case IntrospectionError:
		w.WriteHeader(http.StatusServiceUnavailable)
		return

	case IntrospectionMalformed:
		// A 200 whose body stops being JSON, so the decode branch decides.
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
		// Every other trap leaves this route's response alone.
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

// A 404 when nothing was revoked: answering 200 is how a run goes on to
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

// RFC 7662 section 2.1 and RFC 7009 section 2.1 put the token in a form body;
// the query string is accepted too, and is what khaos's own probes send.
func credentialFrom(r *http.Request) string {
	if token := r.URL.Query().Get(ParamToken); token != "" {
		return token
	}

	// Bounded: the endpoint is unauthenticated, so ParseForm must not be.
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
