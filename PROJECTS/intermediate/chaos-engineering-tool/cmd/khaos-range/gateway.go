// ©AngelaMos | 2026
// gateway.go

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	routeProtected = "/protected"

	headerAuthorization = "Authorization"
	bearerPrefix        = "Bearer "

	// FailClosed refuses when it cannot reach the identity provider. FailOpen
	// serves anyway, which is the defect khaos exists to find.
	FailClosed = "closed"
	FailOpen   = "open"

	// FailStaleRearm serves a cached decision when the provider is unreachable
	// AND re-arms it on every failed check, so the lifetime bounds idleness
	// rather than staleness.
	FailStaleRearm = "stale-rearm"

	introspectPath  = "/introspect?token="
	issuePath       = "/token"
	revokePath      = "/revoke"
	defaultCacheTTL = 2 * time.Second
	upstreamTimeout = 500 * time.Millisecond

	// Wide enough that a probe interval cannot fall out of the window.
	staleCeilingFactor = 4
)

type gateway struct {
	upstream string
	failMode string
	cacheTTL time.Duration

	client *http.Client

	mu    sync.Mutex
	cache map[string]cachedDecision
}

type cachedDecision struct {
	active  bool
	expires time.Time
}

// newGateway builds the fixture. reresolve disables keep-alives, because
// http.Transport resolves an upstream's name once per connection and never
// again, which hides any DNS fault armed after the first request.
func newGateway(
	upstream, failMode string,
	cacheTTL time.Duration,
	reresolve bool,
) *gateway {
	if cacheTTL <= 0 {
		cacheTTL = defaultCacheTTL
	}

	client := &http.Client{Timeout: upstreamTimeout}

	if reresolve {
		client.Transport = &http.Transport{DisableKeepAlives: true}
	}

	return &gateway{
		upstream: upstream,
		failMode: failMode,
		cacheTTL: cacheTTL,
		cache:    map[string]cachedDecision{},
		client:   client,
	}
}

func (g *gateway) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(routeHealth, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(routeProtected, g.protected)
	mux.HandleFunc(issuePath, g.forward(issuePath))
	mux.HandleFunc(revokePath, g.forward(revokePath))
	return mux
}

func (g *gateway) protected(w http.ResponseWriter, r *http.Request) {
	token, scheme := strings.CutPrefix(
		r.Header.Get(headerAuthorization),
		bearerPrefix,
	)

	if !scheme || token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if decision, ok := g.cached(token); ok {
		g.answer(w, decision)
		return
	}

	active, reachable := g.introspect(token)

	if reachable {
		g.remember(token, active)
		g.answer(w, active)
		return
	}

	if g.failMode == FailOpen {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Served AND written back, so the next request finds it fresh again.
	if g.failMode == FailStaleRearm {
		if decision, ok := g.stale(token); ok {
			g.remember(token, decision)
			g.answer(w, decision)
			return
		}
	}

	w.WriteHeader(http.StatusForbidden)
}

// forward passes credential administration to the identity provider, and is
// deliberately unauthenticated: khaos needs a credential before it has one.
func (g *gateway) forward(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := g.upstream + path
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}

		response, err := g.client.Post(target, "", nil)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = response.Body.Close() }()

		w.Header().Set(contentType, mimeJSON)
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}
}

func (g *gateway) answer(w http.ResponseWriter, active bool) {
	if active {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusForbidden)
}

func (g *gateway) introspect(token string) (bool, bool) {
	response, err := g.client.Get(g.upstream + introspectPath + token)
	if err != nil {
		return false, false
	}
	defer func() { _ = response.Body.Close() }()

	// A refusal from the identity provider is an ANSWER, not an outage.
	if response.StatusCode == http.StatusUnauthorized ||
		response.StatusCode == http.StatusForbidden {
		return false, true
	}

	if response.StatusCode != http.StatusOK {
		return false, false
	}

	var body introspection
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return false, false
	}

	return body.Active, true
}

func (g *gateway) cached(token string) (bool, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	decision, ok := g.cache[token]
	if !ok || time.Now().After(decision.expires) {
		return false, false
	}

	return decision.active, true
}

// stale returns a lapsed decision that is still inside the ceiling, which is
// what separates TTL extension from a cache with no expiry at all.
func (g *gateway) stale(token string) (bool, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	decision, ok := g.cache[token]
	if !ok {
		return false, false
	}

	if time.Now().After(decision.expires.Add(g.staleCeiling())) {
		return false, false
	}

	return decision.active, true
}

func (g *gateway) staleCeiling() time.Duration {
	return g.cacheTTL * staleCeilingFactor
}

func (g *gateway) remember(token string, active bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cache[token] = cachedDecision{
		active:  active,
		expires: time.Now().Add(g.cacheTTL),
	}
}
