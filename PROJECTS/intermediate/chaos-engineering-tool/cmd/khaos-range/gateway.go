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

	// FailClosed refuses when it cannot reach the identity provider. This is
	// the correct behaviour for an authentication check.
	//
	// FailOpen serves anyway. This is the defect khaos exists to find, and it
	// is modelled on the Okta AD/LDAP delegated-authentication advisory, where
	// a cached decision was consulted first and could be reached only while the
	// agent was "down or cannot be reached".
	FailClosed = "closed"
	FailOpen   = "open"

	// FailStaleRearm is the bug research 07 section 3.3 says to name, build and
	// detect, because it reads as a resilience feature in review. It serves a
	// cached decision when the provider is unreachable AND re-arms that cache
	// entry for a full lifetime on every failed check. The lifetime therefore
	// stops bounding staleness and starts bounding IDLENESS: a cached allow
	// becomes permanent exactly when the authority that could revoke it is
	// unreachable, for as long as traffic keeps arriving.
	//
	// It is one line different from a defensible design. Serving a stale allow up
	// to a fixed ceiling and never re-arming is the bounded-stale pattern, which
	// is a trade plenty of teams make deliberately. The difference is whether the
	// error branch writes to the cache.
	FailStaleRearm = "stale-rearm"

	introspectPath  = "/introspect?token="
	issuePath       = "/token"
	revokePath      = "/revoke"
	defaultCacheTTL = 2 * time.Second
	upstreamTimeout = 500 * time.Millisecond

	// Generous on purpose. The ceiling has to be wide enough that khaos's own
	// probe interval cannot fall out of it by accident, or a run measures the
	// fixture's timing rather than the bug.
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

// newGateway builds the fixture. reresolve is what the DNS tier needs and is
// worth the extra parameter, because without it that whole family is inert
// against this gateway.
//
// Go's `http.Transport` keeps connections alive, so a client resolves its
// upstream's name ONCE when it opens a connection and then never again for the
// life of that connection. Measured on this fixture: 46 probes produced TWO
// queries to khaos's resolver, both at the first request. A DNS fault armed
// after that changes nothing the gateway can see, and khaos would report a clean
// survival of a fault the target never experienced.
//
// That is a true property of the fault class rather than a fixture defect — it
// is the DNS analogue of session resumption defeating a certificate probe — and
// khaos reports it as such when it measures it. But a fixture that can NEVER
// experience the fault cannot be the thing an exit gate asserts against, so this
// gateway re-resolves per request. Research 05 section 11 ranks the
// application's own connection pool as the caching layer most likely to void a
// DNS experiment, which is exactly what it did here.
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

	// The whole bug is the next three lines. A stale allow is served AND written
	// back, so the next request finds it fresh and writes it back again.
	if g.failMode == FailStaleRearm {
		if decision, ok := g.stale(token); ok {
			g.remember(token, decision)
			g.answer(w, decision)
			return
		}
	}

	w.WriteHeader(http.StatusForbidden)
}

// forward passes credential administration through to the identity provider so
// the range needs exactly one host port. It is deliberately unauthenticated:
// this is a loopback-only fixture whose whole purpose is to be broken, and
// khaos needs to mint itself a credential before it has one.
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
	// Treating any non-200 as "dependency unavailable, proceed" is the single
	// most common fail-open shape in service-to-service code, and a reference
	// implementation that contains it makes the comparison dishonest.
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

// stale returns a decision whose lifetime has passed but which is still inside a
// bounded staleness ceiling.
//
// The ceiling is what makes this the TTL-EXTENSION bug rather than the other one.
// Without it a stale entry is servable forever, which IS a cache with no expiry,
// and khaos measures it as exactly that. With it, every failed check pushes the
// entry back inside the window, so steady traffic keeps a cached allow alive
// indefinitely and a pause longer than the window lets it lapse. One ceiling, and
// the two bugs separate.
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

// staleCeiling is how far past its lifetime a decision may still be served. It is
// a multiple of the lifetime rather than a separate knob, so a range configured
// with one number behaves predictably: steady traffic at any interval shorter
// than this keeps a cached allow alive.
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
