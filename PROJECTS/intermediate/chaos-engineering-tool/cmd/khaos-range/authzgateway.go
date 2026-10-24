// ©AngelaMos | 2026
// authzgateway.go

package main

import (
	"crypto/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// AuthzDistinguishes is correct: an authorization dependency has three
	// outcomes - allow, deny and unknown - and only unknown is eligible for a
	// fallback policy.
	AuthzDistinguishes = "distinguishes"

	AuthzCollapses = "collapses"

	AuthzRetries = "retries"

	// AuthzCached is also CORRECT, and it exists because khaos's own verdict
	// machinery was wrong about it. It differs from `distinguishes` in two ways
	// that are ordinary in real services and that khaos had never been shown
	// together: it caches an authorization decision for a second, and it
	// expresses a refusal as 503 rather than 403, the way a service that maps
	// "my dependency would not authorize this" onto an upstream error does.
	//
	// That produces one acceptance from the cache followed by refusals khaos
	// reads as `Unavailable`, in both fault windows. khaos reported it
	// `deviated / PERMITTED` with "this target's fallback is to allow",
	// because its order-sensitive counts reset on `Rejected` alone while this
	// experiment DECLARES a 503 as its fail-closed outcome. This mode is the
	// input the gate needs to be able to reject.
	AuthzCached = "cached"

	// Short enough to lapse several times inside a fault window, which is what
	// makes the cached acceptance the FIRST sample rather than the whole run.
	authzCacheFor = time.Second

	headerAuthzReason = "X-Khaos-Authz"

	reasonNotAuthenticated = "this service never issued that credential, which is its own check and not the dependency's"

	reasonAuthzAllowed = "the authorization dependency allowed it"

	reasonAuthzDenied = "the authorization dependency denied it"

	reasonAuthzUnknown = "the authorization dependency did not answer, and this mode refuses when it cannot tell"

	reasonAuthzFellOpen = "the authorization dependency did not answer, so this mode allowed it"

	reasonCollapsed = "the authorization dependency DENIED it and this mode read that as no answer, so it allowed it"

	reasonCachedAllow = "this caller's own authorization-decision cache still holds an allow for that credential"

	reasonCachedRefusal = "this caller's own authorization-decision cache still holds a refusal for that credential"

	// Three attempts, because the finding is the ask COUNT and one retry would
	// make it indistinguishable from a second probe arriving.
	authzAttempts = 3
	authzBackoff  = 50 * time.Millisecond
)

type authzGateway struct {
	dependency string
	mode       string
	client     *http.Client

	mu     sync.Mutex
	issued map[string]bool

	// decided is this caller's own authorization-decision cache, and only the
	// cached mode writes to it.
	decided map[string]verdictAt
}

// verdictAt is one cached authorization decision. A caller that caches is
// ordinary; what khaos was wrong about is how the cache's first sample reads
// once the refusals that follow it are 503s rather than 403s.
type verdictAt struct {
	allow bool
	at    time.Time
}

func newAuthzGateway(dependency, mode string) *authzGateway {
	return &authzGateway{
		dependency: dependency,
		mode:       mode,
		client:     &http.Client{Timeout: upstreamTimeout},
		issued:     map[string]bool{},
		decided:    map[string]verdictAt{},
	}
}

// refusalStatus is how THIS caller says no. A 503 is as common as a 403 in
// service-to-service code -- a service that maps a dependency's refusal onto an
// upstream error -- and khaos has to read both as the same refusal.
func (g *authzGateway) refusalStatus() int {
	if g.mode == AuthzCached {
		return http.StatusServiceUnavailable
	}

	return http.StatusForbidden
}

// cachedVerdict answers from this caller's own cache while the entry is fresh.
func (g *authzGateway) cachedVerdict(credential string) (bool, bool) {
	if g.mode != AuthzCached {
		return false, false
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	held, found := g.decided[credential]
	if !found || time.Since(held.at) > authzCacheFor {
		return false, false
	}

	return held.allow, true
}

func (g *authzGateway) remember(credential string, allow bool) {
	if g.mode != AuthzCached {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	g.decided[credential] = verdictAt{allow: allow, at: time.Now()}
}

func (g *authzGateway) routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc(routeAlive, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(routeHealth, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(routeProtected, g.protected)
	mux.HandleFunc(issuePath, g.issue)

	return mux
}

// issue hands out a credential this service will AUTHENTICATE, which is what
// lets khaos present one it will refuse as well as one it will accept.
func (g *authzGateway) issue(w http.ResponseWriter, _ *http.Request) {
	credential := rand.Text()

	g.mu.Lock()
	g.issued[credential] = true
	g.mu.Unlock()

	w.Header().Set(contentType, mimeJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"token":"` + credential + `"}`))
}

func (g *authzGateway) protected(w http.ResponseWriter, r *http.Request) {
	credential, scheme := strings.CutPrefix(
		r.Header.Get(headerAuthorization),
		bearerPrefix,
	)

	if !scheme || credential == "" {
		w.Header().Set(headerAuthzReason, reasonNoCredential)
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	g.mu.Lock()
	known := g.issued[credential]
	g.mu.Unlock()

	if !known {
		w.Header().Set(headerAuthzReason, reasonNotAuthenticated)
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	allow, reason := g.decide(credential)

	w.Header().Set(headerAuthzReason, reason)

	if allow {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(g.refusalStatus())
}

// decide is the whole fixture. One branch reads the dependency's three answers
// as three; the second reads "not 200" as "no answer"; the third reads them
// correctly and asks again every time it does not like one.
func (g *authzGateway) decide(credential string) (bool, string) {
	if allow, fresh := g.cachedVerdict(credential); fresh {
		if allow {
			return true, reasonCachedAllow
		}

		return false, reasonCachedRefusal
	}

	allow, reason := g.readDependency(credential)

	g.remember(credential, allow)

	return allow, reason
}

// readDependency asks and applies this mode's READING of the answer, which is
// the one line the whole experiment is about.
func (g *authzGateway) readDependency(credential string) (bool, string) {
	status, reached := g.ask(credential)

	switch g.mode {
	case AuthzCollapses:
		if reached && status == http.StatusForbidden {
			return true, reasonCollapsed
		}

		if !reached || status != http.StatusOK {
			return true, reasonAuthzFellOpen
		}

		return true, reasonAuthzAllowed

	case AuthzRetries:
		for attempt := 1; attempt < authzAttempts; attempt++ {
			if reached && status == http.StatusOK {
				break
			}

			time.Sleep(authzBackoff)

			status, reached = g.ask(credential)
		}
	}

	if !reached {
		return false, reasonAuthzUnknown
	}

	switch status {
	case http.StatusOK:
		return true, reasonAuthzAllowed

	case http.StatusForbidden, http.StatusUnauthorized:
		return false, reasonAuthzDenied

	default:
		// Unknown, and only unknown is eligible for a fallback policy. This
		// fixture's policy is to refuse.
		return false, reasonAuthzUnknown
	}
}

// ask forwards the credential to the authorization dependency the way an
// Envoy `ext_authz` filter does: the original request's Authorization header,
// and the RESPONSE STATUS is the decision.
func (g *authzGateway) ask(credential string) (int, bool) {
	request, err := http.NewRequest(http.MethodGet, g.dependency, nil)
	if err != nil {
		return 0, false
	}

	request.Header.Set(headerAuthorization, bearerPrefix+credential)

	response, err := g.client.Do(request)
	if err != nil {
		return 0, false
	}
	defer func() { _ = response.Body.Close() }()

	return response.StatusCode, true
}
