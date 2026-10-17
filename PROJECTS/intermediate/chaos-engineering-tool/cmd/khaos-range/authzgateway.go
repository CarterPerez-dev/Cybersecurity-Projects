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

	// AuthzCollapses is research 07 section 6.2's exact shape:
	//
	//	if err != nil || resp.StatusCode != 200 { return Allow }
	//
	// The dependency said no, loudly and correctly, and the caller read it as
	// "no answer". It is the single most common fail-open in service-to-service
	// code because error handling is usually written as "did it work" rather
	// than "what did it say".
	AuthzCollapses = "collapses"

	// AuthzRetries reaches the right verdict the wrong way: generic retry
	// middleware that retries any non-2xx, so a definitive refusal is asked
	// again and again. It fails CLOSED, which is why it is a third mode rather
	// than a variant of the second, and it is the shape research 07 section 6.2
	// step 4 names as the retry storm.
	AuthzRetries = "retries"

	headerAuthzReason = "X-Khaos-Authz"

	reasonNotAuthenticated = "this service never issued that credential, which is its own check and not the dependency's"

	reasonAuthzAllowed = "the authorization dependency allowed it"

	reasonAuthzDenied = "the authorization dependency denied it"

	reasonAuthzUnknown = "the authorization dependency did not answer, and this mode refuses when it cannot tell"

	reasonAuthzFellOpen = "the authorization dependency did not answer, so this mode allowed it"

	reasonCollapsed = "the authorization dependency DENIED it and this mode read that as no answer, so it allowed it"

	// Three attempts, because the finding is the ask COUNT and one retry would
	// make it indistinguishable from a second probe arriving.
	authzAttempts = 3
	authzBackoff  = 50 * time.Millisecond
)

// authzGateway is the CALLER, and the only range fixture whose dependency is
// not a container: khaos serves that itself, because no correct authorization
// service answers a definitive deny on request.
//
// AUTHENTICATION is this service's own job and it is correct in every mode.
// That separation is what makes the experiment measurable: a caller that allows
// on any non-200 from its authorization dependency has no authorization check
// at all, so khaos's baseline guard would correctly void a run against one that
// did nothing else. Research 07's row is about a service whose other checks
// work and whose authorization check collapses.
type authzGateway struct {
	dependency string
	mode       string
	client     *http.Client

	mu     sync.Mutex
	issued map[string]bool
}

func newAuthzGateway(dependency, mode string) *authzGateway {
	return &authzGateway{
		dependency: dependency,
		mode:       mode,
		client:     &http.Client{Timeout: upstreamTimeout},
		issued:     map[string]bool{},
	}
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

	w.WriteHeader(http.StatusForbidden)
}

// decide is the whole fixture. One branch reads the dependency's three answers
// as three; the second reads "not 200" as "no answer"; the third reads them
// correctly and asks again every time it does not like one.
func (g *authzGateway) decide(credential string) (bool, string) {
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
