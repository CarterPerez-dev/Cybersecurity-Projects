// ©AngelaMos | 2026
// controlgateway.go

package main

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/secretfile"
)

const (
	routeLimited  = "/limited"
	routeGoverned = "/governed"
	routeFiltered = "/filtered"

	routeFlaggedToken = "/flagged-token"

	headerControlReason = "X-Khaos-Control"

	limitWindow = 10 * time.Second

	// Short enough that a severed dependency is felt inside one fault window.
	controlRefresh = 500 * time.Millisecond

	reasonWithinBudget = "the limiter counted this request and it is within the budget"

	reasonOverBudget = "the limiter counted this request and it is over the budget"

	reasonLimiterFellOpen = "the limiter could not reach its datastore, so this mode proxied the request anyway and the limit is not being enforced"

	reasonLimiterHeld = "the limiter could not reach its datastore, and this mode refuses rather than stop counting"

	reasonPolicyAllows = "the loaded policy does not deny this subject"

	reasonPolicyDenies = "the loaded policy denies this subject"

	reasonPolicyStale = "the policy store is unreachable, and this mode keeps enforcing the last policy it loaded"

	reasonPolicyDropped = "the policy store is unreachable, so this mode is enforcing no policy at all"

	reasonPolicyNeverLoaded = "this service started with its policy store unreachable and has never held a policy, so its policy set is empty and an empty policy set denies nothing"

	reasonPolicyCannotEvaluate = "this service has never loaded a policy and refuses rather than serve a request it cannot evaluate"

	reasonRulesClean = "no rule in the loaded set matches this request"

	reasonRulesMatched = "a rule in the loaded set matches this request"

	reasonRulesStale = "the rules backend is unreachable, and this mode keeps matching against the last set it loaded"

	reasonRulesDropped = "the rules backend is unreachable, so this mode is matching against no rules at all"

	reasonRulesNeverLoaded = "this service started with its rules backend unreachable and has never held a rule set, so nothing is being filtered"

	reasonRulesCannotFilter = "this service has never loaded a rule set and refuses rather than pass traffic it cannot inspect"
)

// controlGateway carries three security controls, each dialling its own
// dependency address so a fault on one leaves the other two answering.
//
// Authentication is this service's own job and is correct in every mode: a
// service with no other check refuses nothing, and khaos voids a run against
// a target it never observed refusing anything.
type controlGateway struct {
	store  string
	policy string
	rules  string

	failMode string
	limit    int64

	// secret is what this service authenticates WITH, rather than a set of
	// credentials it remembers issuing. The cold-start experiment restarts
	// this container, and a remembered set is empty afterwards: every
	// credential khaos holds reads as unknown, the valid stream goes 401, and
	// the run measures the restart instead of the policy.
	secret []byte

	client *http.Client

	mu      sync.Mutex
	denied  []string
	matched []string

	// Separates "lost what it had" from "never had any". A cold start is only
	// a distinct observation while those are two states.
	loadedPolicy bool
	loadedRules  bool

	freshPolicy bool
	freshRules  bool
}

func newControlGateway(
	store, policy, rules, failMode, secret string,
	limit int64,
) *controlGateway {
	return &controlGateway{
		store:    store,
		policy:   policy,
		rules:    rules,
		failMode: failMode,
		secret:   []byte(secret),
		limit:    limit,
		client:   &http.Client{Timeout: upstreamTimeout},
	}
}

func (g *controlGateway) routes() *http.ServeMux {
	go g.refreshing()

	mux := http.NewServeMux()

	mux.HandleFunc(routeAlive, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(routeHealth, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(issuePath, g.issue(false))
	mux.HandleFunc(routeFlaggedToken, g.issue(true))

	mux.HandleFunc(routeLimited, g.guard(g.limited))
	mux.HandleFunc(routeGoverned, g.guard(g.governed))
	mux.HandleFunc(routeFiltered, g.guard(g.filtered))

	return mux
}

// issue hands out a credential this service authenticates. The marker rides
// in the NONCE, so all three controls can read it off a signed credential and
// the signature still verifies after a restart.
func (g *controlGateway) issue(flagged bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		nonce := rand.Text()
		if flagged {
			nonce = flaggedMarker + "-" + nonce
		}

		w.Header().Set(contentType, mimeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(
			`{"token":"` + secretfile.Token(g.secret, nonce) + `"}`,
		))
	}
}

type decision struct {
	status int
	reason string
}

// guard authenticates, so a refusal from a control is never confused with
// this service failing to identify the caller.
func (g *controlGateway) guard(
	control func(string) decision,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		credential, scheme := strings.CutPrefix(
			r.Header.Get(headerAuthorization),
			bearerPrefix,
		)

		if !scheme || credential == "" {
			w.Header().Set(headerControlReason, reasonNoCredential)
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		if !secretfile.Verify(credential, g.secret) {
			w.Header().Set(headerControlReason, reasonNotAuthenticated)
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		outcome := control(credential)

		w.Header().Set(headerControlReason, outcome.reason)
		w.WriteHeader(outcome.status)
	}
}

func (g *controlGateway) failsOpen() bool {
	return g.failMode == FailOpen
}

// limited is F8. The budget is local and the counter is remote, so a severed
// datastore leaves the limiter knowing the limit and unable to apply it.
func (g *controlGateway) limited(credential string) decision {
	budget := g.limit
	if matches(credential, []string{flaggedMarker}) {
		budget = 0
	}

	window := time.Now().Unix() / int64(limitWindow.Seconds())
	key := credential + ":" + strconv.FormatInt(window, 10)

	count, err := respCount(g.store, key, limitWindow)
	if err != nil {
		if g.failsOpen() {
			return decision{http.StatusOK, reasonLimiterFellOpen}
		}

		return decision{http.StatusTooManyRequests, reasonLimiterHeld}
	}

	if count > budget {
		return decision{http.StatusTooManyRequests, reasonOverBudget}
	}

	return decision{http.StatusOK, reasonWithinBudget}
}

// governed is F11 and F12: losing a loaded policy, and never loading one.
func (g *controlGateway) governed(credential string) decision {
	g.mu.Lock()
	loaded, fresh := g.loadedPolicy, g.freshPolicy
	denied := append([]string(nil), g.denied...)
	g.mu.Unlock()

	if !loaded {
		if g.failsOpen() {
			return decision{http.StatusOK, reasonPolicyNeverLoaded}
		}

		return decision{http.StatusForbidden, reasonPolicyCannotEvaluate}
	}

	if !fresh && g.failsOpen() {
		return decision{http.StatusOK, reasonPolicyDropped}
	}

	if matches(credential, denied) {
		if fresh {
			return decision{http.StatusForbidden, reasonPolicyDenies}
		}

		return decision{http.StatusForbidden, reasonPolicyStale}
	}

	return decision{http.StatusOK, reasonPolicyAllows}
}

// filtered is F21. It hunts the operator's own fallback, not a vendor
// default: of the vendors that document one, both deny.
func (g *controlGateway) filtered(credential string) decision {
	g.mu.Lock()
	loaded, fresh := g.loadedRules, g.freshRules
	matched := append([]string(nil), g.matched...)
	g.mu.Unlock()

	if !loaded {
		if g.failsOpen() {
			return decision{http.StatusOK, reasonRulesNeverLoaded}
		}

		return decision{http.StatusForbidden, reasonRulesCannotFilter}
	}

	if !fresh && g.failsOpen() {
		return decision{http.StatusOK, reasonRulesDropped}
	}

	if matches(credential, matched) {
		if fresh {
			return decision{http.StatusForbidden, reasonRulesMatched}
		}

		return decision{http.StatusForbidden, reasonRulesStale}
	}

	return decision{http.StatusOK, reasonRulesClean}
}

func matches(credential string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern != "" && strings.Contains(credential, pattern) {
			return true
		}
	}

	return false
}

// refreshing re-fetches on an interval rather than per request: holding a
// last-known-good is what makes "lost it" and "never had it" two states.
func (g *controlGateway) refreshing() {
	g.refreshOnce()

	for range time.Tick(controlRefresh) {
		g.refreshOnce()
	}
}

func (g *controlGateway) refreshOnce() {
	var document policyDocument
	policyOK := g.fetch(g.policy+routePolicyDocument, &document)

	var set ruleSet
	rulesOK := g.fetch(g.rules+routeRuleSet, &set)

	g.mu.Lock()
	defer g.mu.Unlock()

	g.freshPolicy = policyOK
	if policyOK {
		g.loadedPolicy = true
		g.denied = document.Deny
	}

	g.freshRules = rulesOK
	if rulesOK {
		g.loadedRules = true
		g.matched = set.Match
	}
}

func (g *controlGateway) fetch(url string, into any) bool {
	response, err := g.client.Get(url)
	if err != nil {
		return false
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return false
	}

	return json.NewDecoder(response.Body).Decode(into) == nil
}
