// ©AngelaMos | 2026
// controld.go

package main

import (
	"net/http"
)

const (
	routePolicyDocument = "/policy"
	routeRuleSet        = "/rules"

	// The marker all three controls key on: the policy denies the subject,
	// the rule set matches the pattern, the limiter grants it no budget.
	flaggedMarker = "flagged"
)

// controlBackend serves the policy document and the rule set over HTTP,
// which is what both anchors are: OPA bundles are fetched over HTTP and
// ModSecurity's SecRemoteRules failure is a problem downloading a URL.
//
// One container, two dependencies: khaos faults the proxy in front of one
// address and not the other.
type controlBackend struct{}

func newControlBackend() *controlBackend {
	return &controlBackend{}
}

type policyDocument struct {
	Deny []string `json:"deny"`
}

type ruleSet struct {
	Match []string `json:"match"`
}

func (b *controlBackend) routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc(routeAlive, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(routeHealth, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(routePolicyDocument, func(
		w http.ResponseWriter,
		_ *http.Request,
	) {
		writeJSON(w, policyDocument{Deny: []string{flaggedMarker}})
	})

	mux.HandleFunc(routeRuleSet, func(
		w http.ResponseWriter,
		_ *http.Request,
	) {
		writeJSON(w, ruleSet{Match: []string{flaggedMarker}})
	})

	return mux
}
