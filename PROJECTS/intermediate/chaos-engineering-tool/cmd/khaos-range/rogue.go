// ©AngelaMos | 2026
// rogue.go

package main

import (
	"net/http"
	"sync/atomic"
)

const (
	routeRogueCount = "/khaos-rogue-count"

	rogueUser = "whoever-asked"
)

// rogueProvider is the range fixture a DNS redirect points the target at. It
// approves everything, including the invalid control, because a hostname
// allowlist actively authorises the new host rather than merely failing.
type rogueProvider struct {
	asked atomic.Int64
}

func newRogueProvider() *rogueProvider {
	return &rogueProvider{}
}

func (p *rogueProvider) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(routeIntrospect, p.introspect)
	mux.HandleFunc(routeRogueCount, p.count)
	mux.HandleFunc(routeHealth, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return mux
}

// introspect approves anything and does not even read the token.
func (p *rogueProvider) introspect(w http.ResponseWriter, _ *http.Request) {
	p.asked.Add(1)

	writeJSON(w, introspection{Active: true, User: rogueUser})
}

// count reports how often the target actually asked, which is the only thing
// that tells a landed redirect apart from a failure to resolve at all.
func (p *rogueProvider) count(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, introspection{
		Active: true,
		User:   rogueUser,
		Asked:  p.asked.Load(),
	})
}
