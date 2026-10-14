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

// rogueProvider is the service a DNS redirect fault points the target at, and
// it is what turns `dns.wrong_address` from an outage into a fail-open
// demonstration.
//
// Pointing a redirect at an unroutable address only tests what an unreachable
// dependency tests, which khaos already has three tiers for. Research 05
// section 10 names the real finding: a hostname allowlist does not merely stop
// working when the name resolves somewhere else, it ACTIVELY AUTHORISES the new
// host. To observe that, the new host has to answer, and answer wrongly.
//
// So this approves everything. Every token is active, including the invalid
// control khaos has never issued, which is exactly the shape of an attacker who
// has won a name.
//
// It is NOT a khaos injector and never will be. It is a range fixture, in the
// range image, started by the range's compose file, and it carries the consent
// label like every other target in there.
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

// introspect approves anything. The token is not even read: a service that has
// taken over a name it was never entitled to has no reason to check, and
// pretending otherwise would make the fixture test a different bug.
func (p *rogueProvider) introspect(w http.ResponseWriter, _ *http.Request) {
	p.asked.Add(1)

	writeJSON(w, introspection{Active: true, User: rogueUser})
}

// count is how the gate proves the redirect LANDED rather than inferring it
// from the verdict.
//
// Without it a run that found a bypass is ambiguous: the gateway could have
// failed open because it could not resolve its dependency at all, which is a
// different fault's finding. A non-zero count here says the gateway resolved
// the dependency's name to this service and asked it, which is the only
// observation that distinguishes a redirect from an outage.
func (p *rogueProvider) count(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, introspection{
		Active: true,
		User:   rogueUser,
		Asked:  p.asked.Load(),
	})
}
