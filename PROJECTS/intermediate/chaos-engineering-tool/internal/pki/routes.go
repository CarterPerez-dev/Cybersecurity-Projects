// ©AngelaMos | 2026
// routes.go

package pki

import (
	"io"
	"net/http"
	"time"
)

const (
	routeDependency = "/"
	dependencyBody  = "khaos range dependency"

	// Marks a request as khaos's OWN probe, so the counters can subtract it.
	headerProbe = "X-Khaos-Probe"
	probeValue  = "confirmation"
)

func (a *Authority) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(RouteCRL, a.serveCRL)
	mux.HandleFunc(RouteOCSP, a.serveOCSP)
	mux.HandleFunc(RouteHealth, a.serveHealth)
	mux.HandleFunc(RouteRoot, a.serveRoot)
	mux.HandleFunc(RouteIdentity, a.serveIdentity)

	return mux
}

// The root the TARGET trusts, which for UntrustedCA is not the chain's own.
func (a *Authority) serveRoot(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(headerType, mimeDER)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(a.TrustedRoot().Raw)
}

func (a *Authority) dependencyRoutes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(
		routeDependency,
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, dependencyBody)
		},
	)

	return mux
}

func (a *Authority) serveHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, healthBody)
}

// Both handlers serve what the ARMED CHAIN carries and read no trap, so they
// cannot invent a fault the chain does not have. With nothing ever armed there
// is no chain and both answer 503, unlike getCertificate, which falls back to
// building an honest one.
func (a *Authority) serveCRL(w http.ResponseWriter, r *http.Request) {
	a.countCRL(r)

	chain, err := a.Served()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	der, reachable := chain.CRL()
	if !reachable {
		refuse(w)

		return
	}

	w.Header().Set(headerType, mimePKIX)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}

func (a *Authority) serveOCSP(w http.ResponseWriter, r *http.Request) {
	a.countOCSP(r)

	chain, err := a.Served()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	der, reachable := chain.OCSP()
	if !reachable {
		refuse(w)

		return
	}

	w.Header().Set(headerType, mimeOCSP)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}

// Hijacked rather than shut down, so one route dies while its neighbour on the
// same listener keeps serving, RouteHealth included.
func refuse(w http.ResponseWriter) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}

	_ = conn.Close()
}

func (a *Authority) countCRL(r *http.Request) {
	a.crlFetches.Add(1)

	if r.Header.Get(headerProbe) == probeValue {
		a.ownCRL.Add(1)
	}
}

func (a *Authority) countOCSP(r *http.Request) {
	a.ocspQueries.Add(1)

	if r.Header.Get(headerProbe) == probeValue {
		a.ownOCSP.Add(1)
	}
}

func (a *Authority) Now() time.Time {
	return a.clock()
}
