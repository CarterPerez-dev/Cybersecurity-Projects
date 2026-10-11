// ©AngelaMos | 2026
// routes.go

package pki

import (
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	routeDependency = "/"
	dependencyBody  = "khaos range dependency"

	// headerProbe marks a request as khaos's OWN confirmation probe, so the
	// counters can subtract it. Without this, "the target fetched the CRL"
	// would be true for every run in which khaos confirmed its own fault.
	headerProbe = "X-Khaos-Probe"
	probeValue  = "confirmation"
)

// routes is the revocation surface. RouteHealth is not decoration: it is the
// CONTROL for the two unreachable traps, and its entire job is to keep
// answering while the CRL or OCSP endpoint refuses. Without it, "khaos broke
// one endpoint" and "khaos fell over" are the same observation.
func (a *Authority) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(RouteCRL, a.serveCRL)
	mux.HandleFunc(RouteOCSP, a.serveOCSP)
	mux.HandleFunc(RouteHealth, a.serveHealth)

	return mux
}

// dependencyRoutes is what khaos answers once a client has got through the
// handshake. The body is deliberately trivial: this endpoint exists so that a
// client which ACCEPTED a bad certificate has something to succeed at, and the
// finding is the acceptance, not anything in the response.
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

func (a *Authority) serveCRL(w http.ResponseWriter, r *http.Request) {
	a.countCRL(r)

	trap := a.Trap()

	if trap.Kind == CRLUnreachable {
		refuse(w)

		return
	}

	chain, err := a.Served()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	der, err := a.CRLFor(trap, chain, a.clock())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set(headerType, mimePKIX)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}

func (a *Authority) serveOCSP(w http.ResponseWriter, r *http.Request) {
	a.countOCSP(r)

	trap := a.Trap()

	switch trap.Kind {
	case OCSPUnreachable:
		refuse(w)

		return

	case OCSPTryLater:
		// A protocol-level refusal, not a transport one. The responder IS
		// reachable and IS answering; it is declining to say. Research 04 calls
		// soft-fail the reason revocation is near-useless in practice, and this
		// is the exact shape that exploits it.
		w.Header().Set(headerType, mimeOCSP)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ocsp.TryLaterErrorResponse)

		return

	default:
		// Every other trap answers with a real, signed response.
	}

	chain, err := a.Served()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	der, err := a.ocspFor(trap, chain, a.clock())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set(headerType, mimeOCSP)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}

// refuse drops the connection without answering, which is what makes one route
// unreachable while its neighbour on the same listener keeps serving.
//
// Dropping the whole listener would be the more literal reading of "the
// responder is down", and it is the wrong choice: it would take RouteHealth
// with it, and then khaos could not show that it had broken one endpoint rather
// than fallen over. A hijacked connection is a transport failure the client
// cannot tell from a dead port, scoped to the route that is supposed to be
// dead.
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

// Now is the authority's clock, which the experiments need in order to assert
// about a validity window without racing a real one.
func (a *Authority) Now() time.Time {
	return a.clock()
}
