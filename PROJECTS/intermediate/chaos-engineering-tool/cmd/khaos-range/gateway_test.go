// ©AngelaMos | 2026
// gateway_test.go

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	shortTTL  = 100 * time.Millisecond
	goodToken = "khaos-range-token-1"
)

type stubIDP struct {
	server    *httptest.Server
	down      atomic.Bool
	status    atomic.Int32
	calls     atomic.Int64
	validOnly string
}

func newStubIDP(t *testing.T) *stubIDP {
	t.Helper()

	stub := &stubIDP{validOnly: goodToken}
	stub.status.Store(http.StatusOK)

	stub.server = httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stub.calls.Add(1)

			if stub.down.Load() {
				hijackAndDrop(w)
				return
			}

			if status := int(stub.status.Load()); status != http.StatusOK {
				w.WriteHeader(status)
				return
			}

			token := r.URL.Query().Get(paramToken)
			writeJSON(
				w,
				introspection{
					Active: token == stub.validOnly,
					User:   "operator",
				},
			)
		}),
	)

	t.Cleanup(stub.server.Close)

	return stub
}

func hijackAndDrop(w http.ResponseWriter) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusGatewayTimeout)
		return
	}

	conn, _, err := hijacker.Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

func ask(t *testing.T, g *gateway, authorization string) int {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, routeProtected, nil)
	if authorization != "" {
		request.Header.Set(headerAuthorization, authorization)
	}

	recorder := httptest.NewRecorder()
	g.routes().ServeHTTP(recorder, request)

	return recorder.Code
}

func TestFailClosedServesFromCacheThenRefuses(t *testing.T) {
	idp := newStubIDP(t)
	g := newGateway(idp.server.URL, FailClosed, shortTTL, false)

	if got := ask(t, g, bearerPrefix+goodToken); got != http.StatusOK {
		t.Fatalf("baseline returned %d, want 200", got)
	}

	idp.down.Store(true)

	if got := ask(t, g, bearerPrefix+goodToken); got != http.StatusOK {
		t.Fatalf(
			"immediately after the outage the gateway returned %d; it should still be "+
				"serving from its decision cache",
			got,
		)
	}

	time.Sleep(shortTTL * 2)

	if got := ask(t, g, bearerPrefix+goodToken); got != http.StatusForbidden {
		t.Fatalf(
			"after the cache expired the gateway returned %d, want 403; a target that "+
				"serves from cache and then refuses has STOPPED serving, and asking only whether "+
				"it ever served reports that as a clean survival",
			got,
		)
	}
}

func TestFailOpenHonoursACredentialItHadRefused(t *testing.T) {
	idp := newStubIDP(t)
	g := newGateway(idp.server.URL, FailOpen, shortTTL, false)

	if got := ask(
		t,
		g,
		bearerPrefix+"never-issued",
	); got != http.StatusForbidden {
		t.Fatalf(
			"baseline returned %d for an invalid credential, want 403",
			got,
		)
	}

	idp.down.Store(true)
	time.Sleep(shortTTL * 2)

	if got := ask(t, g, bearerPrefix+"never-issued"); got != http.StatusOK {
		t.Fatalf(
			"returned %d; the fail-open mode exists to honour a credential it had already "+
				"refused, and if it does not the range cannot produce the finding khaos is for",
			got,
		)
	}
}

func TestARefusalFromTheProviderIsAnAnswerNotAnOutage(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			idp := newStubIDP(t)
			idp.status.Store(int32(status))

			g := newGateway(idp.server.URL, FailOpen, shortTTL, false)

			if got := ask(
				t,
				g,
				bearerPrefix+goodToken,
			); got != http.StatusForbidden {
				t.Fatalf(
					"the provider answered %d and the gateway returned %d; treating a "+
						"refusal from a dependency as 'dependency unavailable, proceed' is the most "+
						"common fail-open shape there is, and it must not be in the reference "+
						"implementation unlabelled",
					status,
					got,
				)
			}
		})
	}
}

func TestTheBearerSchemeIsRequired(t *testing.T) {
	idp := newStubIDP(t)
	g := newGateway(idp.server.URL, FailClosed, shortTTL, false)

	cases := map[string]int{
		bearerPrefix + goodToken: http.StatusOK,
		goodToken:                http.StatusUnauthorized,
		"Basic " + goodToken:     http.StatusUnauthorized,
		bearerPrefix:             http.StatusUnauthorized,
		"":                       http.StatusUnauthorized,
	}

	for authorization, want := range cases {
		name := authorization
		if name == "" {
			name = "no header"
		}

		t.Run(name, func(t *testing.T) {
			if got := ask(t, g, authorization); got != want {
				t.Fatalf("%q returned %d, want %d", authorization, got, want)
			}
		})
	}
}

func TestAFreshCredentialPerRequestDefeatsTheDecisionCache(t *testing.T) {
	idp := newStubIDP(t)
	g := newGateway(idp.server.URL, FailOpen, time.Hour, false)

	const probes = 3

	for range probes {
		ask(t, g, bearerPrefix+"never-issued")
	}

	repeated := idp.calls.Load()

	idp.calls.Store(0)
	for i := range probes {
		ask(t, g, bearerPrefix+"never-issued-"+strings.Repeat("x", i+1))
	}

	fresh := idp.calls.Load()

	if repeated >= fresh {
		t.Fatalf(
			"a repeated credential produced %d provider calls and a fresh one produced %d; "+
				"a negative control that reuses one token keeps the decision cache warm, so the "+
				"cached refusal answers every probe and a control that stops enforcing is never "+
				"exercised",
			repeated,
			fresh,
		)
	}
}

func TestTheProviderIssuesAndRevokes(t *testing.T) {
	provider := newIdentityProvider()
	server := httptest.NewServer(provider.routes())
	defer server.Close()

	response, err := http.Post(server.URL+routeToken, "", nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	var issued map[string]string
	if err := json.NewDecoder(response.Body).Decode(&issued); err != nil {
		t.Fatalf("decode: %v", err)
	}

	token := issued[paramToken]
	if token == "" {
		t.Fatal("the provider issued an empty token")
	}

	if !active(t, server.URL, token) {
		t.Fatal("a freshly issued token was not active")
	}

	revoked, err := http.Post(
		server.URL+routeRevoke+"?"+paramToken+"="+token,
		"",
		nil,
	)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_ = revoked.Body.Close()

	if active(t, server.URL, token) {
		t.Fatal("a revoked token was still active")
	}
}

func active(t *testing.T, base, token string) bool {
	t.Helper()

	response, err := http.Get(
		base + routeIntrospect + "?" + paramToken + "=" + token,
	)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	var body introspection
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	return body.Active
}

// The whole point of the stale-rearm mode: a cached allow that steady traffic
// keeps alive indefinitely and that a pause lets lapse. Deterministic, because
// the Docker version of this question cost two wrong predictions in a row.
func TestStaleRearmSurvivesSteadyTrafficAndLapsesOnAPause(t *testing.T) {
	idp := newStubIDP(t)
	g := newGateway(idp.server.URL, FailStaleRearm, shortTTL, false)

	// The provider is up, so this caches a genuine allow.
	if status := ask(t, g, bearerPrefix+goodToken); status != http.StatusOK {
		t.Fatalf("baseline status %d, want 200", status)
	}

	idp.down.Store(true)

	// Steady traffic at an interval longer than the lifetime but well inside the
	// ceiling. Every request lands on the stale path and re-arms the entry, so the
	// allow has to survive all of them.
	const beats = 6

	for beat := range beats {
		time.Sleep(shortTTL + shortTTL/2)

		if status := ask(
			t,
			g,
			bearerPrefix+goodToken,
		); status != http.StatusOK {
			t.Fatalf(
				"beat %d: status %d, want 200. Steady traffic must keep a re-armed cache "+
					"alive, or this mode is not the TTL-extension bug",
				beat,
				status,
			)
		}
	}

	// Now stop. Nothing re-arms, so the entry falls out of the ceiling.
	time.Sleep(shortTTL*staleCeilingFactor + shortTTL)

	if status := ask(t, g, bearerPrefix+goodToken); status == http.StatusOK {
		t.Fatalf(
			"after a pause longer than the ceiling the gateway still served the cached " +
				"allow, so this mode is a cache with no expiry rather than one being re-armed",
		)
	}
}

// The mirror, and the reason the ceiling exists. Without a bound this mode is
// indistinguishable from a no-expiry cache, which is the OTHER bug khaos has to
// tell it apart from.
func TestWithoutACeilingStaleRearmWouldBeANoExpiryCache(t *testing.T) {
	idp := newStubIDP(t)
	g := newGateway(idp.server.URL, FailStaleRearm, shortTTL, false)

	if ceiling := g.staleCeiling(); ceiling <= shortTTL {
		t.Fatalf(
			"the staleness ceiling is %s against a %s lifetime; a ceiling that is not "+
				"wider than the lifetime cannot be re-armed into",
			ceiling,
			shortTTL,
		)
	}

	if status := ask(t, g, bearerPrefix+goodToken); status != http.StatusOK {
		t.Fatalf("baseline status %d, want 200", status)
	}

	idp.down.Store(true)

	// One lifetime past expiry is inside the ceiling: served.
	time.Sleep(shortTTL * 2)
	if status := ask(t, g, bearerPrefix+goodToken); status != http.StatusOK {
		t.Fatalf("status %d inside the ceiling, want 200", status)
	}

	// Far past it is not, and that is the bound a no-expiry cache lacks.
	time.Sleep(shortTTL * (staleCeilingFactor + 2))
	if status := ask(t, g, bearerPrefix+goodToken); status == http.StatusOK {
		t.Fatal("a decision far outside the staleness ceiling was still served")
	}
}

// Fail-closed must not grow a stale path by accident. It is the reference
// implementation, and a 300-star teaching repo's correct side is what readers
// copy.
func TestFailClosedNeverServesAStaleDecision(t *testing.T) {
	idp := newStubIDP(t)
	g := newGateway(idp.server.URL, FailClosed, shortTTL, false)

	if status := ask(t, g, bearerPrefix+goodToken); status != http.StatusOK {
		t.Fatalf("baseline status %d, want 200", status)
	}

	idp.down.Store(true)
	time.Sleep(shortTTL * 2)

	if status := ask(t, g, bearerPrefix+goodToken); status == http.StatusOK {
		t.Fatal("the fail-closed gateway served a stale decision")
	}
}
