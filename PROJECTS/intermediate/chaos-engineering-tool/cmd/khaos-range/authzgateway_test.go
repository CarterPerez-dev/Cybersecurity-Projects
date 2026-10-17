// ©AngelaMos | 2026
// authzgateway_test.go

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// stubAuthz is khaos's side of the experiment, reduced to what the fixture can
// observe: an answer it is told to give, and a count of how many times it was
// asked for one.
type stubAuthz struct {
	status atomic.Int64
	asked  atomic.Int64
	server *httptest.Server
}

func newStubAuthz(t *testing.T) *stubAuthz {
	t.Helper()

	stub := &stubAuthz{}
	stub.status.Store(http.StatusOK)

	stub.server = httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			stub.asked.Add(1)
			w.WriteHeader(int(stub.status.Load()))
		}),
	)
	t.Cleanup(stub.server.Close)

	return stub
}

func authzFixture(t *testing.T, mode string) (*authzGateway, *stubAuthz) {
	t.Helper()

	dependency := newStubAuthz(t)

	return newAuthzGateway(dependency.server.URL, mode), dependency
}

// issued asks the fixture for a credential it will AUTHENTICATE, which is the
// property that makes the whole experiment measurable: a caller that allows on
// any non-200 from its authorization dependency refuses nothing at all, and
// khaos's baseline guard would void the run rather than measure one.
func issued(t *testing.T, g *authzGateway) string {
	t.Helper()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, issuePath, nil)

	g.routes().ServeHTTP(recorder, request)

	var body struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decode the issued credential: %v", err)
	}

	if body.Token == "" {
		t.Fatal("the fixture issued no credential")
	}

	return body.Token
}

func askAuthz(t *testing.T, g *authzGateway, credential string) int {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, routeProtected, nil)
	if credential != "" {
		request.Header.Set(headerAuthorization, bearerPrefix+credential)
	}

	recorder := httptest.NewRecorder()
	g.routes().ServeHTTP(recorder, request)

	return recorder.Code
}

// Authentication is the fixture's OWN check and it is correct in every mode.
// Without it there is no baseline: the collapsing caller would refuse nothing,
// and an experiment against it could only ever report that the target was not
// enforcing anything to begin with.
func TestEveryModeAuthenticatesLocally(t *testing.T) {
	for _, mode := range []string{
		AuthzDistinguishes,
		AuthzCollapses,
		AuthzRetries,
	} {
		t.Run(mode, func(t *testing.T) {
			gateway, dependency := authzFixture(t, mode)

			if got := askAuthz(
				t,
				gateway,
				"a-credential-this-service-never-issued",
			); got != http.StatusUnauthorized {
				t.Fatalf(
					"an unissued credential returned %d, want %d: this check is what gives the experiment a baseline",
					got,
					http.StatusUnauthorized,
				)
			}

			if got := askAuthz(t, gateway, ""); got != http.StatusUnauthorized {
				t.Fatalf("no credential returned %d, want %d",
					got, http.StatusUnauthorized)
			}

			if asked := dependency.asked.Load(); asked != 0 {
				t.Fatalf(
					"the fixture asked its authorization dependency %d times about a credential it had not authenticated; the two checks are separate and khaos counts the second one",
					asked,
				)
			}
		})
	}
}

// The three callers, which are three cells of research 07 section 6.2's
// matrix. The deny is the row that separates them.
func TestTheThreeCallersReadADenyDifferently(t *testing.T) {
	for _, row := range []struct {
		mode      string
		wantDeny  int
		wantOut   int
		wantAsked int64
	}{
		{
			mode:      AuthzDistinguishes,
			wantDeny:  http.StatusForbidden,
			wantOut:   http.StatusForbidden,
			wantAsked: 1,
		},
		{
			mode:      AuthzCollapses,
			wantDeny:  http.StatusOK,
			wantOut:   http.StatusOK,
			wantAsked: 1,
		},
		{
			mode:      AuthzRetries,
			wantDeny:  http.StatusForbidden,
			wantOut:   http.StatusForbidden,
			wantAsked: authzAttempts,
		},
	} {
		t.Run(row.mode, func(t *testing.T) {
			gateway, dependency := authzFixture(t, row.mode)
			credential := issued(t, gateway)

			if got := askAuthz(
				t,
				gateway,
				credential,
			); got != http.StatusOK {
				t.Fatalf("an allowed credential returned %d, want 200", got)
			}

			dependency.status.Store(http.StatusForbidden)
			dependency.asked.Store(0)

			if got := askAuthz(t, gateway, credential); got != row.wantDeny {
				t.Fatalf(
					"under a definitive 403 from its dependency the caller answered %d, want %d",
					got,
					row.wantDeny,
				)
			}

			if asked := dependency.asked.Load(); asked != row.wantAsked {
				t.Fatalf(
					"the caller asked %d time(s) about a credential its dependency had refused, want %d",
					asked,
					row.wantAsked,
				)
			}

			dependency.status.Store(http.StatusServiceUnavailable)

			if got := askAuthz(t, gateway, credential); got != row.wantOut {
				t.Fatalf(
					"with its dependency unable to answer the caller answered %d, want %d",
					got,
					row.wantOut,
				)
			}
		})
	}
}

// The collapse has to be reached through the STATUS and not through a transport
// error, because that is the distinction the whole experiment is about: every
// network fault khaos already has produces the error, and only this tier can
// produce a definitive refusal.
func TestTheCollapseNamesWhichAnswerItIgnored(t *testing.T) {
	gateway, dependency := authzFixture(t, AuthzCollapses)
	credential := issued(t, gateway)

	dependency.status.Store(http.StatusForbidden)

	request := httptest.NewRequest(http.MethodGet, routeProtected, nil)
	request.Header.Set(headerAuthorization, bearerPrefix+credential)

	recorder := httptest.NewRecorder()
	gateway.routes().ServeHTTP(recorder, request)

	reason := recorder.Header().Get(headerAuthzReason)

	if !strings.Contains(reason, "DENIED") {
		t.Fatalf(
			"the collapsing caller allowed a denied credential and said %q, which does not say the dependency had refused it",
			reason,
		)
	}

	dependency.status.Store(http.StatusServiceUnavailable)

	outage := httptest.NewRecorder()
	gateway.routes().ServeHTTP(
		outage,
		request.Clone(request.Context()),
	)

	if outage.Header().Get(headerAuthzReason) == reason {
		t.Fatal(
			"the collapsing caller gives the same reason for a deny and for an outage; the fixture is the thing khaos measures, so the two have to be distinguishable in it even though its behaviour is not",
		)
	}
}

// A caller that cannot reach its dependency at all is the branch every network
// fault already reaches, and the correct modes must refuse there too.
func TestAnUnreachableDependencyIsRefusedByTheCorrectModes(t *testing.T) {
	for _, mode := range []string{AuthzDistinguishes, AuthzRetries} {
		t.Run(mode, func(t *testing.T) {
			gateway, dependency := authzFixture(t, mode)
			credential := issued(t, gateway)

			dependency.server.Close()

			if got := askAuthz(
				t,
				gateway,
				credential,
			); got != http.StatusForbidden {
				t.Fatalf(
					"with its dependency unreachable the caller answered %d, want %d",
					got,
					http.StatusForbidden,
				)
			}
		})
	}
}
