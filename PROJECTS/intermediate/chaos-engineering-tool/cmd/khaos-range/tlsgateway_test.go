// ©AngelaMos | 2026
// tlsgateway_test.go

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/pki"
	"github.com/CarterPerez-dev/khaos/internal/tlsclient"
)

// routes() panicked on a duplicate ServeMux pattern, which took the container
// down on startup with exit 2 and a stack trace. Nothing caught it: the package
// built, vetted and linted clean, because a duplicate registration is a runtime
// panic.
//
// This is the cheapest possible guard against that whole class, and it would
// have caught the original in milliseconds.
func TestEveryRoleBuildsItsRoutesWithoutPanicking(t *testing.T) {
	for _, role := range []string{
		roleIDP,
		roleGateway,
		roleVerifier,
		roleTLS,
		roleRogue,
		roleDB,
		roleSecret,
		roleAuthz,
		roleControl,
		roleControld,
	} {
		t.Run(role, func(t *testing.T) {
			handler, err := roleHandler(role)
			if err != nil {
				t.Fatalf("role %s: %v", role, err)
			}

			if handler == nil {
				t.Fatalf("role %s built no handler", role)
			}
		})
	}
}

// Every gateway has to answer its health route, because `range up --wait` waits
// on it and a gateway that does not is a range that never comes up.
func TestEveryRoleAnswersItsHealthRoute(t *testing.T) {
	for _, role := range []string{
		roleIDP,
		roleGateway,
		roleVerifier,
		roleTLS,
	} {
		t.Run(role, func(t *testing.T) {
			handler, err := roleHandler(role)
			if err != nil {
				t.Fatalf("role %s: %v", role, err)
			}

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(
				recorder,
				httptest.NewRequest(http.MethodGet, routeHealth, nil),
			)

			if recorder.Code != http.StatusOK {
				t.Fatalf(
					"role %s answered %d on %s, so `range up --wait` would never see it come up",
					role,
					recorder.Code,
					routeHealth,
				)
			}
		})
	}
}

// An unknown TLS mode must NOT fall back to the correct client. A fixture that
// quietly became correct would report every experiment in the family as
// fail-closed, which is the most expensive way to be wrong: the run is green
// and the finding is gone.
func TestAnUnknownTLSModeDoesNotBecomeTheCorrectClient(t *testing.T) {
	got := resolveTLSMode("not-a-mode")

	if got == tlsclient.Correct {
		t.Fatal(
			"an unparseable mode resolved to the correct client, so a typo in the range's environment would silently pass every tls experiment",
		)
	}
}

// And a mode that IS valid has to be honoured, or the gate cannot drive the
// gateway through the broken clients at all.
func TestAValidTLSModeIsHonoured(t *testing.T) {
	for _, name := range tlsclient.Modes() {
		t.Run(name, func(t *testing.T) {
			if got := resolveTLSMode(name); string(got) != name {
				t.Fatalf("mode %q resolved to %q", name, got)
			}
		})
	}
}

// The gateway refuses when it cannot reach its dependency at all, which is what
// makes the baseline fail loudly rather than a fault's measurement being
// quietly wrong. The default dependency address is deliberately unreachable.
func TestTheTLSGatewayRefusesAnUnreachableDependency(t *testing.T) {
	gateway := newTLSGateway(
		"http://127.0.0.1:1",
		"https://127.0.0.1:1",
		"http://127.0.0.1:1",
		pki.DefaultHost,
		FailClosed,
		string(tlsclient.Correct),
		0,
	)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, routeProtected, nil)
	request.Header.Set(headerAuthorization, bearerPrefix+"a-token")

	gateway.routes().ServeHTTP(recorder, request)

	if recorder.Code == http.StatusOK {
		t.Fatal(
			"the gateway served a request while its dependency was unreachable and its fail mode was closed",
		)
	}
}

// The dependency arrives as a URL and is DIALLED as an address. Handing the URL
// straight to the dialer produced
// `too many colons in address https://host.docker.internal:58520`, which
// reached the verdict as a failed handshake and voided the baseline of every
// certificate experiment. Only a live run against the range could find it,
// because every in-process test passed an address already.
func TestTheDependencyURLIsReducedToADialableAddress(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://host.docker.internal:58520", "host.docker.internal:58520"},
		{"http://127.0.0.1:9000", "127.0.0.1:9000"},

		// Already an address, so it passes through untouched.
		{"127.0.0.1:9000", "127.0.0.1:9000"},
	}

	for _, each := range cases {
		t.Run(each.raw, func(t *testing.T) {
			if got := dialAddress(each.raw); got != each.want {
				t.Fatalf("dialAddress(%q) = %q, want %q",
					each.raw, got, each.want)
			}
		})
	}
}

// The gateway against a REAL authority, end to end in one process.
//
// This is the test the range needed and did not have. The first live run
// reported `baseline-not-met`: the gateway refused valid traffic before any
// fault was armed, and nothing in the suite could say why because the only
// coverage was a Docker run whose authority died with it.
func TestTheTLSGatewayServesAgainstAnHonestAuthority(t *testing.T) {
	authority, err := pki.New(pki.Config{Host: pki.DefaultHost})
	if err != nil {
		t.Fatalf("build an authority: %v", err)
	}

	t.Cleanup(func() { _ = authority.Close() })

	if err := authority.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("bind revocation: %v", err)
	}

	if err := authority.ListenTLS("127.0.0.1:0"); err != nil {
		t.Fatalf("bind the dependency: %v", err)
	}

	if err := authority.Disarm(); err != nil {
		t.Fatalf("mint the honest chain: %v", err)
	}

	revocation, err := authority.Addr()
	if err != nil {
		t.Fatalf("revocation address: %v", err)
	}

	dependency, err := authority.TLSAddr()
	if err != nil {
		t.Fatalf("dependency address: %v", err)
	}

	client := tlsclient.New(tlsclient.Config{
		Mode:  tlsclient.Correct,
		Host:  pki.DefaultHost,
		Roots: authority.TrustedPool(),
	})

	decision := client.Decide(t.Context(), dependency)

	if !decision.Accepted {
		t.Fatalf(
			"the correct client refused khaos's own honest dependency at %s (%s); every tls experiment's baseline runs through this",
			dependency,
			decision.Reason,
		)
	}

	// And through the gateway's own trust-store fetch, which is the half the
	// client above skips by being handed a pool directly.
	gateway := newTLSGateway(
		"http://127.0.0.1:1",
		dependency,
		"http://"+revocation,
		pki.DefaultHost,
		FailClosed,
		string(tlsclient.Correct),
		0,
	)

	fetched := gateway.trustStore(t.Context())

	refetch := tlsclient.New(tlsclient.Config{
		Mode:  tlsclient.Correct,
		Host:  pki.DefaultHost,
		Roots: fetched,
	})

	if again := refetch.Decide(t.Context(), dependency); !again.Accepted {
		t.Fatalf(
			"the gateway's own fetched trust store could not verify the honest dependency (%s); the anchor it reads from %s is not the one the chain needs",
			again.Reason,
			revocation+pki.RouteRoot,
		)
	}
}
