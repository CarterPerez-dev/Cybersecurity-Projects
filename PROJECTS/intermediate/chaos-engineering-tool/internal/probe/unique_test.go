// ©AngelaMos | 2026
// unique_test.go

package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

const (
	fixedToken = "a-credential-the-target-should-refuse"
	bearer     = "Bearer "
	samples    = 6
)

func recorder(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()

	var mu sync.Mutex
	seen := []string{}

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = append(seen, r.Header.Get("Authorization"))
			mu.Unlock()
			w.WriteHeader(http.StatusUnauthorized)
		}),
	)
	t.Cleanup(server.Close)

	return server, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string{}, seen...)
	}
}

// The negative control must carry a FRESH identity per request. A fixed invalid
// credential keeps the target's decision cache warm, so one cached refusal
// answers every probe and a control that stops enforcing during the fault is
// never exercised. Measured against the range before this existed: a gateway
// explicitly configured to fail open, with a cache TTL longer than the fault
// window, reported passed / HELD, conclusive, exit 0.
//
// Nothing else can observe this. HTTPProbe exposes no accessor for its token and
// Describe omits the credential, so the only way to see it is from the far end.
func TestTheNegativeControlCarriesAFreshCredentialPerRequest(t *testing.T) {
	server, sent := recorder(t)

	p := NewHTTP(HTTPOptions{
		Name:       "invalid-credential",
		URL:        server.URL,
		Token:      fixedToken,
		Credential: Invalid,
		Unique:     true,
	})

	for range samples {
		if outcome := p.Run(
			context.Background(),
		); outcome.Disposition != Rejected {
			t.Fatalf(
				"the recorder did not reject the credential, got %s",
				outcome.Disposition,
			)
		}
	}

	headers := sent()
	if len(headers) != samples {
		t.Fatalf("the target saw %d requests, want %d", len(headers), samples)
	}

	distinct := map[string]bool{}
	for _, header := range headers {
		if header == bearer+fixedToken {
			t.Fatalf(
				"the negative control sent the bare fixed credential %q; a credential-keyed "+
					"decision cache answers every probe from one cached refusal and a control that "+
					"stops enforcing during the fault is never exercised",
				fixedToken,
			)
		}
		distinct[header] = true
	}

	if len(distinct) != samples {
		t.Fatalf(
			"the negative control sent %d distinct credentials across %d requests; every "+
				"repeat is a probe the target can answer from cache",
			len(distinct),
			samples,
		)
	}
}

// The valid probe is the mirror: it must send the SAME credential every time, or
// the valid stream is measuring credential issuance rather than the control.
func TestTheValidProbeSendsOneStableCredential(t *testing.T) {
	server, sent := recorder(t)

	p := NewHTTP(HTTPOptions{
		Name:       "valid-credential",
		URL:        server.URL,
		Token:      fixedToken,
		Credential: Valid,
	})

	for range samples {
		p.Run(context.Background())
	}

	for i, header := range sent() {
		if header != bearer+fixedToken {
			t.Fatalf(
				"request %d carried %q, want the operator's credential unchanged",
				i,
				header,
			)
		}
	}
}
