// ©AngelaMos | 2026
// helpers_test.go

package verifier_test

import (
	gocontext "context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/verifier"
)

// pair stands up a real provider on a real listener and a verifier pointed at
// it. The provider is reached over HTTP rather than in-process on purpose: the
// JWKS and introspection traps live in the HTTP handlers, so a verifier wired
// straight to the Go methods would never see them.
func pair(
	t *testing.T,
	mode verifier.Mode,
) (*idp.Provider, *verifier.Verifier) {
	t.Helper()

	provider, err := idp.New(idp.Config{})
	if err != nil {
		t.Fatalf("build a provider: %v", err)
	}

	if err := provider.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("bind a provider: %v", err)
	}

	t.Cleanup(func() { _ = provider.Close() })

	addr, err := provider.Addr()
	if err != nil {
		t.Fatalf("addr: %v", err)
	}

	root := "http://" + addr

	v := verifier.New(verifier.Config{
		Issuer:        provider.Issuer(),
		Audience:      idp.DefaultAudience,
		JWKSURI:       root + idp.RouteJWKS,
		IntrospectURI: root + idp.RouteIntrospect,
		Mode:          mode,
		KeyTTL:        keyTTL,
		DecisionTTL:   decisionTTL,
		Client:        &http.Client{Timeout: upstreamTimeout},
	})

	return provider, v
}

func context(t *testing.T) gocontext.Context {
	t.Helper()

	ctx, cancel := gocontext.WithTimeout(gocontext.Background(), 20*time.Second)
	t.Cleanup(cancel)

	return ctx
}

func orErr(err error, observable string) any {
	if err != nil {
		return err
	}
	if observable == "" {
		return "no observable appeared"
	}
	return observable
}

// serveSet publishes a key set khaos did not mint, which is the only way to
// reach the checks that khaos's own provider can never trip. khaos hard-codes
// `use: sig` and a 2048-bit modulus on everything it publishes, so a test
// restricted to khaos's own output cannot exercise either refusal.
func serveSet(t *testing.T, set idp.JWKSet) string {
	t.Helper()

	body, err := set.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}),
	)

	t.Cleanup(server.Close)

	return server.URL
}
