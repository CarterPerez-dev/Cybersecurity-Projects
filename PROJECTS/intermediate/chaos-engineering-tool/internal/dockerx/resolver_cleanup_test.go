// ©AngelaMos | 2026
// resolver_cleanup_test.go

package dockerx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestResolverCleanupSurvivesSetupCancellation(t *testing.T) {
	var removed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("API-Version", "1.56")
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodDelete &&
				strings.HasSuffix(r.URL.Path, "/containers/owned-resolver") {
				removed.Store(true)
				w.WriteHeader(http.StatusNoContent)
			}
		},
	))
	defer server.Close()
	client, err := Connect(t.Context(), Endpoint{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err = client.DiscardResolver(ctx, "owned-resolver", ctx.Err())
	if !removed.Load() || !errors.Is(err, context.Canceled) {
		t.Fatalf("setup cleanup: removed=%v error=%v", removed.Load(), err)
	}
}
