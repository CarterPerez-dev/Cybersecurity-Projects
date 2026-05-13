// ©AngelaMos | 2026
// recovery_test.go

package middleware_test

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRecovery_PanicReturns500(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	h := middleware.Recovery(
		logger,
	)(
		http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			panic("boom")
		}),
	)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), `"INTERNAL_ERROR"`)
	require.Contains(t, buf.String(), "handler panic")
	require.Contains(t, buf.String(), "boom")
}

func TestRecovery_NoPanicPassesThrough(t *testing.T) {
	h := middleware.Recovery(
		quietLogger(),
	)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
			if _, err := w.Write([]byte("ok")); err != nil {
				t.Fatalf("write: %v", err)
			}
		}),
	)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, http.StatusTeapot, w.Code)
	require.Equal(t, "ok", w.Body.String())
}

func TestRecovery_LogsRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	chain := middleware.RequestID(
		middleware.Recovery(
			logger,
		)(
			http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				panic("boom")
			}),
		),
	)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("X-Request-ID", "test-rid-123")
	chain.ServeHTTP(w, r)

	require.Contains(t, buf.String(), "test-rid-123")
}
