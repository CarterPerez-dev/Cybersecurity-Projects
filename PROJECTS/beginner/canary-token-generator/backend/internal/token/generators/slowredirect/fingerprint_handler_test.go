// ©AngelaMos | 2026
// fingerprint_handler_test.go

//go:build integration

package slowredirect_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/testutil"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/slowredirect"
)

const (
	fingerprintRoute = "/c/{id}/fingerprint"
	clientIP         = "203.0.113.45"
	jsonContentType  = "application/json"
)

func newSlowredirectRepos(
	t *testing.T,
) (*token.Repository, *event.Repository) {
	t.Helper()
	db := sqlx.NewDb(testutil.NewTestDB(t), "pgx")
	return token.NewRepository(db), event.NewRepository(db)
}

func seedSlowredirectToken(
	t *testing.T,
	repo *token.Repository,
	id, destination string,
) *token.Token {
	t.Helper()
	metaJSON, err := json.Marshal(map[string]string{
		"destination_url": destination,
	})
	require.NoError(t, err)
	tok := &token.Token{
		ID:           id,
		ManageID:     uuid.New().String(),
		Type:         token.TypeSlowRedirect,
		Memo:         "integration-fp",
		AlertChannel: token.ChannelWebhook,
		WebhookURL:   testutil.Ptr("https://example.com/hook"),
		CreatedIP:    clientIP,
		CreatedFP:    "abcdef0123456789",
		Metadata:     json.RawMessage(metaJSON),
		Enabled:      true,
	}
	require.NoError(t, repo.Insert(context.Background(), tok))
	return tok
}

func seedSlowredirectEvent(
	t *testing.T,
	evtRepo *event.Repository,
	tokenID string,
) *event.Event {
	t.Helper()
	e := &event.Event{
		TokenID:  tokenID,
		SourceIP: clientIP,
		Extra:    json.RawMessage(`{"initial":"value"}`),
	}
	require.NoError(t, evtRepo.Insert(context.Background(), e))
	return e
}

func mountFingerprintRouter(h http.Handler) http.Handler {
	r := chi.NewRouter()
	r.Post(fingerprintRoute, h.ServeHTTP)
	return r
}

func postFingerprint(
	router http.Handler,
	tokenID, contentType string,
	body []byte,
) *httptest.ResponseRecorder {
	req := httptest.NewRequest(
		http.MethodPost,
		"/c/"+tokenID+"/fingerprint",
		bytes.NewReader(body),
	)
	req.Header.Set("CF-Connecting-IP", clientIP)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestFingerprintHandler_AttachesToRecentEvent(t *testing.T) {
	t.Parallel()
	tokRepo, evtRepo := newSlowredirectRepos(t)
	ctx := context.Background()

	tok := seedSlowredirectToken(t, tokRepo, "fpattach0001",
		"https://news.example.com")
	evt := seedSlowredirectEvent(t, evtRepo, tok.ID)

	router := mountFingerprintRouter(
		slowredirect.NewFingerprintHandler(evtRepo),
	)

	fpBody := []byte(
		`{"screen":{"w":1920,"h":1080},"timezone":"America/Los_Angeles"}`,
	)
	rr := postFingerprint(router, tok.ID, jsonContentType, fpBody)
	require.Equal(t, http.StatusNoContent, rr.Code)

	got, err := evtRepo.GetByID(ctx, evt.ID)
	require.NoError(t, err)

	var merged map[string]any
	require.NoError(t, json.Unmarshal(got.Extra, &merged))
	require.Equal(t, "value", merged["initial"])
	require.Equal(t, "America/Los_Angeles", merged["timezone"])
	screen, ok := merged["screen"].(map[string]any)
	require.True(t, ok, "screen sub-object must round-trip as nested map")
	require.EqualValues(t, 1920, screen["w"])
	require.EqualValues(t, 1080, screen["h"])
}

func TestFingerprintHandler_NoMatchingEvent_Returns204(t *testing.T) {
	t.Parallel()
	tokRepo, evtRepo := newSlowredirectRepos(t)

	tok := seedSlowredirectToken(t, tokRepo, "fpnomatch001",
		"https://news.example.com")

	router := mountFingerprintRouter(
		slowredirect.NewFingerprintHandler(evtRepo),
	)

	rr := postFingerprint(
		router, tok.ID, jsonContentType,
		[]byte(`{"screen":{"w":800,"h":600}}`),
	)
	require.Equal(
		t,
		http.StatusNoContent,
		rr.Code,
		"no matching event must still return 204 — fingerprint is enrichment, not the trigger",
	)
}

func TestFingerprintHandler_InvalidJSON_Returns204AndDoesNotTouchEvent(
	t *testing.T,
) {
	t.Parallel()
	tokRepo, evtRepo := newSlowredirectRepos(t)
	ctx := context.Background()

	tok := seedSlowredirectToken(t, tokRepo, "fpinvjson001",
		"https://news.example.com")
	evt := seedSlowredirectEvent(t, evtRepo, tok.ID)

	router := mountFingerprintRouter(
		slowredirect.NewFingerprintHandler(evtRepo),
	)

	rr := postFingerprint(
		router, tok.ID, jsonContentType,
		[]byte("not-json-at-all"),
	)
	require.Equal(t, http.StatusNoContent, rr.Code)

	got, err := evtRepo.GetByID(ctx, evt.ID)
	require.NoError(t, err)

	var stored map[string]any
	require.NoError(t, json.Unmarshal(got.Extra, &stored))
	require.Equal(
		t,
		"value",
		stored["initial"],
		"invalid JSON must not corrupt the stored Extra JSONB",
	)
}

func TestFingerprintHandler_WrongContentType_Returns204AndDoesNotTouchEvent(
	t *testing.T,
) {
	t.Parallel()
	tokRepo, evtRepo := newSlowredirectRepos(t)
	ctx := context.Background()

	tok := seedSlowredirectToken(t, tokRepo, "fpctype00001",
		"https://news.example.com")
	evt := seedSlowredirectEvent(t, evtRepo, tok.ID)

	router := mountFingerprintRouter(
		slowredirect.NewFingerprintHandler(evtRepo),
	)

	rr := postFingerprint(
		router, tok.ID,
		"text/plain",
		[]byte(`{"screen":{"w":1024,"h":768}}`),
	)
	require.Equal(
		t,
		http.StatusNoContent,
		rr.Code,
		"non-JSON content-type must be ignored — handler only processes the embedded template's POST",
	)

	got, err := evtRepo.GetByID(ctx, evt.ID)
	require.NoError(t, err)

	var stored map[string]any
	require.NoError(t, json.Unmarshal(got.Extra, &stored))
	require.Equal(t, "value", stored["initial"])
	_, mergedAnyway := stored["screen"]
	require.False(
		t,
		mergedAnyway,
		"event Extra must not absorb a payload whose content-type was rejected",
	)
}

func TestFingerprintHandler_OversizeBody_Returns204AndDoesNotTouchEvent(
	t *testing.T,
) {
	t.Parallel()
	tokRepo, evtRepo := newSlowredirectRepos(t)
	ctx := context.Background()

	tok := seedSlowredirectToken(t, tokRepo, "fpoversz0001",
		"https://news.example.com")
	evt := seedSlowredirectEvent(t, evtRepo, tok.ID)

	router := mountFingerprintRouter(
		slowredirect.NewFingerprintHandler(evtRepo),
	)

	const oversizeBytes = 128 * 1024
	junk := strings.Repeat("A", oversizeBytes)
	body := []byte(`{"junk":"` + junk + `"}`)
	require.Greater(t, len(body), 64*1024)

	rr := postFingerprint(router, tok.ID, jsonContentType, body)
	require.Equal(
		t,
		http.StatusNoContent,
		rr.Code,
		"body over the 64 KiB cap must still return 204 — no error surfaces to the client",
	)

	got, err := evtRepo.GetByID(ctx, evt.ID)
	require.NoError(t, err)

	var stored map[string]any
	require.NoError(t, json.Unmarshal(got.Extra, &stored))
	require.Equal(t, "value", stored["initial"])
	_, mergedAnyway := stored["junk"]
	require.False(
		t,
		mergedAnyway,
		"oversize body must not be merged into Extra — MaxBytesReader cuts before AttachFingerprint",
	)
}

func TestFingerprintHandler_EmptyTokenID_Returns204(t *testing.T) {
	t.Parallel()
	_, evtRepo := newSlowredirectRepos(t)

	handler := slowredirect.NewFingerprintHandler(evtRepo)
	r := chi.NewRouter()
	r.Post("/c/{id}/fingerprint", handler.ServeHTTP)

	req := httptest.NewRequest(
		http.MethodPost,
		"/c//fingerprint",
		bytes.NewReader([]byte(`{}`)),
	)
	req.Header.Set("Content-Type", jsonContentType)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Contains(
		t,
		[]int{
			http.StatusNoContent,
			http.StatusNotFound,
			http.StatusMovedPermanently,
		},
		rr.Code,
		"empty token id must not produce a 5xx — handler's guard returns 204, chi may also redirect or 404 at the routing layer",
	)
}
