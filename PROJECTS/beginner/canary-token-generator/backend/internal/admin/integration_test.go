// ©AngelaMos | 2026
// integration_test.go

//go:build integration

package admin_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/admin"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/testutil"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
)

const (
	intgBaseURL       = "https://canary.example.com"
	intgManageURL     = "https://canary.example.com"
	intgOperatorToken = "test-operator-token-CONSTANT-COMPARE-OK"
)

type intgURLBuilder struct{}

func (intgURLBuilder) TriggerURL(id string) string {
	return intgBaseURL + "/c/" + id
}

func (intgURLBuilder) ManageURL(manageID string) string {
	return intgManageURL + "/m/" + manageID
}

type intgStack struct {
	router    chi.Router
	tokenRepo *token.Repository
	eventRepo *event.Repository
}

func setupIntgStack(t *testing.T) *intgStack {
	t.Helper()
	db := sqlx.NewDb(testutil.NewTestDB(t), "pgx")

	tokenRepo := token.NewRepository(db)
	eventRepo := event.NewRepository(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	adminH := admin.NewHandler(tokenRepo, eventRepo, intgURLBuilder{}, logger)

	r := chi.NewRouter()
	r.Route("/api", func(api chi.Router) {
		api.Route("/admin", func(adm chi.Router) {
			adm.Use(middleware.OperatorBearer(intgOperatorToken))
			adminH.RegisterRoutes(adm)
		})
	})

	return &intgStack{router: r, tokenRepo: tokenRepo, eventRepo: eventRepo}
}

func seedIntgToken(
	t *testing.T,
	repo *token.Repository,
	id string,
	typ token.Type,
	ch token.AlertChannel,
) *token.Token {
	t.Helper()
	tok := &token.Token{
		ID:           id,
		ManageID:     uuid.New().String(),
		Type:         typ,
		Memo:         "admin-intg",
		AlertChannel: ch,
		CreatedIP:    "203.0.113.42",
		CreatedFP:    "abcdef0123456789",
		Metadata:     json.RawMessage(`{}`),
		Enabled:      true,
	}
	switch ch {
	case token.ChannelTelegram:
		tok.TelegramBot = testutil.Ptr("111:AAA")
		tok.TelegramChat = testutil.Ptr("12345")
	case token.ChannelWebhook:
		tok.WebhookURL = testutil.Ptr("https://example.com/hook")
	}
	require.NoError(t, repo.Insert(context.Background(), tok))
	return tok
}

func authedGet(
	t *testing.T,
	r chi.Router,
	path, tok string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func authedPost(
	t *testing.T,
	r chi.Router,
	path, tok string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestIntegration_AdminBearer_404OnMissing(t *testing.T) {
	st := setupIntgStack(t)
	w := authedGet(t, st.router, "/api/admin/stats", "")
	require.Equal(t, http.StatusNotFound, w.Code,
		"missing Authorization must return 404, not 401")
	require.Empty(t, w.Header().Get("WWW-Authenticate"))
}

func TestIntegration_AdminBearer_404OnWrongToken(t *testing.T) {
	st := setupIntgStack(t)
	w := authedGet(t, st.router, "/api/admin/stats", "wrong-token")
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestIntegration_AdminStats_Authorized(t *testing.T) {
	st := setupIntgStack(t)
	ctx := context.Background()

	tok := seedIntgToken(
		t,
		st.tokenRepo,
		"adminstats01",
		token.TypeWebbug,
		token.ChannelTelegram,
	)
	seedIntgToken(
		t,
		st.tokenRepo,
		"adminstats02",
		token.TypeDocx,
		token.ChannelWebhook,
	)

	require.NoError(t, st.eventRepo.Insert(ctx, &event.Event{
		TokenID: tok.ID, SourceIP: "203.0.113.50",
	}))

	w := authedGet(t, st.router, "/api/admin/stats", intgOperatorToken)
	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())

	var body struct {
		Success bool        `json:"success"`
		Data    admin.Stats `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.True(t, body.Success)
	require.GreaterOrEqual(t, body.Data.TokensCount, int64(2))
	require.GreaterOrEqual(t, body.Data.EventsCount, int64(1))
	require.NotEmpty(t, body.Data.ByType)
	require.NotEmpty(t, body.Data.ByAlertChannel)
}

func TestIntegration_AdminListTokens_Authorized(t *testing.T) {
	st := setupIntgStack(t)

	for i := range 4 {
		seedIntgToken(t, st.tokenRepo,
			"adminlist0"+string(rune('a'+i)),
			token.TypeWebbug, token.ChannelWebhook)
	}

	w := authedGet(t, st.router, "/api/admin/tokens?limit=2", intgOperatorToken)
	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())

	var body struct {
		Data admin.TokenListResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.Len(t, body.Data.Tokens, 2)
	require.GreaterOrEqual(t, body.Data.Total, int64(4))
	require.True(t, body.Data.Page.HasMore)
	require.Equal(t, 2, body.Data.Page.NextOffset)

	require.Contains(t, body.Data.Tokens[0].TriggerURL, "/c/")
	require.Contains(t, body.Data.Tokens[0].ManageURL, "/m/")
}

func TestIntegration_AdminDisableToken_Authorized(t *testing.T) {
	st := setupIntgStack(t)
	ctx := context.Background()

	tok := seedIntgToken(
		t,
		st.tokenRepo,
		"admindis001a",
		token.TypeWebbug,
		token.ChannelWebhook,
	)
	require.True(t, tok.Enabled)

	w := authedPost(t, st.router,
		"/api/admin/tokens/"+tok.ID+"/disable",
		intgOperatorToken)
	require.Equal(t, http.StatusNoContent, w.Code)

	got, err := st.tokenRepo.GetByID(ctx, tok.ID)
	require.NoError(t, err)
	require.False(t, got.Enabled, "disable must persist to DB")
}

func TestIntegration_AdminDisableToken_NotFound(t *testing.T) {
	st := setupIntgStack(t)

	w := authedPost(t, st.router,
		"/api/admin/tokens/admindismiss/disable",
		intgOperatorToken)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), `"NOT_FOUND"`)
}
