// ©AngelaMos | 2026
// handler_test.go

package admin_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/admin"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
)

const (
	testBaseURL   = "https://canary.example.com"
	testManageURL = "https://canary.example.com"
)

type fakeURLBuilder struct{}

func (fakeURLBuilder) TriggerURL(id string) string {
	return testBaseURL + "/c/" + id
}

func (fakeURLBuilder) ManageURL(manageID string) string {
	return testManageURL + "/m/" + manageID
}

type fakeTokenRepo struct {
	mu                sync.Mutex
	tokens            []token.Token
	disabledCalls     []string
	setEnabledErr     error
	listErr           error
	countErr          error
	countByTypeErr    error
	countByChannelErr error
}

func newFakeTokenRepo() *fakeTokenRepo {
	return &fakeTokenRepo{tokens: []token.Token{}}
}

func (f *fakeTokenRepo) ListAll(
	_ context.Context,
	opts token.ListOptions,
) ([]token.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	start := opts.Offset
	if start > len(f.tokens) {
		start = len(f.tokens)
	}
	end := start + opts.Limit
	if end > len(f.tokens) {
		end = len(f.tokens)
	}
	out := make([]token.Token, end-start)
	copy(out, f.tokens[start:end])
	return out, nil
}

func (f *fakeTokenRepo) CountAll(_ context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.countErr != nil {
		return 0, f.countErr
	}
	return int64(len(f.tokens)), nil
}

func (f *fakeTokenRepo) CountByType(
	_ context.Context,
) ([]token.TypeCount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.countByTypeErr != nil {
		return nil, f.countByTypeErr
	}
	counts := map[token.Type]int64{}
	for _, t := range f.tokens {
		counts[t.Type]++
	}
	out := []token.TypeCount{}
	for typ, c := range counts {
		out = append(out, token.TypeCount{Type: typ, Count: c})
	}
	return out, nil
}

func (f *fakeTokenRepo) CountByAlertChannel(
	_ context.Context,
) ([]token.ChannelCount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.countByChannelErr != nil {
		return nil, f.countByChannelErr
	}
	counts := map[token.AlertChannel]int64{}
	for _, t := range f.tokens {
		counts[t.AlertChannel]++
	}
	out := []token.ChannelCount{}
	for ch, c := range counts {
		out = append(out, token.ChannelCount{Channel: ch, Count: c})
	}
	return out, nil
}

func (f *fakeTokenRepo) SetEnabled(
	_ context.Context,
	id string,
	enabled bool,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disabledCalls = append(f.disabledCalls, id)
	if f.setEnabledErr != nil {
		return f.setEnabledErr
	}
	for i := range f.tokens {
		if f.tokens[i].ID == id {
			f.tokens[i].Enabled = enabled
			return nil
		}
	}
	return token.ErrNotFound
}

type fakeEventRepo struct {
	count int64
	err   error
}

func (f *fakeEventRepo) CountAll(_ context.Context) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.count, nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newRouter(h *admin.Handler) chi.Router {
	r := chi.NewRouter()
	h.Register(r)
	return r
}

func seedToken(id string, typ token.Type, ch token.AlertChannel) token.Token {
	return token.Token{
		ID:           id,
		ManageID:     "mng-" + id,
		Type:         typ,
		AlertChannel: ch,
		Enabled:      true,
		Metadata:     json.RawMessage(`{}`),
	}
}

func TestAdmin_GetStats_HappyPath(t *testing.T) {
	repo := newFakeTokenRepo()
	repo.tokens = []token.Token{
		seedToken("a01", token.TypeWebbug, token.ChannelTelegram),
		seedToken("a02", token.TypeWebbug, token.ChannelWebhook),
		seedToken("a03", token.TypeDocx, token.ChannelTelegram),
	}
	events := &fakeEventRepo{count: 17}
	h := admin.NewHandler(repo, events, fakeURLBuilder{}, quietLogger())
	r := newRouter(h)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stats", nil))

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var body struct {
		Success bool        `json:"success"`
		Data    admin.Stats `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.True(t, body.Success)
	require.Equal(t, int64(3), body.Data.TokensCount)
	require.Equal(t, int64(17), body.Data.EventsCount)
	require.NotEmpty(t, body.Data.ByType)
	require.NotEmpty(t, body.Data.ByAlertChannel)

	byType := map[token.Type]int64{}
	for _, c := range body.Data.ByType {
		byType[c.Type] = c.Count
	}
	require.Equal(t, int64(2), byType[token.TypeWebbug])
	require.Equal(t, int64(1), byType[token.TypeDocx])

	byChan := map[token.AlertChannel]int64{}
	for _, c := range body.Data.ByAlertChannel {
		byChan[c.Channel] = c.Count
	}
	require.Equal(t, int64(2), byChan[token.ChannelTelegram])
	require.Equal(t, int64(1), byChan[token.ChannelWebhook])
}

func TestAdmin_GetStats_TokenCountFails_500(t *testing.T) {
	repo := newFakeTokenRepo()
	repo.countErr = errors.New("db down")
	events := &fakeEventRepo{}
	h := admin.NewHandler(repo, events, fakeURLBuilder{}, quietLogger())
	r := newRouter(h)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stats", nil))

	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), `"INTERNAL_ERROR"`)
}

func TestAdmin_GetStats_EventCountFails_500(t *testing.T) {
	repo := newFakeTokenRepo()
	events := &fakeEventRepo{err: errors.New("redis down")}
	h := admin.NewHandler(repo, events, fakeURLBuilder{}, quietLogger())
	r := newRouter(h)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stats", nil))

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAdmin_ListTokens_DefaultPagination(t *testing.T) {
	repo := newFakeTokenRepo()
	for i := range 3 {
		repo.tokens = append(repo.tokens, seedToken(
			"t0"+string(rune('a'+i)),
			token.TypeWebbug,
			token.ChannelWebhook,
		))
	}
	h := admin.NewHandler(
		repo,
		&fakeEventRepo{},
		fakeURLBuilder{},
		quietLogger(),
	)
	r := newRouter(h)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tokens", nil))

	require.Equal(t, http.StatusOK, w.Code)
	var body struct {
		Success bool                    `json:"success"`
		Data    admin.TokenListResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.True(t, body.Success)
	require.Len(t, body.Data.Tokens, 3)
	require.Equal(t, int64(3), body.Data.Total)
	require.False(t, body.Data.Page.HasMore)
	require.Equal(t, 3, body.Data.Page.NextOffset)

	require.Equal(t, testBaseURL+"/c/t0a", body.Data.Tokens[0].TriggerURL)
	require.Equal(t, testManageURL+"/m/mng-t0a", body.Data.Tokens[0].ManageURL)
}

func TestAdmin_ListTokens_HasMoreWhenBeyondPage(t *testing.T) {
	repo := newFakeTokenRepo()
	for i := range 5 {
		repo.tokens = append(repo.tokens, seedToken(
			"row"+string(rune('a'+i)),
			token.TypeWebbug,
			token.ChannelWebhook,
		))
	}
	h := admin.NewHandler(
		repo,
		&fakeEventRepo{},
		fakeURLBuilder{},
		quietLogger(),
	)
	r := newRouter(h)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(
		http.MethodGet,
		"/tokens?limit=2",
		nil,
	))
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Data admin.TokenListResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.Len(t, body.Data.Tokens, 2)
	require.Equal(t, int64(5), body.Data.Total)
	require.True(t, body.Data.Page.HasMore)
	require.Equal(t, 2, body.Data.Page.NextOffset)
}

func TestAdmin_ListTokens_OffsetPagesThrough(t *testing.T) {
	repo := newFakeTokenRepo()
	for i := range 5 {
		repo.tokens = append(repo.tokens, seedToken(
			"pg"+string(rune('a'+i)),
			token.TypeWebbug,
			token.ChannelWebhook,
		))
	}
	h := admin.NewHandler(
		repo,
		&fakeEventRepo{},
		fakeURLBuilder{},
		quietLogger(),
	)
	r := newRouter(h)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(
		http.MethodGet,
		"/tokens?limit=2&offset=4",
		nil,
	))
	require.Equal(t, http.StatusOK, w.Code)
	var body struct {
		Data admin.TokenListResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.Len(t, body.Data.Tokens, 1)
	require.False(t, body.Data.Page.HasMore)
	require.Equal(t, 5, body.Data.Page.NextOffset)
}

func TestAdmin_ListTokens_InvalidOffset_400(t *testing.T) {
	repo := newFakeTokenRepo()
	h := admin.NewHandler(
		repo,
		&fakeEventRepo{},
		fakeURLBuilder{},
		quietLogger(),
	)
	r := newRouter(h)

	for _, badOffset := range []string{"-1", "abc", "1.5"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(
			http.MethodGet, "/tokens?offset="+badOffset, nil,
		))
		require.Equal(t, http.StatusBadRequest, w.Code, "offset=%s", badOffset)
		require.Contains(t, w.Body.String(), `"BAD_PARAM"`)
	}
}

func TestAdmin_ListTokens_LimitCappedAt100(t *testing.T) {
	repo := newFakeTokenRepo()
	for i := range 150 {
		repo.tokens = append(repo.tokens, seedToken(
			"lim"+strItoa(i),
			token.TypeWebbug,
			token.ChannelWebhook,
		))
	}
	h := admin.NewHandler(
		repo,
		&fakeEventRepo{},
		fakeURLBuilder{},
		quietLogger(),
	)
	r := newRouter(h)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(
		http.MethodGet,
		"/tokens?limit=500",
		nil,
	))
	require.Equal(t, http.StatusOK, w.Code)
	var body struct {
		Data admin.TokenListResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.Len(t, body.Data.Tokens, 100,
		"limit=500 must be capped to maxPageSize=100")
}

func TestAdmin_ListTokens_RepoError_500(t *testing.T) {
	repo := newFakeTokenRepo()
	repo.listErr = errors.New("db down")
	h := admin.NewHandler(
		repo,
		&fakeEventRepo{},
		fakeURLBuilder{},
		quietLogger(),
	)
	r := newRouter(h)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tokens", nil))
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAdmin_DisableToken_HappyPath(t *testing.T) {
	repo := newFakeTokenRepo()
	repo.tokens = []token.Token{
		seedToken("disok0001a", token.TypeWebbug, token.ChannelWebhook),
	}
	h := admin.NewHandler(
		repo,
		&fakeEventRepo{},
		fakeURLBuilder{},
		quietLogger(),
	)
	r := newRouter(h)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(
		http.MethodPost,
		"/tokens/disok0001a/disable",
		nil,
	))
	require.Equal(t, http.StatusNoContent, w.Code)
	require.False(t, repo.tokens[0].Enabled)
	require.Equal(t, []string{"disok0001a"}, repo.disabledCalls)
}

func TestAdmin_DisableToken_NotFound_404(t *testing.T) {
	repo := newFakeTokenRepo()
	h := admin.NewHandler(
		repo,
		&fakeEventRepo{},
		fakeURLBuilder{},
		quietLogger(),
	)
	r := newRouter(h)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(
		http.MethodPost,
		"/tokens/missing/disable",
		nil,
	))
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), `"NOT_FOUND"`)
}

func TestAdmin_DisableToken_RepoError_500(t *testing.T) {
	repo := newFakeTokenRepo()
	repo.tokens = []token.Token{
		seedToken("repoerr01a", token.TypeWebbug, token.ChannelWebhook),
	}
	repo.setEnabledErr = errors.New("db error")
	h := admin.NewHandler(
		repo,
		&fakeEventRepo{},
		fakeURLBuilder{},
		quietLogger(),
	)
	r := newRouter(h)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(
		http.MethodPost,
		"/tokens/repoerr01a/disable",
		nil,
	))
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), `"INTERNAL_ERROR"`)
}

func TestAdmin_DisableToken_GetIsNotRouted(t *testing.T) {
	repo := newFakeTokenRepo()
	repo.tokens = []token.Token{
		seedToken("methodtest1", token.TypeWebbug, token.ChannelWebhook),
	}
	h := admin.NewHandler(
		repo,
		&fakeEventRepo{},
		fakeURLBuilder{},
		quietLogger(),
	)
	r := newRouter(h)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(
		http.MethodGet,
		"/tokens/methodtest1/disable",
		nil,
	))
	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func strItoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var out []byte
	for i > 0 {
		out = append([]byte{digits[i%10]}, out...)
		i /= 10
	}
	return string(out)
}
