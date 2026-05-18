// ©AngelaMos | 2026
// handler_test.go

package token_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
)

type triggerGen struct {
	tokenType token.Type
	artifact  generators.Artifact
	resp      *generators.TriggerResponse
	evt       *event.Event
}

func (g *triggerGen) Type() token.Type { return g.tokenType }

func (g *triggerGen) Generate(
	_ context.Context,
	_ *token.Token,
	_ string,
) (generators.Artifact, error) {
	return g.artifact, nil
}

func (g *triggerGen) Trigger(
	_ context.Context,
	_ *token.Token,
	_ *http.Request,
) (*event.Event, *generators.TriggerResponse, error) {
	return g.evt, g.resp, nil
}

type recordingEvents struct {
	events []*event.Event
}

func (r *recordingEvents) Record(
	_ context.Context,
	_ *token.Token,
	e *event.Event,
) error {
	r.events = append(r.events, e)
	return nil
}

func quietHandlerLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newWebbugHandler(
	t *testing.T,
	gen token.Generator,
) (*token.Handler, *fakeRepo, *recordingEvents) {
	t.Helper()
	repo := newFakeRepo()
	rec := &recordingEvents{}
	svc := token.NewService(
		repo,
		token.MapRegistry{token.TypeWebbug: gen},
		token.ServiceConfig{
			BaseURL:   "https://canary.example.com",
			ManageURL: "https://canary.example.com",
		},
	)
	return token.NewHandler(
		svc,
		rec,
		nil,
		nil,
		nil,
		quietHandlerLogger(),
		false,
	), repo, rec
}

func TestGetTypes_Returns7Types(t *testing.T) {
	svc := token.NewService(newFakeRepo(), token.MapRegistry{},
		token.ServiceConfig{BaseURL: "https://x.test"})
	h := token.NewHandler(svc, nil, nil, nil, nil, quietHandlerLogger(), false)

	r := chi.NewRouter()
	h.RegisterAPIRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tokens/types", nil))

	require.Equal(t, http.StatusOK, w.Code)
	var body struct {
		Success bool                   `json:"success"`
		Data    []token.TypeDescriptor `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.True(t, body.Success)
	require.Len(t, body.Data, 7)
}

func TestCreateToken_HappyPath(t *testing.T) {
	gen := &triggerGen{
		tokenType: token.TypeWebbug,
		artifact: generators.Artifact{
			Kind: generators.KindURL, URL: "https://canary.example.com/c/x",
		},
	}
	h, _, _ := newWebbugHandler(t, gen)

	r := chi.NewRouter()
	h.RegisterAPIRoutes(r)

	body := strings.NewReader(`{
		"type":"webbug","memo":"m","alert_channel":"webhook",
		"webhook_url":"https://example.com/h","cf_turnstile_response":"t",
		"metadata":{}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Token    token.Response     `json:"token"`
			Artifact token.ArtifactJSON `json:"artifact"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.True(t, resp.Success)
	require.Equal(t, token.TypeWebbug, resp.Data.Token.Type)
	require.NotEmpty(t, resp.Data.Token.ID)
	require.Contains(t, resp.Data.Token.TriggerURL, "/c/")
	require.Contains(t, resp.Data.Token.ManageURL, "/m/")
	require.Equal(t, "url", resp.Data.Artifact.Kind)
}

func TestCreateToken_BadJSON(t *testing.T) {
	gen := &triggerGen{tokenType: token.TypeWebbug}
	h, _, _ := newWebbugHandler(t, gen)

	r := chi.NewRouter()
	h.RegisterAPIRoutes(r)

	req := httptest.NewRequest(
		http.MethodPost,
		"/tokens",
		strings.NewReader(`{not json`),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "BAD_JSON")
}

func TestCreateToken_ValidationFailure(t *testing.T) {
	gen := &triggerGen{tokenType: token.TypeWebbug}
	h, _, _ := newWebbugHandler(t, gen)

	r := chi.NewRouter()
	h.RegisterAPIRoutes(r)

	body := strings.NewReader(
		`{"type":"webbug","memo":"m","cf_turnstile_response":"t"}`,
	)
	req := httptest.NewRequest(http.MethodPost, "/tokens", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "VALIDATION_ERROR")
}

func TestHandleTrigger_KnownTokenReturnsResponseAndRecordsEvent(t *testing.T) {
	gen := &triggerGen{
		tokenType: token.TypeWebbug,
		artifact:  generators.Artifact{Kind: generators.KindURL},
		resp: &generators.TriggerResponse{
			StatusCode:  200,
			ContentType: "image/gif",
			Body:        []byte{0x47, 0x49, 0x46, 0x38},
		},
		evt: &event.Event{SourceIP: "1.2.3.4"},
	}
	h, repo, rec := newWebbugHandler(t, gen)

	tok := &token.Token{
		ID: "abcdef012345", ManageID: "m", Type: token.TypeWebbug,
		AlertChannel: token.ChannelWebhook, Enabled: true,
		Metadata: json.RawMessage(`{}`),
	}
	require.NoError(t, repo.Insert(context.Background(), tok))

	r := chi.NewRouter()
	h.RegisterTriggerRoutes(r)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/c/abcdef012345", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "image/gif", w.Header().Get("Content-Type"))
	require.Equal(t, []byte{0x47, 0x49, 0x46, 0x38}, w.Body.Bytes())
	require.Len(t, rec.events, 1)
}

func TestHandleTrigger_TrimsTrailingUnderscoresFromPaddedID(t *testing.T) {
	gen := &triggerGen{
		tokenType: token.TypeWebbug,
		artifact:  generators.Artifact{Kind: generators.KindURL},
		resp: &generators.TriggerResponse{
			StatusCode:  200,
			ContentType: "image/gif",
			Body:        []byte{0x47},
		},
		evt: &event.Event{SourceIP: "1.2.3.4"},
	}
	h, repo, rec := newWebbugHandler(t, gen)

	tok := &token.Token{
		ID: "abcdef012345", ManageID: "m", Type: token.TypeWebbug,
		AlertChannel: token.ChannelWebhook, Enabled: true,
		Metadata: json.RawMessage(`{}`),
	}
	require.NoError(t, repo.Insert(context.Background(), tok))

	r := chi.NewRouter()
	h.RegisterTriggerRoutes(r)

	w := httptest.NewRecorder()
	padded := "/c/abcdef012345____________________"
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, padded, nil))

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, rec.events, 1,
		"trailing-underscore padded id must still resolve to the real token "+
			"so PDFs already in the field (carrying padded URLs) record events "+
			"instead of silently no-opping (audit finding F2)")
}

func TestHandleTrigger_UnknownTokenStillReturnsArtifactShape(t *testing.T) {
	gen := &triggerGen{
		tokenType: token.TypeWebbug,
		resp: &generators.TriggerResponse{
			StatusCode:  200,
			ContentType: "image/gif",
			Body:        []byte{0x47, 0x49, 0x46},
		},
	}
	h, _, rec := newWebbugHandler(t, gen)

	r := chi.NewRouter()
	h.RegisterTriggerRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/c/nonexistent1", nil))

	require.Equal(t, http.StatusOK, w.Code,
		"unknown tokens still return artifact shape (defense in depth)")
	require.Empty(t, rec.events, "no event recorded for unknown token")
}

func TestHandleTrigger_DisabledTokenIsTreatedAsUnknown(t *testing.T) {
	gen := &triggerGen{
		tokenType: token.TypeWebbug,
		resp: &generators.TriggerResponse{
			StatusCode:  200,
			ContentType: "image/gif",
			Body:        []byte{0x47},
		},
		evt: &event.Event{SourceIP: "1.2.3.4"},
	}
	h, repo, rec := newWebbugHandler(t, gen)

	tok := &token.Token{
		ID: "disabled1234", ManageID: "m", Type: token.TypeWebbug,
		AlertChannel: token.ChannelWebhook, Enabled: false,
		Metadata: json.RawMessage(`{}`),
	}
	require.NoError(t, repo.Insert(context.Background(), tok))

	r := chi.NewRouter()
	h.RegisterTriggerRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/c/disabled1234", nil))

	require.Equal(t, http.StatusOK, w.Code)
	require.Empty(t, rec.events, "disabled token must not record events")
}

func TestHandleFingerprint_Returns204WithNoRecorder(t *testing.T) {
	gen := &triggerGen{tokenType: token.TypeWebbug}
	h, _, _ := newWebbugHandler(t, gen)

	r := chi.NewRouter()
	h.RegisterTriggerRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/c/anything/fingerprint", strings.NewReader(`{"x":1}`)))

	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestArtifactToJSON_Kinds(t *testing.T) {
	cases := []struct {
		name string
		in   generators.Artifact
		want token.ArtifactJSON
	}{
		{
			"url",
			generators.Artifact{
				Kind:           generators.KindURL,
				URL:            "u",
				DestinationURL: "d",
			},
			token.ArtifactJSON{Kind: "url", URL: "u", DestinationURL: "d"},
		},
		{
			"file",
			generators.Artifact{
				Kind:        generators.KindFile,
				Filename:    "f.docx",
				ContentType: "x",
				Content:     []byte("hi"),
			},
			token.ArtifactJSON{
				Kind:        "file",
				Filename:    "f.docx",
				ContentType: "x",
				ContentB64:  "aGk=",
			},
		},
		{
			"text",
			generators.Artifact{
				Kind:        generators.KindText,
				Filename:    ".env",
				ContentType: "text/plain",
				Content:     []byte("KEY=v"),
			},
			token.ArtifactJSON{
				Kind:        "text",
				Filename:    ".env",
				ContentType: "text/plain",
				Content:     "KEY=v",
			},
		},
		{
			"conn",
			generators.Artifact{
				Kind:             generators.KindConnectionString,
				ConnectionString: "mysql://x",
			},
			token.ArtifactJSON{
				Kind:             "connection_string",
				ConnectionString: "mysql://x",
			},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, exposeArtifactToJSON(c.in))
		})
	}
}

func exposeArtifactToJSON(a generators.Artifact) token.ArtifactJSON {
	gen := &triggerGen{tokenType: token.TypeWebbug, artifact: a}
	repo := newFakeRepo()
	svc := token.NewService(repo, token.MapRegistry{token.TypeWebbug: gen},
		token.ServiceConfig{BaseURL: "https://x"})
	h := token.NewHandler(svc, nil, nil, nil, nil, quietHandlerLogger(), false)

	r := chi.NewRouter()
	h.RegisterAPIRoutes(r)

	body := strings.NewReader(
		`{"type":"webbug","alert_channel":"webhook","webhook_url":"https://x/h","cf_turnstile_response":"t","metadata":{}}`,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/tokens", body))

	var resp struct {
		Data struct {
			Artifact token.ArtifactJSON `json:"artifact"`
		} `json:"data"`
	}
	if jsonErr := json.NewDecoder(w.Body).Decode(&resp); jsonErr != nil {
		panic(jsonErr)
	}
	return resp.Data.Artifact
}

type fakeEventQuery struct {
	listResult event.ListResult
	listErr    error
	countN     int64
	countErr   error
	lastTokID  string
	lastOpts   event.ListOptions
}

func (f *fakeEventQuery) ListByToken(
	_ context.Context,
	tokenID string,
	opts event.ListOptions,
) (event.ListResult, error) {
	f.lastTokID = tokenID
	f.lastOpts = opts
	return f.listResult, f.listErr
}

func (f *fakeEventQuery) CountByToken(
	_ context.Context,
	_ string,
) (int64, error) {
	return f.countN, f.countErr
}

type fakeDedupCounter struct {
	n   int64
	err error
}

func (f *fakeDedupCounter) CountActiveDedup(
	_ context.Context,
	_ string,
) (int64, error) {
	return f.n, f.err
}

func newManageHandler(
	t *testing.T,
	eq *fakeEventQuery,
	dc *fakeDedupCounter,
) (*token.Handler, *fakeRepo) {
	t.Helper()
	repo := newFakeRepo()
	svc := token.NewService(repo, token.MapRegistry{},
		token.ServiceConfig{
			BaseURL:   "https://canary.example.com",
			ManageURL: "https://canary.example.com",
		})
	return token.NewHandler(
			svc,
			nil,
			nil,
			eq,
			dc,
			quietHandlerLogger(),
			false,
		),
		repo
}

func seedToken(t *testing.T, repo *fakeRepo, manageID string) *token.Token {
	t.Helper()
	tok := &token.Token{
		ID:           "tok" + manageID[:8],
		ManageID:     manageID,
		Type:         token.TypeWebbug,
		Memo:         "manage-test",
		AlertChannel: token.ChannelWebhook,
		WebhookURL:   strPtr("https://x/h"),
		CreatedIP:    "1.1.1.1",
		CreatedFP:    "fp",
		Metadata:     json.RawMessage(`{}`),
		Enabled:      true,
		TriggerCount: 5,
	}
	require.NoError(t, repo.Insert(context.Background(), tok))
	return tok
}

func strPtr(s string) *string { return &s }

func decodeManage(t *testing.T, body []byte) struct {
	Success bool                 `json:"success"`
	Data    token.ManageResponse `json:"data"`
} {
	t.Helper()
	var resp struct {
		Success bool                 `json:"success"`
		Data    token.ManageResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp
}

func TestGetManage_HappyPath(t *testing.T) {
	t.Parallel()
	eq := &fakeEventQuery{
		countN: 17,
		listResult: event.ListResult{
			Events: []event.Event{
				{ID: 42, TokenID: "x", SourceIP: "1.2.3.4"},
				{ID: 41, TokenID: "x", SourceIP: "5.6.7.8"},
			},
			HasMore: false,
		},
	}
	dc := &fakeDedupCounter{n: 3}
	h, repo := newManageHandler(t, eq, dc)
	tok := seedToken(t, repo, "11111111-1111-1111-1111-111111111111")

	r := chi.NewRouter()
	h.RegisterManageRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/m/"+tok.ManageID, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
	resp := decodeManage(t, w.Body.Bytes())
	require.True(t, resp.Success)
	require.Equal(t, tok.ID, resp.Data.Token.ID)
	require.Equal(
		t,
		"https://canary.example.com/c/"+tok.ID,
		resp.Data.Token.TriggerURL,
	)
	require.Equal(t, int64(5), resp.Data.Token.TriggerCount)
	require.Len(t, resp.Data.Events, 2)
	require.Equal(t, int64(17), resp.Data.EventsTotal)
	require.Equal(t, int64(3), resp.Data.EventsSilencedActive)
}

func TestGetManage_404OnUnknownManageID(t *testing.T) {
	t.Parallel()
	h, _ := newManageHandler(t, &fakeEventQuery{}, &fakeDedupCounter{})

	r := chi.NewRouter()
	h.RegisterManageRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(
		w,
		httptest.NewRequest(http.MethodGet, "/m/does-not-exist", nil),
	)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "NOT_FOUND")
}

func TestGetManage_400OnBadCursor(t *testing.T) {
	t.Parallel()
	h, repo := newManageHandler(t, &fakeEventQuery{}, &fakeDedupCounter{})
	tok := seedToken(t, repo, "22222222-2222-2222-2222-222222222222")

	r := chi.NewRouter()
	h.RegisterManageRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/m/"+tok.ManageID+"?cursor=notanumber", nil))
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "BAD_CURSOR")
}

func TestGetManage_400OnNegativeCursor(t *testing.T) {
	t.Parallel()
	h, repo := newManageHandler(t, &fakeEventQuery{}, &fakeDedupCounter{})
	tok := seedToken(t, repo, "33333333-3333-3333-3333-333333333333")

	r := chi.NewRouter()
	h.RegisterManageRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/m/"+tok.ManageID+"?cursor=-1", nil))
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetManage_PaginationCursorAndHasMore(t *testing.T) {
	t.Parallel()
	full := []event.Event{}
	for i := 20; i > 0; i-- {
		full = append(full, event.Event{ID: int64(i), SourceIP: "1.1.1.1"})
	}
	eq := &fakeEventQuery{
		listResult: event.ListResult{
			Events:     full,
			HasMore:    true,
			NextCursor: 1,
		},
		countN: 50,
	}
	h, repo := newManageHandler(t, eq, &fakeDedupCounter{})
	tok := seedToken(t, repo, "44444444-4444-4444-4444-444444444444")

	r := chi.NewRouter()
	h.RegisterManageRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/m/"+tok.ManageID, nil))
	require.Equal(t, http.StatusOK, w.Code)

	resp := decodeManage(t, w.Body.Bytes())
	require.Len(t, resp.Data.Events, 20)
	require.True(t, resp.Data.Page.HasMore)
	require.Equal(t, "1", resp.Data.Page.NextCursor,
		"cursor is the ID of the last event returned")
}

func TestGetManage_LimitParamRespected(t *testing.T) {
	t.Parallel()
	eq := &fakeEventQuery{}
	h, repo := newManageHandler(t, eq, &fakeDedupCounter{})
	tok := seedToken(t, repo, "55555555-5555-5555-5555-555555555555")

	r := chi.NewRouter()
	h.RegisterManageRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/m/"+tok.ManageID+"?limit=5", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, 5, eq.lastOpts.Limit)
}

func TestGetManage_LimitCappedAtMax(t *testing.T) {
	t.Parallel()
	eq := &fakeEventQuery{}
	h, repo := newManageHandler(t, eq, &fakeDedupCounter{})
	tok := seedToken(t, repo, "66666666-6666-6666-6666-666666666666")

	r := chi.NewRouter()
	h.RegisterManageRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/m/"+tok.ManageID+"?limit=999", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.LessOrEqual(t, eq.lastOpts.Limit, 100,
		"limit should be capped at manageMaxPageSize")
}

func TestDeleteManage_HappyPath(t *testing.T) {
	t.Parallel()
	h, repo := newManageHandler(t, &fakeEventQuery{}, &fakeDedupCounter{})
	tok := seedToken(t, repo, "77777777-7777-7777-7777-777777777777")

	r := chi.NewRouter()
	h.RegisterManageRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(
		w,
		httptest.NewRequest(http.MethodDelete, "/m/"+tok.ManageID, nil),
	)
	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestDeleteManage_404OnUnknownManageID(t *testing.T) {
	t.Parallel()
	h, _ := newManageHandler(t, &fakeEventQuery{}, &fakeDedupCounter{})

	r := chi.NewRouter()
	h.RegisterManageRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(
		w,
		httptest.NewRequest(http.MethodDelete, "/m/does-not-exist", nil),
	)
	require.Equal(t, http.StatusNotFound, w.Code)
}
