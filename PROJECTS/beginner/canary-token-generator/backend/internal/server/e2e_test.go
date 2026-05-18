// ©AngelaMos | 2026
// e2e_test.go

//go:build integration

package server_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/notify"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/testutil"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/registry"
)

const (
	e2eBaseURL       = "https://canary.example.com"
	e2eManageURL     = "https://canary.example.com"
	e2eTelegramBot   = "111:AAA"
	e2eTelegramChat  = "12345"
	e2eMySQLPubHost  = "localhost"
	e2eMySQLPubPort  = 3306
	e2eClientIP      = "203.0.113.10"
	e2eClientUA      = "E2E/1.0"
	e2eEventualWait  = 3 * time.Second
	e2eEventualTick  = 20 * time.Millisecond
	e2eSendTimeout   = 2 * time.Second
	e2eDedupTTL      = 15 * time.Minute
)

type e2eSender struct {
	mu    sync.Mutex
	calls []event.NotifyInfo
}

func (s *e2eSender) Channel() string { return "telegram" }

func (s *e2eSender) Send(
	_ context.Context,
	info event.NotifyInfo,
	_ *event.Event,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, info)
	return nil
}

func (s *e2eSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

type e2eRegistryAdapter struct{ r registry.Registry }

func (a e2eRegistryAdapter) Get(
	t token.Type,
) (token.Generator, bool) {
	g, ok := a.r[t]
	return g, ok
}

type e2eRecorderAdapter struct{ svc *event.Service }

func (a e2eRecorderAdapter) Record(
	ctx context.Context,
	t *token.Token,
	evt *event.Event,
) error {
	return a.svc.Record(ctx, t.NotifyInfo(), evt)
}

type e2eStack struct {
	router    chi.Router
	notifySvc *notify.Service
	sender    *e2eSender
	eventRepo *event.Repository
	tokenRepo *token.Repository
}

func setupE2EStack(t *testing.T) *e2eStack {
	t.Helper()

	db := sqlx.NewDb(testutil.NewTestDB(t), "pgx")

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		if cErr := rdb.Close(); cErr != nil {
			t.Logf("redis close: %v", cErr)
		}
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tokenRepo := token.NewRepository(db)
	eventRepo := event.NewRepository(db)
	sender := &e2eSender{}

	notifySvc := notify.NewService(eventRepo,
		notify.WithLogger(logger),
		notify.WithSendTimeout(e2eSendTimeout),
	)
	notifySvc.Register(sender)

	eventSvc := event.NewService(
		eventRepo,
		tokenRepo,
		rdb,
		notifySvc,
		event.ServiceConfig{
			DedupTTL: e2eDedupTTL,
			Logger:   logger,
		},
	)

	genReg := registry.Build(registry.Config{
		BaseURL:         e2eBaseURL,
		MySQLPublicHost: e2eMySQLPubHost,
		MySQLPublicPort: e2eMySQLPubPort,
	})
	tokenSvc := token.NewService(
		tokenRepo,
		e2eRegistryAdapter{r: genReg},
		token.ServiceConfig{
			BaseURL:   e2eBaseURL,
			ManageURL: e2eManageURL,
		},
	)

	tokenH := token.NewHandler(
		tokenSvc,
		e2eRecorderAdapter{svc: eventSvc},
		nil,
		eventRepo,
		eventSvc,
		logger,
		true,
	)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recovery(logger))
	tokenH.RegisterTriggerRoutes(r)
	r.Route("/api", func(api chi.Router) {
		api.Get("/tokens/types", tokenH.GetTypes)
		api.Post("/tokens", tokenH.CreateToken)
		tokenH.RegisterManageRoutes(api)
	})

	return &e2eStack{
		router:    r,
		notifySvc: notifySvc,
		sender:    sender,
		eventRepo: eventRepo,
		tokenRepo: tokenRepo,
	}
}

type e2eCreateResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Token    token.Response     `json:"token"`
		Artifact token.ArtifactJSON `json:"artifact"`
	} `json:"data"`
}

func createE2EToken(
	t *testing.T,
	st *e2eStack,
	kind token.Type,
	metadata string,
) e2eCreateResponse {
	t.Helper()

	body := `{
		"type": "` + string(kind) + `",
		"memo": "e2e ` + string(kind) + `",
		"alert_channel": "telegram",
		"telegram_bot": "` + e2eTelegramBot + `",
		"telegram_chat": "` + e2eTelegramChat + `"`
	if metadata != "" {
		body += `, "metadata": ` + metadata
	}
	body += `}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/tokens",
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	st.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "body=%s", w.Body.String())

	var resp e2eCreateResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.True(t, resp.Success)
	require.NotEmpty(t, resp.Data.Token.ID)
	return resp
}

func extractEmbeddedTriggerURL(
	t *testing.T,
	kind token.Type,
	art token.ArtifactJSON,
	tokenID string,
) string {
	t.Helper()
	switch art.Kind {
	case "url":
		require.NotEmpty(t, art.URL)
		return art.URL
	case "file":
		raw, err := base64.StdEncoding.DecodeString(art.ContentB64)
		require.NoError(t, err)
		if kind == token.TypeDocx {
			return matchTriggerURLInZip(t, raw, tokenID)
		}
		return matchTriggerURL(t, raw, tokenID)
	case "text":
		return matchTriggerURL(t, []byte(art.Content), tokenID)
	default:
		t.Fatalf("unhandled artifact kind for HTTP trigger: %s", art.Kind)
		return ""
	}
}

func matchTriggerURLInZip(
	t *testing.T,
	raw []byte,
	tokenID string,
) string {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	require.NoError(t, err, "docx artifact must be a valid zip")
	needle := []byte("/c/" + tokenID)
	for _, f := range r.File {
		rc, oErr := f.Open()
		if oErr != nil {
			continue
		}
		content, rErr := io.ReadAll(rc)
		_ = rc.Close()
		if rErr != nil {
			continue
		}
		if bytes.Contains(content, needle) {
			return matchTriggerURL(t, content, tokenID)
		}
	}
	t.Fatalf(
		"docx: no zip member contains /c/%s (members=%d)",
		tokenID, len(r.File),
	)
	return ""
}

func matchTriggerURL(t *testing.T, raw []byte, tokenID string) string {
	t.Helper()
	pattern := regexp.MustCompile(
		`https?://[A-Za-z0-9.\-:]+/(?:c|k)/` +
			regexp.QuoteMeta(tokenID) +
			`(?:\?[A-Za-z0-9_=&\-%.]*)?`,
	)
	match := pattern.Find(raw)
	require.NotNilf(
		t,
		match,
		"embedded trigger URL for token %s not found in artifact (len=%d)",
		tokenID, len(raw),
	)
	return string(match)
}

func TestE2E_AllTokenTypes_CreateTriggerNotifyRecord(t *testing.T) {
	st := setupE2EStack(t)

	cases := []struct {
		name     string
		kind     token.Type
		metadata string
		httpable bool
	}{
		{
			name:     "webbug",
			kind:     token.TypeWebbug,
			metadata: "",
			httpable: true,
		},
		{
			name:     "slowredirect",
			kind:     token.TypeSlowRedirect,
			metadata: `{"destination_url":"https://example.com/out"}`,
			httpable: true,
		},
		{
			name:     "docx",
			kind:     token.TypeDocx,
			metadata: "",
			httpable: true,
		},
		{
			name:     "pdf",
			kind:     token.TypePDF,
			metadata: "",
			httpable: true,
		},
		{
			name:     "kubeconfig",
			kind:     token.TypeKubeconfig,
			metadata: "",
			httpable: true,
		},
		{
			name:     "envfile",
			kind:     token.TypeEnvfile,
			metadata: `{"include_keys":["aws"]}`,
			httpable: true,
		},
		{
			name:     "mysql",
			kind:     token.TypeMySQL,
			metadata: "",
			httpable: false,
		},
	}

	var expectedNotifications int

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			resp := createE2EToken(t, st, c.kind, c.metadata)
			tokenID := resp.Data.Token.ID

			if c.kind == token.TypePDF {
				raw, err := base64.StdEncoding.DecodeString(
					resp.Data.Artifact.ContentB64,
				)
				require.NoError(t, err)
				idx := bytes.Index(raw, []byte("/c/"+tokenID))
				require.GreaterOrEqualf(
					t,
					idx,
					0,
					"PDF artifact must embed /c/<id> (id=%s)",
					tokenID,
				)
				after := raw[idx+len("/c/"+tokenID)]
				require.NotEqualf(
					t,
					byte('_'),
					after,
					"audit finding F2 regression: the byte immediately after "+
						"the PDF-embedded /c/<id> must not be '_' — otherwise "+
						"Acrobat fetches /c/<id>____ and the canary silently "+
						"no-ops on lookup (id=%s, after=%q)",
					tokenID, after,
				)
			}

			if !c.httpable {
				require.Equal(t, "connection_string", resp.Data.Artifact.Kind)
				require.NotEmpty(t, resp.Data.Artifact.ConnectionString)
				return
			}

			triggerURL := extractEmbeddedTriggerURL(
				t,
				c.kind,
				resp.Data.Artifact,
				tokenID,
			)
			require.NotEmpty(t, triggerURL)

			trigReq := httptest.NewRequest(http.MethodGet, triggerURL, nil)
			trigReq.Header.Set("CF-Connecting-IP", e2eClientIP)
			trigReq.Header.Set("User-Agent", e2eClientUA)
			tw := httptest.NewRecorder()
			st.router.ServeHTTP(tw, trigReq)
			require.Truef(
				t,
				tw.Code == http.StatusOK ||
					tw.Code == http.StatusFound ||
					tw.Code == http.StatusForbidden,
				"trigger expected 200/302/403 (kubeconfig camouflages "+
					"as K8s 403), got %d for %s (url=%s)",
				tw.Code, c.kind, triggerURL,
			)

			expectedNotifications++
			require.Eventuallyf(
				t,
				func() bool {
					return st.sender.count() >= expectedNotifications
				},
				e2eEventualWait,
				e2eEventualTick,
				"notifier should fire for %s (got=%d want>=%d)",
				c.kind, st.sender.count(), expectedNotifications,
			)

			count, err := st.eventRepo.CountByToken(
				context.Background(),
				tokenID,
			)
			require.NoError(t, err)
			require.GreaterOrEqualf(
				t,
				count,
				int64(1),
				"at least one event must be recorded for %s",
				c.kind,
			)

			manageReq := httptest.NewRequest(
				http.MethodGet,
				"/api/m/"+resp.Data.Token.ManageID,
				nil,
			)
			mw := httptest.NewRecorder()
			st.router.ServeHTTP(mw, manageReq)
			require.Equal(t, http.StatusOK, mw.Code)
			var manage struct {
				Success bool `json:"success"`
				Data    struct {
					EventsTotal int64 `json:"events_total"`
				} `json:"data"`
			}
			require.NoError(t, json.NewDecoder(mw.Body).Decode(&manage))
			require.True(t, manage.Success)
			require.GreaterOrEqual(
				t,
				manage.Data.EventsTotal,
				int64(1),
				"manage view must show at least one event for "+c.name,
			)
		})
	}

	st.notifySvc.Wait()
}
