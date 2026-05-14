// ©AngelaMos | 2026
// sender_test.go

package telegram_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/notify/telegram"
)

const (
	testBotToken = "111222:ABCDEFG"
	testChatID   = "98765"
	testMemo     = "prod-db-creds"
	testTokenID  = "tokabc123def"
	testManageID = "11111111-2222-3333-4444-555555555555"
)

func sampleInfo() event.NotifyInfo {
	return event.NotifyInfo{
		TokenID:      testTokenID,
		ManageID:     testManageID,
		Type:         "envfile",
		Memo:         testMemo,
		AlertChannel: "telegram",
		TelegramBot:  testBotToken,
		TelegramChat: testChatID,
	}
}

func sampleEvent() *event.Event {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	city := "Toronto"
	country := "CA"
	asnOrg := "Cloudflare, Inc."
	return &event.Event{
		ID:          42,
		TokenID:     testTokenID,
		TriggeredAt: time.Date(2026, 5, 14, 12, 30, 0, 0, time.UTC),
		SourceIP:    "203.0.113.45",
		UserAgent:   &ua,
		GeoCity:     &city,
		GeoCountry:  &country,
		GeoASNOrg:   &asnOrg,
	}
}

type capture struct {
	calls    atomic.Int32
	lastURL  atomic.Value
	lastBody atomic.Value
}

func writeOK(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"ok":true}`)); err != nil {
		t.Logf("write: %v", err)
	}
}

func newCaptureServer(
	t *testing.T,
	handler http.HandlerFunc,
) (*httptest.Server, *capture) {
	t.Helper()
	c := &capture{}
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.calls.Add(1)
			c.lastURL.Store(r.URL.String())
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Logf("read body: %v", err)
				return
			}
			c.lastBody.Store(body)
			handler(w, r)
		}),
	)
	t.Cleanup(srv.Close)
	return srv, c
}

func loadBody(t *testing.T, c *capture) []byte {
	t.Helper()
	raw, ok := c.lastBody.Load().([]byte)
	require.True(t, ok, "no body captured")
	return raw
}

func newSender(
	t *testing.T,
	apiBase string,
	opts ...telegram.Option,
) *telegram.Sender {
	t.Helper()
	cfg := telegram.Config{
		APIBase:   apiBase,
		ManageURL: "https://canary.example.com",
	}
	for _, o := range opts {
		o(&cfg)
	}
	return telegram.NewSender(cfg)
}

func TestSender_Channel(t *testing.T) {
	t.Parallel()
	s := newSender(t, "https://api.telegram.org")
	require.Equal(t, "telegram", s.Channel())
}

func TestSender_Send_PostsToCorrectURL(t *testing.T) {
	t.Parallel()
	srv, cap := newCaptureServer(
		t,
		func(w http.ResponseWriter, _ *http.Request) { writeOK(t, w) },
	)
	s := newSender(t, srv.URL)

	require.NoError(
		t,
		s.Send(context.Background(), sampleInfo(), sampleEvent()),
	)
	require.Equal(t, int32(1), cap.calls.Load())
	require.Equal(t, "/bot"+testBotToken+"/sendMessage", cap.lastURL.Load())
}

func TestSender_Send_BodyShape(t *testing.T) {
	t.Parallel()
	srv, cap := newCaptureServer(
		t,
		func(w http.ResponseWriter, _ *http.Request) { writeOK(t, w) },
	)
	s := newSender(t, srv.URL)

	require.NoError(
		t,
		s.Send(context.Background(), sampleInfo(), sampleEvent()),
	)

	var body map[string]string
	require.NoError(t, json.Unmarshal(loadBody(t, cap), &body))
	require.Equal(t, testChatID, body["chat_id"])
	require.Equal(t, "MarkdownV2", body["parse_mode"])
	require.NotEmpty(t, body["text"])
}

func TestSender_Send_MessageContainsKeyFields(t *testing.T) {
	t.Parallel()
	srv, cap := newCaptureServer(
		t,
		func(w http.ResponseWriter, _ *http.Request) { writeOK(t, w) },
	)
	s := newSender(t, srv.URL)

	require.NoError(
		t,
		s.Send(context.Background(), sampleInfo(), sampleEvent()),
	)

	var body map[string]string
	require.NoError(t, json.Unmarshal(loadBody(t, cap), &body))
	text := body["text"]

	require.Contains(t, text, "Canary triggered")
	require.Contains(
		t,
		text,
		`prod\-db\-creds`,
		"memo escaped (- is V2 special)",
	)
	require.Contains(t, text, "envfile")
	require.Contains(t, text, `203\.0\.113\.45`, "IP dots escaped")
	require.Contains(t,
		text,
		`\(Toronto, CA\)`,
		"geo wrapping parens escaped (V2 reserved chars)",
	)
	require.Contains(t, text, `Cloudflare, Inc\.`, "asn_org . escaped")
	require.Contains(t, text, "View full event timeline", "manage link present")
	require.Contains(t,
		text,
		"https://canary.example.com/m/"+testManageID,
		"manage URL present in link",
	)
}

func TestSender_Send_TruncatesUserAgentTo80Chars(t *testing.T) {
	t.Parallel()
	srv, cap := newCaptureServer(
		t,
		func(w http.ResponseWriter, _ *http.Request) { writeOK(t, w) },
	)
	s := newSender(t, srv.URL)

	longUA := strings.Repeat("X", 200)
	evt := sampleEvent()
	evt.UserAgent = &longUA

	require.NoError(t, s.Send(context.Background(), sampleInfo(), evt))

	var body map[string]string
	require.NoError(t, json.Unmarshal(loadBody(t, cap), &body))
	require.Contains(t, body["text"], strings.Repeat("X", 80))
	require.NotContains(t, body["text"], strings.Repeat("X", 81),
		"user agent should be truncated to 80 chars")
}

func TestSender_Send_HandlesNilGeoAndUA(t *testing.T) {
	t.Parallel()
	srv, cap := newCaptureServer(
		t,
		func(w http.ResponseWriter, _ *http.Request) { writeOK(t, w) },
	)
	s := newSender(t, srv.URL)

	evt := &event.Event{
		ID:          1,
		TokenID:     testTokenID,
		TriggeredAt: time.Date(2026, 5, 14, 12, 30, 0, 0, time.UTC),
		SourceIP:    "203.0.113.45",
	}
	require.NoError(t, s.Send(context.Background(), sampleInfo(), evt))

	var body map[string]string
	require.NoError(t, json.Unmarshal(loadBody(t, cap), &body))
	require.Contains(t, body["text"], `203\.0\.113\.45`)
}

func TestSender_Send_EmptyBotReturnsConfigErr(t *testing.T) {
	t.Parallel()
	s := newSender(t, "http://unused.test")
	info := sampleInfo()
	info.TelegramBot = ""
	err := s.Send(context.Background(), info, sampleEvent())
	require.ErrorIs(t, err, telegram.ErrChannelNotConfigured)
}

func TestSender_Send_EmptyChatReturnsConfigErr(t *testing.T) {
	t.Parallel()
	s := newSender(t, "http://unused.test")
	info := sampleInfo()
	info.TelegramChat = ""
	err := s.Send(context.Background(), info, sampleEvent())
	require.ErrorIs(t, err, telegram.ErrChannelNotConfigured)
}

func TestSender_Send_RetriesOn5xxThenSucceeds(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			n := attempts.Add(1)
			if n == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			writeOK(t, w)
		}),
	)
	t.Cleanup(srv.Close)

	s := newSender(t, srv.URL,
		telegram.WithMaxTries(3),
		telegram.WithMaxElapsed(2*time.Second),
		telegram.WithInitialInterval(5*time.Millisecond),
	)
	require.NoError(
		t,
		s.Send(context.Background(), sampleInfo(), sampleEvent()),
	)
	require.Equal(t, int32(2), attempts.Load())
}

func TestSender_Send_PermanentOn4xx(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write(
				[]byte(`{"ok":false,"description":"chat not found"}`),
			); err != nil {
				t.Logf("write: %v", err)
			}
		}),
	)
	t.Cleanup(srv.Close)

	s := newSender(t, srv.URL,
		telegram.WithMaxTries(5),
		telegram.WithInitialInterval(5*time.Millisecond),
	)
	err := s.Send(context.Background(), sampleInfo(), sampleEvent())
	require.Error(t, err)
	require.Equal(t, int32(1), attempts.Load(), "no retry on 4xx")
}

func TestSender_Send_AbortsAfterMaxTries(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}),
	)
	t.Cleanup(srv.Close)

	s := newSender(t, srv.URL,
		telegram.WithMaxTries(3),
		telegram.WithMaxElapsed(5*time.Second),
		telegram.WithInitialInterval(2*time.Millisecond),
	)
	err := s.Send(context.Background(), sampleInfo(), sampleEvent())
	require.Error(t, err)
	require.Equal(t, int32(3), attempts.Load())
}

func TestSender_Send_RespectsContextCancel(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(
		http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			time.Sleep(2 * time.Second)
		}),
	)
	t.Cleanup(srv.Close)

	s := newSender(t, srv.URL,
		telegram.WithMaxTries(3),
		telegram.WithInitialInterval(5*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		100*time.Millisecond,
	)
	defer cancel()

	err := s.Send(ctx, sampleInfo(), sampleEvent())
	require.Error(t, err)
	require.True(t,
		errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, context.Canceled),
		"expected context error, got %v", err,
	)
}

func TestEscapeMD(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"plain", "plain"},
		{"a.b", `a\.b`},
		{"a-b", `a\-b`},
		{"file.txt", `file\.txt`},
		{"203.0.113.45", `203\.0\.113\.45`},
		{"hello!", `hello\!`},
		{"a_b*c", `a\_b\*c`},
		{"(parens)", `\(parens\)`},
		{"[bracket]", `\[bracket\]`},
		{"~tilde~", `\~tilde\~`},
		{"`code`", "\\`code\\`"},
		{"a>b<c", `a\>b<c`},
		{"a#b", `a\#b`},
		{"a+b=c", `a\+b\=c`},
		{"a|b{c}d", `a\|b\{c\}d`},
		{"unicode—em", "unicode—em"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			require.Equal(t, tc.want, telegram.EscapeMD(tc.in))
		})
	}
}
