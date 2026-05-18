// ©AngelaMos | 2026
// generator_test.go

package webbug_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/webbug"
)

const (
	cacheControlNoStore = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaNoCache       = "no-cache"
	pixelContentType    = "image/jpeg"
	jpegSOI0            = 0xff
	jpegSOI1            = 0xd8
)

func newWebbugToken(id string) *token.Token {
	return &token.Token{
		ID:           id,
		ManageID:     "manage-" + id,
		Type:         token.TypeWebbug,
		Memo:         "unit test webbug",
		AlertChannel: token.ChannelWebhook,
		Enabled:      true,
	}
}

func TestGenerator_TypeIsWebbug(t *testing.T) {
	g := webbug.New()
	require.Equal(t, token.TypeWebbug, g.Type())
}

func TestGenerate_ReturnsURLArtifact(t *testing.T) {
	cases := []struct {
		name    string
		baseURL string
		id      string
		wantURL string
	}{
		{
			name:    "no trailing slash",
			baseURL: "https://canary.example.com",
			id:      "abc123",
			wantURL: "https://canary.example.com/c/abc123",
		},
		{
			name:    "trailing slash trimmed",
			baseURL: "https://canary.example.com/",
			id:      "xyz999",
			wantURL: "https://canary.example.com/c/xyz999",
		},
		{
			name:    "subpath base URL preserved",
			baseURL: "https://example.com/canary",
			id:      "p7",
			wantURL: "https://example.com/canary/c/p7",
		},
	}

	g := webbug.New()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			art, err := g.Generate(
				context.Background(),
				newWebbugToken(tc.id),
				tc.baseURL,
			)
			require.NoError(t, err)
			require.Equal(t, generators.KindURL, art.Kind)
			require.Equal(t, tc.wantURL, art.URL)
		})
	}
}

func TestTrigger_RecordsEventWithRequestMetadata(t *testing.T) {
	g := webbug.New()
	tok := newWebbugToken("token1")

	t.Run(
		"captures token id, source ip, user agent, referer",
		func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/c/token1", nil)
			r.Header.Set("CF-Connecting-IP", "203.0.113.50")
			r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
			r.Header.Set("Referer", "https://victim.example.com/inbox")

			evt, _, err := g.Trigger(context.Background(), tok, r)
			require.NoError(t, err)
			require.NotNil(t, evt)
			require.Equal(t, "token1", evt.TokenID)
			require.Equal(t, "203.0.113.50", evt.SourceIP)
			require.NotNil(t, evt.UserAgent)
			require.Equal(t, "Mozilla/5.0 (X11; Linux x86_64)", *evt.UserAgent)
			require.NotNil(t, evt.Referer)
			require.Equal(t, "https://victim.example.com/inbox", *evt.Referer)
		},
	)

	t.Run("source ip precedence", func(t *testing.T) {
		cases := []struct {
			name    string
			headers map[string]string
			remote  string
			wantIP  string
		}{
			{
				name: "CF wins over XFF and XRI",
				headers: map[string]string{
					"CF-Connecting-IP": "203.0.113.10",
					"X-Forwarded-For":  "198.51.100.1, 198.51.100.2",
					"X-Real-IP":        "192.0.2.99",
				},
				remote: "127.0.0.1:9999",
				wantIP: "203.0.113.10",
			},
			{
				name: "XFF leftmost wins over XRI when no CF",
				headers: map[string]string{
					"X-Forwarded-For": "198.51.100.1, 198.51.100.7",
					"X-Real-IP":       "192.0.2.99",
				},
				remote: "127.0.0.1:9999",
				wantIP: "198.51.100.1",
			},
			{
				name: "XFF trailing-comma falls through to XRI",
				headers: map[string]string{
					"X-Forwarded-For": "198.51.100.1, ",
					"X-Real-IP":       "192.0.2.99",
				},
				remote: "127.0.0.1:9999",
				wantIP: "198.51.100.1",
			},
			{
				name: "XFF entirely empty entries fall through to XRI",
				headers: map[string]string{
					"X-Forwarded-For": ", ,",
					"X-Real-IP":       "192.0.2.99",
				},
				remote: "127.0.0.1:9999",
				wantIP: "192.0.2.99",
			},
			{
				name: "XRI when no CF or XFF",
				headers: map[string]string{
					"X-Real-IP": "192.0.2.99",
				},
				remote: "127.0.0.1:9999",
				wantIP: "192.0.2.99",
			},
			{
				name:    "RemoteAddr IPv4 strips port",
				headers: nil,
				remote:  "127.0.0.1:9999",
				wantIP:  "127.0.0.1",
			},
			{
				name:    "RemoteAddr IPv6 strips brackets and port",
				headers: nil,
				remote:  "[2001:db8::1]:54321",
				wantIP:  "2001:db8::1",
			},
			{
				name:    "RemoteAddr loopback IPv6 strips brackets and port",
				headers: nil,
				remote:  "[::1]:9999",
				wantIP:  "::1",
			},
			{
				name:    "RemoteAddr without port falls back to raw value",
				headers: nil,
				remote:  "127.0.0.1",
				wantIP:  "127.0.0.1",
			},
			{
				name: "XFF mixed IPv4+IPv6 leftmost",
				headers: map[string]string{
					"X-Forwarded-For": "198.51.100.1, 2001:db8::dead",
				},
				remote: "127.0.0.1:9999",
				wantIP: "198.51.100.1",
			},
			{
				name: "CF value is trimmed of whitespace",
				headers: map[string]string{
					"CF-Connecting-IP": "  203.0.113.10  ",
				},
				remote: "127.0.0.1:9999",
				wantIP: "203.0.113.10",
			},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, "/c/token1", nil)
				for k, v := range tc.headers {
					r.Header.Set(k, v)
				}
				r.RemoteAddr = tc.remote
				evt, _, err := g.Trigger(context.Background(), tok, r)
				require.NoError(t, err)
				require.NotNil(t, evt)
				require.Equal(t, tc.wantIP, evt.SourceIP)
			})
		}
	})

	t.Run(
		"missing user agent and referer record as nil pointers",
		func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/c/token1", nil)
			r.Header.Del("User-Agent")
			r.Header.Del("Referer")
			r.Header.Set("CF-Connecting-IP", "203.0.113.5")

			evt, _, err := g.Trigger(context.Background(), tok, r)
			require.NoError(t, err)
			require.NotNil(t, evt)
			require.Nil(
				t,
				evt.UserAgent,
				"absent user agent must map to nil, not empty string",
			)
			require.Nil(
				t,
				evt.Referer,
				"absent referer must map to nil, not empty string",
			)
		},
	)
}

func TestTrigger_ResponseIsEmbeddedJPEG(t *testing.T) {
	g := webbug.New()
	tok := newWebbugToken("abc")
	r := httptest.NewRequest(http.MethodGet, "/c/abc", nil)

	_, resp, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, pixelContentType, resp.ContentType)
	require.NotEmpty(t, resp.Body, "embedded pixel.jpg must not be empty")
	require.Equal(t, jpegSOI0, int(resp.Body[0]),
		"body must begin with JPEG SOI marker 0xff 0xd8")
	require.Equal(t, jpegSOI1, int(resp.Body[1]),
		"body must begin with JPEG SOI marker 0xff 0xd8")
	require.Equal(t, cacheControlNoStore, resp.ExtraHeaders["Cache-Control"])
	require.Equal(t, pragmaNoCache, resp.ExtraHeaders["Pragma"])
}

func TestTrigger_ResponseBodyIsIndependentCopyPerCall(t *testing.T) {
	g := webbug.New()
	tok := newWebbugToken("abc")
	r := httptest.NewRequest(http.MethodGet, "/c/abc", nil)

	_, resp1, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	_, resp2, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)

	original := resp2.Body[0]
	resp1.Body[0] = 0x00
	require.Equal(
		t,
		original,
		resp2.Body[0],
		"each Trigger call must produce an independent body slice",
	)
}

func TestTrigger_TokenNotFound_StillReturnsImage(t *testing.T) {
	g := webbug.New()
	r := httptest.NewRequest(http.MethodGet, "/c/does-not-exist", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.100")
	r.Header.Set("User-Agent", "curl/8.0.0")

	evt, resp, err := g.Trigger(context.Background(), nil, r)
	require.NoError(
		t,
		err,
		"nil-token path must not error (spec §8.5 defense-in-depth)",
	)
	require.NotNil(t, resp, "nil-token path must still return image response")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, pixelContentType, resp.ContentType)
	require.NotEmpty(t, resp.Body)
	require.Nil(
		t,
		evt,
		"nil-token path returns nil event so the handler cannot accidentally persist a row with empty TokenID (FK violation)",
	)
}
