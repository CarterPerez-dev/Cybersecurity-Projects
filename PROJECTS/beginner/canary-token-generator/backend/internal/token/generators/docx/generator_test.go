// ©AngelaMos | 2026
// generator_test.go

package docx_test

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/docx"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/pixel"
)

//go:embed template/template.docx
var rawTemplate []byte

const (
	testBaseURL              = "https://canary.example.com"
	placeholderLiteral       = "HONEY_TRACK_URL"
	footerEntryName          = "word/footer2.xml"
	docxContentTypeMIME      = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	defaultFilename          = "Document.docx"
	cacheControlNoStoreValue = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaNoCacheValue       = "no-cache"
	gifByteLength            = 43
)

func newDocxToken(id string) *token.Token {
	return &token.Token{
		ID:           id,
		ManageID:     "manage-" + id,
		Type:         token.TypeDocx,
		Memo:         "unit test docx",
		AlertChannel: token.ChannelWebhook,
		Enabled:      true,
	}
}

func newDocxTokenWithFilename(id, filename string) *token.Token {
	tok := newDocxToken(id)
	tok.Filename = &filename
	return tok
}

func readFooterXML(t *testing.T, archive []byte) []byte {
	t.Helper()
	r, err := zip.NewReader(
		bytes.NewReader(archive),
		int64(len(archive)),
	)
	require.NoError(t, err)
	for _, f := range r.File {
		if f.Name != footerEntryName {
			continue
		}
		rc, oErr := f.Open()
		require.NoError(t, oErr)
		body, rErr := io.ReadAll(rc)
		require.NoError(t, rc.Close())
		require.NoError(t, rErr)
		return body
	}
	t.Fatalf("entry %q not found in zip", footerEntryName)
	return nil
}

func zipEntryBodies(t *testing.T, archive []byte) map[string][]byte {
	t.Helper()
	r, err := zip.NewReader(
		bytes.NewReader(archive),
		int64(len(archive)),
	)
	require.NoError(t, err)
	out := make(map[string][]byte, len(r.File))
	for _, f := range r.File {
		rc, oErr := f.Open()
		require.NoError(t, oErr)
		body, rErr := io.ReadAll(rc)
		require.NoError(t, rc.Close())
		require.NoError(t, rErr)
		out[f.Name] = body
	}
	return out
}

func zipEntryMethods(t *testing.T, archive []byte) map[string]uint16 {
	t.Helper()
	r, err := zip.NewReader(
		bytes.NewReader(archive),
		int64(len(archive)),
	)
	require.NoError(t, err)
	out := make(map[string]uint16, len(r.File))
	for _, f := range r.File {
		out[f.Name] = f.Method
	}
	return out
}

func TestGenerator_TypeIsDocx(t *testing.T) {
	g := docx.New()
	require.Equal(t, token.TypeDocx, g.Type())
}

func TestGenerate_ArtifactKindIsFile(t *testing.T) {
	g := docx.New()
	art, err := g.Generate(
		context.Background(),
		newDocxToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.Equal(t, generators.KindFile, art.Kind)
}

func TestGenerate_ContentTypeIsDocxMIME(t *testing.T) {
	g := docx.New()
	art, err := g.Generate(
		context.Background(),
		newDocxToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.Equal(t, docxContentTypeMIME, art.ContentType)
}

func TestGenerate_Filename(t *testing.T) {
	g := docx.New()

	t.Run("nil Filename defaults to Document.docx", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newDocxToken("abc"),
			testBaseURL,
		)
		require.NoError(t, err)
		require.Equal(t, defaultFilename, art.Filename)
	})

	t.Run(
		"empty Filename pointer defaults to Document.docx",
		func(t *testing.T) {
			art, err := g.Generate(
				context.Background(),
				newDocxTokenWithFilename("abc", ""),
				testBaseURL,
			)
			require.NoError(t, err)
			require.Equal(t, defaultFilename, art.Filename)
		},
	)

	t.Run(
		"whitespace-only Filename defaults to Document.docx",
		func(t *testing.T) {
			art, err := g.Generate(
				context.Background(),
				newDocxTokenWithFilename("abc", "   "),
				testBaseURL,
			)
			require.NoError(t, err)
			require.Equal(t, defaultFilename, art.Filename)
		},
	)

	t.Run("set Filename is preserved (trimmed)", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newDocxTokenWithFilename("abc", "  Q4-Plan.docx  "),
			testBaseURL,
		)
		require.NoError(t, err)
		require.Equal(t, "Q4-Plan.docx", art.Filename)
	})
}

func TestGenerate_TriggerURL(t *testing.T) {
	g := docx.New()

	t.Run("base URL trailing slash trimmed", func(t *testing.T) {
		artA, err := g.Generate(
			context.Background(),
			newDocxToken("tk1"),
			"https://canary.example.com",
		)
		require.NoError(t, err)
		artB, err := g.Generate(
			context.Background(),
			newDocxToken("tk1"),
			"https://canary.example.com/",
		)
		require.NoError(t, err)

		bodyA := readFooterXML(t, artA.Content)
		bodyB := readFooterXML(t, artB.Content)
		require.Contains(t, string(bodyA), "https://canary.example.com/c/tk1")
		require.Contains(t, string(bodyB), "https://canary.example.com/c/tk1")
	})

	t.Run("base URL subpath preserved", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newDocxToken("tk2"),
			"https://example.com/canary",
		)
		require.NoError(t, err)
		body := readFooterXML(t, art.Content)
		require.Contains(t, string(body), "https://example.com/canary/c/tk2")
	})

	t.Run("different token ids produce distinct outputs", func(t *testing.T) {
		artA, err := g.Generate(
			context.Background(),
			newDocxToken("aaa"),
			testBaseURL,
		)
		require.NoError(t, err)
		artB, err := g.Generate(
			context.Background(),
			newDocxToken("bbb"),
			testBaseURL,
		)
		require.NoError(t, err)
		require.NotEqual(t, artA.Content, artB.Content)
	})
}

func TestGenerate_OutputIsValidZip(t *testing.T) {
	g := docx.New()
	art, err := g.Generate(
		context.Background(),
		newDocxToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)

	r, zErr := zip.NewReader(
		bytes.NewReader(art.Content),
		int64(len(art.Content)),
	)
	require.NoError(t, zErr, "generated docx must parse as a zip archive")
	require.NotEmpty(t, r.File, "zip must contain at least one entry")
}

func TestGenerate_FooterContainsTriggerURL(t *testing.T) {
	g := docx.New()
	art, err := g.Generate(
		context.Background(),
		newDocxToken("token42"),
		testBaseURL,
	)
	require.NoError(t, err)

	body := readFooterXML(t, art.Content)
	require.Contains(
		t,
		string(body),
		"https://canary.example.com/c/token42",
		"footer must reference the canary trigger URL after substitution",
	)
}

func TestGenerate_FooterDoesNotContainPlaceholder(t *testing.T) {
	g := docx.New()
	art, err := g.Generate(
		context.Background(),
		newDocxToken("xyz"),
		testBaseURL,
	)
	require.NoError(t, err)

	body := readFooterXML(t, art.Content)
	require.NotContains(
		t,
		string(body),
		placeholderLiteral,
		"placeholder must be fully substituted in footer2.xml",
	)
}

func TestGenerate_OtherEntriesUnchanged(t *testing.T) {
	g := docx.New()
	art, err := g.Generate(
		context.Background(),
		newDocxToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)

	templateBodies := zipEntryBodies(t, rawTemplate)
	outputBodies := zipEntryBodies(t, art.Content)
	require.Len(
		t,
		outputBodies,
		len(templateBodies),
		"output must have the same entry count as the template",
	)

	for name, tmplBody := range templateBodies {
		outBody, ok := outputBodies[name]
		require.True(t, ok, "output missing template entry %q", name)
		if name == footerEntryName {
			require.NotEqual(
				t,
				tmplBody,
				outBody,
				"footer2.xml must change after substitution",
			)
			continue
		}
		require.Equal(
			t,
			tmplBody,
			outBody,
			"non-footer entry %q must be byte-identical to template",
			name,
		)
	}
}

func TestGenerate_PreservesCompressionMethods(t *testing.T) {
	g := docx.New()
	art, err := g.Generate(
		context.Background(),
		newDocxToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)

	templateMethods := zipEntryMethods(t, rawTemplate)
	outputMethods := zipEntryMethods(t, art.Content)

	hasStore, hasDeflate := false, false
	for _, m := range templateMethods {
		switch m {
		case zip.Store:
			hasStore = true
		case zip.Deflate:
			hasDeflate = true
		}
	}
	require.True(
		t,
		hasStore && hasDeflate,
		"template must mix STORE and DEFLATE for this test to be a real regression guard",
	)

	for name, tmplMethod := range templateMethods {
		outMethod, ok := outputMethods[name]
		require.True(t, ok, "output missing template entry %q", name)
		require.Equal(
			t,
			tmplMethod,
			outMethod,
			"entry %q method mismatch (template=%d, output=%d)",
			name,
			tmplMethod,
			outMethod,
		)
	}
}

func TestTrigger_ReturnsGIFLikeWebbug(t *testing.T) {
	g := docx.New()
	tok := newDocxToken("abc")
	r := httptest.NewRequest(http.MethodGet, "/c/abc", nil)

	_, resp, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, pixel.ContentType, resp.ContentType)
	require.Len(t, resp.Body, gifByteLength)
	require.Equal(t, pixel.Clone(), resp.Body)
	require.Equal(
		t,
		cacheControlNoStoreValue,
		resp.ExtraHeaders["Cache-Control"],
	)
	require.Equal(t, pragmaNoCacheValue, resp.ExtraHeaders["Pragma"])
}

func TestTrigger_RecordsEventWithRequestMetadata(t *testing.T) {
	g := docx.New()
	tok := newDocxToken("token1")

	t.Run(
		"captures token id, source ip, user agent, referer",
		func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/c/token1", nil)
			r.Header.Set("CF-Connecting-IP", "203.0.113.50")
			r.Header.Set("User-Agent", "LibreOffice/24.2")
			r.Header.Set("Referer", "https://victim.example.com/inbox")

			evt, _, err := g.Trigger(context.Background(), tok, r)
			require.NoError(t, err)
			require.NotNil(t, evt)
			require.Equal(t, "token1", evt.TokenID)
			require.Equal(t, "203.0.113.50", evt.SourceIP)
			require.NotNil(t, evt.UserAgent)
			require.Equal(t, "LibreOffice/24.2", *evt.UserAgent)
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
				name: "XFF rightmost wins over XRI when no CF",
				headers: map[string]string{
					"X-Forwarded-For": "198.51.100.1, 198.51.100.7",
					"X-Real-IP":       "192.0.2.99",
				},
				remote: "127.0.0.1:9999",
				wantIP: "198.51.100.7",
			},
			{
				name: "XFF trailing-comma falls through to last non-empty",
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
				name: "XFF IPv6 rightmost",
				headers: map[string]string{
					"X-Forwarded-For": "198.51.100.1, 2001:db8::dead",
				},
				remote: "127.0.0.1:9999",
				wantIP: "2001:db8::dead",
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

func TestTrigger_ResponseBodyIsIndependentCopyPerCall(t *testing.T) {
	g := docx.New()
	tok := newDocxToken("abc")
	r := httptest.NewRequest(http.MethodGet, "/c/abc", nil)

	_, resp1, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)
	_, resp2, err := g.Trigger(context.Background(), tok, r)
	require.NoError(t, err)

	resp1.Body[0] = 0x00
	require.Equal(
		t,
		byte(0x47),
		resp2.Body[0],
		"each Trigger call must produce an independent body slice",
	)
}

func TestTrigger_TokenNotFound_StillReturnsGIF(t *testing.T) {
	g := docx.New()
	r := httptest.NewRequest(http.MethodGet, "/c/does-not-exist", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.100")
	r.Header.Set("User-Agent", "curl/8.0.0")

	evt, resp, err := g.Trigger(context.Background(), nil, r)
	require.NoError(
		t,
		err,
		"nil-token path must not error (spec §8.5 defense-in-depth)",
	)
	require.NotNil(t, resp, "nil-token path must still return GIF response")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, pixel.ContentType, resp.ContentType)
	require.Equal(t, pixel.Clone(), resp.Body)
	require.Nil(
		t,
		evt,
		"nil-token path returns nil event so the handler cannot persist a row with empty TokenID (FK violation)",
	)
}
