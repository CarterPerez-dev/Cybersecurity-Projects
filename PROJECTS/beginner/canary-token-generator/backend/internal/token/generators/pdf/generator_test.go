// ©AngelaMos | 2026
// generator_test.go

package pdf_test

import (
	"bytes"
	"context"
	_ "embed"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/pdf"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/pixel"
)

//go:embed template/template.pdf
var rawTemplate []byte

const (
	testBaseURL              = "https://canary.example.com"
	placeholderRootLiteral   = "HONEY_TRACK_URL_PADDED_TO_FIXED_WIDTH"
	pdfContentTypeMIME       = "application/pdf"
	defaultFilename          = "Document.pdf"
	cacheControlNoStoreValue = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaNoCacheValue       = "no-cache"
	gifByteLength            = 43
	pdfHeaderPrefix          = "%PDF-"
	pdfTrailer               = "%%EOF\n"
)

func fullPlaceholder() string {
	return placeholderRootLiteral +
		strings.Repeat("_", pdf.PlaceholderLength-len(placeholderRootLiteral))
}

func newPDFToken(id string) *token.Token {
	return &token.Token{
		ID:           id,
		ManageID:     "manage-" + id,
		Type:         token.TypePDF,
		Memo:         "unit test pdf",
		AlertChannel: token.ChannelWebhook,
		Enabled:      true,
	}
}

func newPDFTokenWithFilename(id, filename string) *token.Token {
	tok := newPDFToken(id)
	tok.Filename = &filename
	return tok
}

func TestTemplate_PlaceholderRootIsByteLocatableExactlyOnce(t *testing.T) {
	require.Equal(
		t,
		1,
		bytes.Count(rawTemplate, []byte(placeholderRootLiteral)),
		"template must contain the placeholder root exactly once as literal bytes",
	)
}

func TestTemplate_FullPlaceholderIsByteLocatableExactlyOnce(t *testing.T) {
	full := fullPlaceholder()
	require.Len(
		t,
		full,
		pdf.PlaceholderLength,
		"derived placeholder must be %d bytes",
		pdf.PlaceholderLength,
	)
	require.Equal(
		t,
		1,
		bytes.Count(rawTemplate, []byte(full)),
		"template must contain the full %d-byte placeholder exactly once as literal bytes (not encoded inside a Flate stream)",
		pdf.PlaceholderLength,
	)
}

func TestTemplate_StartsWithPDFHeader(t *testing.T) {
	require.True(
		t,
		bytes.HasPrefix(rawTemplate, []byte(pdfHeaderPrefix)),
		"template must start with %q",
		pdfHeaderPrefix,
	)
}

func TestTemplate_EndsWithEOFMarker(t *testing.T) {
	require.True(
		t,
		bytes.HasSuffix(rawTemplate, []byte(pdfTrailer)),
		"template must end with %q",
		pdfTrailer,
	)
}

func TestTemplate_PdfcpuValidates(t *testing.T) {
	require.NoError(
		t,
		api.Validate(bytes.NewReader(rawTemplate), nil),
		"template must pass pdfcpu validation",
	)
}

func TestGenerator_TypeIsPDF(t *testing.T) {
	g := pdf.New()
	require.Equal(t, token.TypePDF, g.Type())
}

func TestGenerate_ArtifactKindIsFile(t *testing.T) {
	g := pdf.New()
	art, err := g.Generate(
		context.Background(),
		newPDFToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.Equal(t, generators.KindFile, art.Kind)
}

func TestGenerate_ContentTypeIsPDFMIME(t *testing.T) {
	g := pdf.New()
	art, err := g.Generate(
		context.Background(),
		newPDFToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.Equal(t, pdfContentTypeMIME, art.ContentType)
}

func TestGenerate_Filename(t *testing.T) {
	g := pdf.New()

	t.Run("nil Filename defaults to Document.pdf", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newPDFToken("abc"),
			testBaseURL,
		)
		require.NoError(t, err)
		require.Equal(t, defaultFilename, art.Filename)
	})

	t.Run(
		"empty Filename pointer defaults to Document.pdf",
		func(t *testing.T) {
			art, err := g.Generate(
				context.Background(),
				newPDFTokenWithFilename("abc", ""),
				testBaseURL,
			)
			require.NoError(t, err)
			require.Equal(t, defaultFilename, art.Filename)
		},
	)

	t.Run(
		"whitespace-only Filename defaults to Document.pdf",
		func(t *testing.T) {
			art, err := g.Generate(
				context.Background(),
				newPDFTokenWithFilename("abc", "   "),
				testBaseURL,
			)
			require.NoError(t, err)
			require.Equal(t, defaultFilename, art.Filename)
		},
	)

	t.Run("set Filename is preserved (trimmed)", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newPDFTokenWithFilename("abc", "  Q4-Plan.pdf  "),
			testBaseURL,
		)
		require.NoError(t, err)
		require.Equal(t, "Q4-Plan.pdf", art.Filename)
	})
}

func TestGenerate_TriggerURL(t *testing.T) {
	g := pdf.New()

	t.Run("base URL trailing slash trimmed", func(t *testing.T) {
		artA, err := g.Generate(
			context.Background(),
			newPDFToken("tk1"),
			"https://canary.example.com",
		)
		require.NoError(t, err)
		artB, err := g.Generate(
			context.Background(),
			newPDFToken("tk1"),
			"https://canary.example.com/",
		)
		require.NoError(t, err)

		require.Contains(
			t,
			string(artA.Content),
			"https://canary.example.com/c/tk1",
		)
		require.Contains(
			t,
			string(artB.Content),
			"https://canary.example.com/c/tk1",
		)
	})

	t.Run("base URL subpath preserved", func(t *testing.T) {
		art, err := g.Generate(
			context.Background(),
			newPDFToken("tk2"),
			"https://example.com/canary",
		)
		require.NoError(t, err)
		require.Contains(
			t,
			string(art.Content),
			"https://example.com/canary/c/tk2",
		)
	})

	t.Run(
		"different token ids produce distinct outputs",
		func(t *testing.T) {
			artA, err := g.Generate(
				context.Background(),
				newPDFToken("aaa"),
				testBaseURL,
			)
			require.NoError(t, err)
			artB, err := g.Generate(
				context.Background(),
				newPDFToken("bbb"),
				testBaseURL,
			)
			require.NoError(t, err)
			require.NotEqual(t, artA.Content, artB.Content)
		},
	)
}

func TestGenerate_LengthUnchanged(t *testing.T) {
	g := pdf.New()
	art, err := g.Generate(
		context.Background(),
		newPDFToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.Len(
		t,
		art.Content,
		len(rawTemplate),
		"output byte length must equal template byte length so xref offsets remain valid",
	)
}

func TestGenerate_ContainsTriggerURL(t *testing.T) {
	g := pdf.New()
	art, err := g.Generate(
		context.Background(),
		newPDFToken("token42"),
		testBaseURL,
	)
	require.NoError(t, err)

	require.True(
		t,
		bytes.Contains(
			art.Content,
			[]byte("https://canary.example.com/c/token42"),
		),
		"output must contain the canary trigger URL after substitution",
	)
}

func TestGenerate_ByteAfterTokenIDIsNotUnderscore(t *testing.T) {
	g := pdf.New()
	art, err := g.Generate(
		context.Background(),
		newPDFToken("token42"),
		testBaseURL,
	)
	require.NoError(t, err)

	urlPrefix := testBaseURL + "/c/token42"
	idx := bytes.Index(art.Content, []byte(urlPrefix))
	require.GreaterOrEqual(
		t,
		idx,
		0,
		"trigger URL prefix must be present in PDF output",
	)
	after := art.Content[idx+len(urlPrefix)]
	require.NotEqual(
		t,
		byte('_'),
		after,
		"byte immediately after the token id must not be underscore — "+
			"otherwise Acrobat fetches /c/token42____ and the canary silently "+
			"no-ops on lookup (audit finding F2)",
	)
}

func TestGenerate_PlaceholderRemoved(t *testing.T) {
	g := pdf.New()
	art, err := g.Generate(
		context.Background(),
		newPDFToken("xyz"),
		testBaseURL,
	)
	require.NoError(t, err)

	require.False(
		t,
		bytes.Contains(art.Content, []byte(placeholderRootLiteral)),
		"placeholder root must be fully substituted out of the output",
	)
}

func TestGenerate_TooLongURL_ReturnsError(t *testing.T) {
	g := pdf.New()

	overLongID := strings.Repeat("x", pdf.PlaceholderLength)
	_, err := g.Generate(
		context.Background(),
		newPDFToken(overLongID),
		testBaseURL,
	)
	require.Error(t, err)
	require.ErrorIs(t, err, pdf.ErrTriggerURLTooLong)
}

func TestGenerate_BoundaryURL_AtPlaceholderLength_Succeeds(t *testing.T) {
	g := pdf.New()

	base := "http://x"
	prefix := base + "/c/"
	idLen := pdf.PlaceholderLength - len(prefix)
	require.Positive(
		t,
		idLen,
		"test base+/c/ must leave room for at least one id char",
	)
	id := strings.Repeat("a", idLen)

	art, err := g.Generate(
		context.Background(),
		newPDFToken(id),
		base,
	)
	require.NoError(
		t,
		err,
		"URL whose length exactly equals placeholder length must succeed (no padding needed)",
	)
	require.True(
		t,
		bytes.Contains(art.Content, []byte(prefix+id)),
		"boundary URL must be present in output",
	)
}

func TestGenerate_PdfcpuValidates(t *testing.T) {
	g := pdf.New()
	art, err := g.Generate(
		context.Background(),
		newPDFToken("validate-me"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.NoError(
		t,
		api.Validate(bytes.NewReader(art.Content), nil),
		"output PDF must remain valid after placeholder substitution",
	)
}

func TestGenerate_OutputDifferentFromTemplate(t *testing.T) {
	g := pdf.New()
	art, err := g.Generate(
		context.Background(),
		newPDFToken("abc"),
		testBaseURL,
	)
	require.NoError(t, err)
	require.NotEqual(
		t,
		rawTemplate,
		art.Content,
		"output must differ from template after substitution",
	)
}

func TestGenerate_SubstitutionAtSamePlaceholderPosition(t *testing.T) {
	g := pdf.New()
	art, err := g.Generate(
		context.Background(),
		newPDFToken("position-check"),
		testBaseURL,
	)
	require.NoError(t, err)

	placeholderOffset := bytes.Index(
		rawTemplate,
		[]byte(placeholderRootLiteral),
	)
	require.GreaterOrEqual(t, placeholderOffset, 0)

	urlOffset := bytes.Index(
		art.Content,
		[]byte("https://canary.example.com/c/position-check"),
	)
	require.Equal(
		t,
		placeholderOffset,
		urlOffset,
		"trigger URL must occupy the same byte offset the placeholder did",
	)
}

func TestTrigger_ReturnsGIFLikeWebbug(t *testing.T) {
	g := pdf.New()
	tok := newPDFToken("abc")
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
	g := pdf.New()
	tok := newPDFToken("token1")

	t.Run(
		"captures token id, source ip, user agent, referer",
		func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/c/token1", nil)
			r.Header.Set("CF-Connecting-IP", "203.0.113.50")
			r.Header.Set("User-Agent", "AcrobatReader/2024.001")
			r.Header.Set("Referer", "https://victim.example.com/share")

			evt, _, err := g.Trigger(context.Background(), tok, r)
			require.NoError(t, err)
			require.NotNil(t, evt)
			require.Equal(t, "token1", evt.TokenID)
			require.Equal(t, "203.0.113.50", evt.SourceIP)
			require.NotNil(t, evt.UserAgent)
			require.Equal(t, "AcrobatReader/2024.001", *evt.UserAgent)
			require.NotNil(t, evt.Referer)
			require.Equal(
				t,
				"https://victim.example.com/share",
				*evt.Referer,
			)
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
	g := pdf.New()
	tok := newPDFToken("abc")
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
	g := pdf.New()
	r := httptest.NewRequest(http.MethodGet, "/c/does-not-exist", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.100")
	r.Header.Set("User-Agent", "AcrobatReader/2024")

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
