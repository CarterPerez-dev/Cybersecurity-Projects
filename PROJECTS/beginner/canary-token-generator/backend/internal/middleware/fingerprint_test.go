// ©AngelaMos | 2026
// fingerprint_test.go

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
)

func newRequest(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestRealIP_Precedence(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		remote  string
		want    string
	}{
		{
			"CF wins",
			map[string]string{
				"CF-Connecting-IP": "203.0.113.10",
				"X-Forwarded-For":  "198.51.100.1",
				"X-Real-IP":        "192.0.2.99",
			},
			"127.0.0.1:9",
			"203.0.113.10",
		},
		{
			"XFF rightmost no CF",
			map[string]string{
				"X-Forwarded-For": "198.51.100.1, 198.51.100.7",
				"X-Real-IP":       "192.0.2.99",
			},
			"127.0.0.1:9",
			"198.51.100.7",
		},
		{
			"XFF trailing comma falls through",
			map[string]string{
				"X-Forwarded-For": "198.51.100.1, ",
				"X-Real-IP":       "192.0.2.99",
			},
			"127.0.0.1:9",
			"198.51.100.1",
		},
		{
			"XFF empty entries fall to XRI",
			map[string]string{
				"X-Forwarded-For": ", ,",
				"X-Real-IP":       "192.0.2.99",
			},
			"127.0.0.1:9",
			"192.0.2.99",
		},
		{
			"XRI when no CF or XFF",
			map[string]string{"X-Real-IP": "192.0.2.99"},
			"127.0.0.1:9",
			"192.0.2.99",
		},
		{"RemoteAddr IPv4 strips port", nil, "127.0.0.1:9999", "127.0.0.1"},
		{
			"RemoteAddr IPv6 strips brackets",
			nil,
			"[2001:db8::1]:54321",
			"2001:db8::1",
		},
		{"RemoteAddr loopback IPv6", nil, "[::1]:9", "::1"},
		{"RemoteAddr no port fallback", nil, "127.0.0.1", "127.0.0.1"},
		{
			"XFF IPv6 rightmost",
			map[string]string{
				"X-Forwarded-For": "198.51.100.1, 2001:db8::dead",
			},
			"127.0.0.1:9",
			"2001:db8::dead",
		},
		{
			"CF trimmed",
			map[string]string{"CF-Connecting-IP": "  203.0.113.10  "},
			"127.0.0.1:9",
			"203.0.113.10",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(
				t,
				tc.want,
				middleware.RealIP(newRequest(tc.remote, tc.headers)),
			)
		})
	}
}

func TestOptionalHeader(t *testing.T) {
	require.Nil(t, middleware.OptionalHeader(""))
	require.Nil(t, middleware.OptionalHeader("   "))
	v := middleware.OptionalHeader("  hello  ")
	require.NotNil(t, v)
	require.Equal(t, "hello", *v)
}

func TestExtractFingerprint_DeterministicAndLength(t *testing.T) {
	r1 := newRequest("127.0.0.1:9", map[string]string{
		"CF-Connecting-IP": "203.0.113.10",
		"User-Agent":       "Mozilla/5.0",
	})
	r2 := newRequest("10.0.0.1:9", map[string]string{
		"CF-Connecting-IP": "203.0.113.10",
		"User-Agent":       "Mozilla/5.0",
	})

	fp1 := middleware.ExtractFingerprint(r1)
	fp2 := middleware.ExtractFingerprint(r2)
	require.Equal(t, fp1, fp2, "same realIP + UA must yield same fingerprint")
	require.Len(t, fp1, 16)
	require.Regexp(t, `^[0-9a-f]{16}$`, fp1)
}

func TestExtractFingerprint_DifferentIPsDifferentFingerprints(t *testing.T) {
	a := middleware.ExtractFingerprint(newRequest(
		"127.0.0.1:9",
		map[string]string{
			"CF-Connecting-IP": "203.0.113.1",
			"User-Agent":       "X",
		},
	))
	b := middleware.ExtractFingerprint(newRequest(
		"127.0.0.1:9",
		map[string]string{
			"CF-Connecting-IP": "203.0.113.2",
			"User-Agent":       "X",
		},
	))
	require.NotEqual(t, a, b)
}

func TestKeyByFingerprint_HasPrefix(t *testing.T) {
	key := middleware.KeyByFingerprint(newRequest("127.0.0.1:9", nil))
	require.True(t, strings.HasPrefix(key, "ratelimit:fp:"))
	require.Len(t, key, len("ratelimit:fp:")+16)
}
