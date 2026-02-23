// ©AngelaMos | 2026
// entropy_test.go

package rules

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShannonEntropy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		data    string
		charset string
		wantMin float64
		wantMax float64
	}{
		"empty string": {
			data:    "",
			charset: "",
			wantMin: 0.0,
			wantMax: 0.0,
		},
		"single repeated character": {
			data:    "aaaaaaa",
			charset: "",
			wantMin: 0.0,
			wantMax: 0.0,
		},
		"two equally distributed chars": {
			data:    "ab",
			charset: "",
			wantMin: 1.0,
			wantMax: 1.0,
		},
		"four equally distributed chars": {
			data:    "abcd",
			charset: "",
			wantMin: 2.0,
			wantMax: 2.0,
		},
		"real password low entropy": {
			data:    "password123",
			charset: "",
			wantMin: 2.5,
			wantMax: 3.5,
		},
		"aws key high entropy": { //nolint:gosec
			data:    "AKIAIOSFODNN7EXAMPLE",
			charset: Base64Charset,
			wantMin: 3.5,
			wantMax: 5.0,
		},
		"hex string": {
			data:    "a1b2c3d4e5f6a7b8c9d0",
			charset: HexCharset,
			wantMin: 3.0,
			wantMax: 4.0,
		},
		"high entropy random base64": {
			data:    "kR9mPx2vBnQ8jL5wYz3hTf",
			charset: Base64Charset,
			wantMin: 4.0,
			wantMax: 5.5,
		},
		"charset filtering removes non-charset": {
			data:    "abc!!!def!!!ghi",
			charset: AlphanumericCharset,
			wantMin: 2.5,
			wantMax: 3.5,
		},
		"empty after charset filter": {
			data:    "!!!???",
			charset: AlphanumericCharset,
			wantMin: 0.0,
			wantMax: 0.0,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := ShannonEntropy(tc.data, tc.charset)
			assert.GreaterOrEqual(t, got, tc.wantMin,
				"entropy too low")
			assert.LessOrEqual(t, got, tc.wantMax,
				"entropy too high")
		})
	}
}

func TestShannonEntropyExactValues(t *testing.T) {
	t.Parallel()

	got := ShannonEntropy("ab", "")
	assert.InDelta(t, 1.0, got, 0.001)

	got = ShannonEntropy("aabb", "")
	assert.InDelta(t, 1.0, got, 0.001)

	got = ShannonEntropy("abcdefgh", "")
	assert.InDelta(t, 3.0, got, 0.001)
}

func TestDetectCharset(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input string
		want  string
	}{
		"hex string": {
			input: "a1b2c3d4e5f6",
			want:  "hex",
		},
		"base64 with special chars": {
			input: "kR9mPx2vBnQ8jL5w+/YzTf==",
			want:  "base64",
		},
		"pure alphanumeric": {
			input: "HelloWorld123XYZ",
			want:  "base64",
		},
		"mixed with symbols": {
			input: "hello@world#foo$bar",
			want:  "alphanumeric",
		},
		"empty string": {
			input: "",
			want:  "alphanumeric",
		},
		"only hex digits": {
			input: "deadbeef0123456789",
			want:  "hex",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := DetectCharset(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestExtractHighEntropyTokens(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		line      string
		charset   string
		threshold float64
		minLen    int
		wantCount int
		wantFirst string
	}{
		"extracts high entropy token": {
			line:      `api_key = "kR9mPx2vBnQ8jL5wYz3hTf6aU7cD"`,
			charset:   Base64Charset,
			threshold: 3.5,
			minLen:    20,
			wantCount: 1,
			wantFirst: "kR9mPx2vBnQ8jL5wYz3hTf6aU7cD",
		},
		"skips low entropy": {
			line:      `password = "aaaaaaaaaaaaaaaaaaaaaa"`,
			charset:   Base64Charset,
			threshold: 3.5,
			minLen:    20,
			wantCount: 0,
		},
		"skips short tokens": {
			line:      `key = "abc"`,
			charset:   Base64Charset,
			threshold: 1.0,
			minLen:    20,
			wantCount: 0,
		},
		"multiple tokens in one line": {
			line: `FIRST="kR9mPx2vBnQ8jL5wYz3hTf" ` +
				`SECOND="aX7bC4dE9fG2hI5jK8mN"`,
			charset:   Base64Charset,
			threshold: 3.0,
			minLen:    20,
			wantCount: 2,
		},
		"no tokens in plain text": {
			line:      "this is just a normal line of code",
			charset:   Base64Charset,
			threshold: 4.0,
			minLen:    20,
			wantCount: 0,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tokens := ExtractHighEntropyTokens(
				tc.line,
				tc.charset,
				tc.threshold,
				tc.minLen,
			)
			require.Len(t, tokens, tc.wantCount)
			if tc.wantCount > 0 && tc.wantFirst != "" {
				assert.Equal(t, tc.wantFirst, tokens[0].Value)
				assert.Greater(
					t,
					tokens[0].Entropy,
					tc.threshold,
				)
				assert.False(
					t,
					math.IsNaN(tokens[0].Entropy),
				)
			}
		})
	}
}
