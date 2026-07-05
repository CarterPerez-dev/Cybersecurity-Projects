// ©AngelaMos | 2026
// normalize_test.go

package normalize

import "testing"

var params = []string{"utm_*", "gclid", "fbclid", "ref", "mc_cid", "mc_eid"}

func TestCanonicalURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase host+scheme", "HTTPS://Example.COM/Path", "https://example.com/Path"},
		{"drop fragment", "https://example.com/a#section", "https://example.com/a"},
		{"strip utm params", "https://example.com/a?utm_source=x&utm_medium=y&id=7", "https://example.com/a?id=7"},
		{"strip gclid fbclid ref", "https://example.com/a?gclid=1&fbclid=2&ref=z&keep=1", "https://example.com/a?keep=1"},
		{"strip mailchimp", "https://example.com/a?mc_cid=1&mc_eid=2", "https://example.com/a"},
		{"drop trailing slash", "https://example.com/a/b/", "https://example.com/a/b"},
		{"root trailing slash", "https://example.com/", "https://example.com"},
		{"sorted query", "https://example.com/a?b=2&a=1", "https://example.com/a?a=1&b=2"},
		{"tracking case insensitive", "https://example.com/a?UTM_Source=x&id=1", "https://example.com/a?id=1"},
		{"path preserved case", "https://example.com/Foo/Bar", "https://example.com/Foo/Bar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalURL(tc.in, params)
			if err != nil {
				t.Fatalf("CanonicalURL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("CanonicalURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCanonicalURLCollapsesTracking(t *testing.T) {
	a, _ := CanonicalURL("https://example.com/story?utm_source=twitter", params)
	b, _ := CanonicalURL("https://example.com/story", params)
	if a != b {
		t.Errorf("tracking variants did not collapse: %q vs %q", a, b)
	}
	if ContentHash(a) != ContentHash(b) {
		t.Error("content hashes differ for tracking variants")
	}
}

func TestCanonicalURLErrors(t *testing.T) {
	for _, in := range []string{"", "not a url", "/relative/only"} {
		if _, err := CanonicalURL(in, params); err == nil {
			t.Errorf("CanonicalURL(%q) expected error", in)
		}
	}
}

func TestNormalizeTitle(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"CVE-2021-44228: Log4Shell!", "cve 2021 44228 log4shell"},
		{"  Multiple   Spaces  ", "multiple spaces"},
		{"Punctuation, and; stuff.", "punctuation and stuff"},
		{"Café déjà vu", "café déjà vu"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := NormalizeTitle(tc.in); got != tc.want {
			t.Errorf("NormalizeTitle(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeTitleStableHash(t *testing.T) {
	a := TitleHash(NormalizeTitle("Breaking: Big Hack!!!"))
	b := TitleHash(NormalizeTitle("breaking big hack"))
	if a != b {
		t.Error("normalized-title hashes differ for equivalent titles")
	}
}

func TestStripHTML(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"<p>Hello <b>world</b></p>", "Hello world"},
		{"<div>a</div>\n<div>b</div>", "a b"},
		{"<script>bad()</script>visible", "visible"},
		{"plain text", "plain text"},
		{"<a href='x'>link</a> and text", "link and text"},
	}
	for _, tc := range cases {
		if got := StripHTML(tc.in); got != tc.want {
			t.Errorf("StripHTML(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestContentHashDeterministic(t *testing.T) {
	const u = "https://example.com/a"
	if ContentHash(u) != ContentHash(u) {
		t.Error("ContentHash not deterministic")
	}
	if len(ContentHash(u)) != 64 {
		t.Errorf("ContentHash length = %d, want 64 hex chars", len(ContentHash(u)))
	}
}
