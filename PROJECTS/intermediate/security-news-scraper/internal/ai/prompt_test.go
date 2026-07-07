// ©AngelaMos | 2026
// prompt_test.go

package ai

import (
	"strings"
	"testing"
)

func TestBuildPromptIncludesContext(t *testing.T) {
	cvss := 9.8
	epss := 0.97
	_, user := buildPrompt(IdeationRequest{
		Titles:      []string{"Massive breach at ACME"},
		Sources:     []string{"Krebs", "The Register"},
		CVEs:        []CVEContext{{ID: "CVE-2025-5777", CVSS: &cvss, KEV: true, EPSS: &epss}},
		ClusterSize: 2,
		SpanHours:   6,
	})
	for _, want := range []string{"Massive breach at ACME", "Krebs", "The Register", "CVE-2025-5777", "CVSS 9.8", "KEV", "EPSS 0.97"} {
		if !strings.Contains(user, want) {
			t.Errorf("user prompt missing %q\n---\n%s", want, user)
		}
	}
}

func TestParseResultValid(t *testing.T) {
	res, err := parseResult(`{"summary":"s","why":"w","angles":["a","b","c"],"format":"video"}`)
	if err != nil {
		t.Fatalf("parseResult: %v", err)
	}
	if res.Summary != "s" || res.Why != "w" || len(res.Angles) != 3 || res.Format != FormatVideo {
		t.Errorf("got %+v", res)
	}
}

func TestParseResultTolerantWrapper(t *testing.T) {
	raw := "Here is the JSON:\n```json\n{\"summary\":\"s\",\"why\":\"w\",\"angles\":[\"a\"],\"format\":\"blog\"}\n```\nHope that helps."
	res, err := parseResult(raw)
	if err != nil {
		t.Fatalf("parseResult: %v", err)
	}
	if res.Summary != "s" || len(res.Angles) != 1 {
		t.Errorf("got %+v", res)
	}
}

func TestParseResultIgnoresPreJSONBraces(t *testing.T) {
	raw := `Let me plan {step: outline} then answer: {"summary":"real","why":"w","angles":["a","b"],"format":"blog"} done.`
	res, err := parseResult(raw)
	if err != nil {
		t.Fatalf("parseResult: %v", err)
	}
	if res.Summary != "real" || len(res.Angles) != 2 {
		t.Errorf("got %+v", res)
	}
}

func TestParseResultErrors(t *testing.T) {
	cases := []string{
		"no json here",
		`{"why":"w","angles":["a"],"format":"blog"}`,
		`{"summary":"s","why":"w","angles":[],"format":"blog"}`,
		`{"summary":"s",`,
	}
	for _, c := range cases {
		if _, err := parseResult(c); err == nil {
			t.Errorf("parseResult(%q) = nil error, want error", c)
		}
	}
}

func TestNormalizeFormat(t *testing.T) {
	cases := map[string]string{
		"newsletter": FormatNewsletter,
		"VIDEO":      FormatVideo,
		"blog":       FormatBlog,
		"nonsense":   FormatBlog,
		"":           FormatBlog,
	}
	for in, want := range cases {
		if got := normalizeFormat(in); got != want {
			t.Errorf("normalizeFormat(%q) = %q, want %q", in, got, want)
		}
	}
}
