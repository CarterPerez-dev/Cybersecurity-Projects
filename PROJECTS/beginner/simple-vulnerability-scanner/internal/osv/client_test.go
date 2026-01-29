// ©AngelaMos | 2026
// client_test.go

package osv

import (
	"testing"
)

func TestExtractSeverityCVSSV3(t *testing.T) {
	t.Parallel()

	v := &osvVuln{
		Severity: []severity{
			{Type: "CVSS_V3", Score: "9.8"},
		},
	}
	got := extractSeverity(v)
	if got != "CRITICAL" { //nolint:goconst
		t.Errorf("extractSeverity = %q, want CRITICAL", got)
	}
}

func TestExtractSeverityCVSSV4(t *testing.T) {
	t.Parallel()

	v := &osvVuln{
		Severity: []severity{
			{Type: "CVSS_V4", Score: "7.5"},
		},
	}
	got := extractSeverity(v)
	if got != "HIGH" {
		t.Errorf("extractSeverity = %q, want HIGH", got)
	}
}

func TestExtractSeverityCVSSVector(t *testing.T) {
	t.Parallel()

	v := &osvVuln{
		Severity: []severity{
			{
				Type:  "CVSS_V3",
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8",
			},
		},
	}
	got := extractSeverity(v)
	if got != "CRITICAL" {
		t.Errorf("extractSeverity = %q, want CRITICAL", got)
	}
}

func TestExtractSeverityDatabaseSpecific(t *testing.T) {
	t.Parallel()

	v := &osvVuln{
		DatabaseSpecific: map[string]any{
			"severity": "MODERATE",
		},
	}
	got := extractSeverity(v)
	if got != "MODERATE" {
		t.Errorf("extractSeverity = %q, want MODERATE", got)
	}
}

func TestExtractSeverityUnknown(t *testing.T) {
	t.Parallel()

	v := &osvVuln{}
	got := extractSeverity(v)
	if got != "UNKNOWN" {
		t.Errorf("extractSeverity = %q, want UNKNOWN", got)
	}
}

func TestClassifyScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		score float64
		want  string
	}{
		{9.8, "CRITICAL"},
		{9.0, "CRITICAL"},
		{8.5, "HIGH"},
		{7.0, "HIGH"},
		{6.9, "MODERATE"},
		{4.0, "MODERATE"},
		{3.9, "LOW"},
		{0.1, "LOW"},
		{0.0, "NONE"},
	}

	for _, tt := range tests {
		got := classifyScore(tt.score)
		if got != tt.want {
			t.Errorf(
				"classifyScore(%v) = %q, want %q",
				tt.score, got, tt.want,
			)
		}
	}
}

func TestIsDuplicate(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{
		"CVE-2023-1234": true,
	}

	v1 := &osvVuln{
		ID:      "GHSA-xxxx-yyyy",
		Aliases: []string{"CVE-2023-1234"},
	}
	if !isDuplicate(v1, seen) {
		t.Error("should detect duplicate via alias")
	}

	v2 := &osvVuln{
		ID:      "CVE-2023-1234",
		Aliases: []string{},
	}
	if !isDuplicate(v2, seen) {
		t.Error("should detect duplicate via direct ID")
	}

	v3 := &osvVuln{
		ID:      "PYSEC-2024-001",
		Aliases: []string{"CVE-2024-9999"},
	}
	if isDuplicate(v3, seen) {
		t.Error("should not flag non-duplicate as duplicate")
	}
}

func TestExtractFixed(t *testing.T) {
	t.Parallel()

	aff := []affected{
		{
			Package: pkg{Name: "django", Ecosystem: "PyPI"},
			Ranges: []rng{
				{
					Type: "ECOSYSTEM",
					Events: []event{
						{Introduced: "0"},
						{Fixed: "4.2.8"},
					},
				},
			},
		},
	}

	got := extractFixed(aff)
	if got != "4.2.8" {
		t.Errorf("extractFixed = %q, want 4.2.8", got)
	}
}

func TestExtractFixedNoFix(t *testing.T) {
	t.Parallel()

	aff := []affected{
		{
			Package: pkg{Name: "django", Ecosystem: "PyPI"},
			Ranges: []rng{
				{
					Type:   "ECOSYSTEM",
					Events: []event{{Introduced: "0"}},
				},
			},
		},
	}

	got := extractFixed(aff)
	if got != "" {
		t.Errorf("extractFixed = %q, want empty", got)
	}
}

func TestExtractLink(t *testing.T) {
	t.Parallel()

	refs := []reference{
		{Type: "WEB", URL: "https://example.com"},
		{
			Type: "ADVISORY",
			URL:  "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
		},
	}

	got := extractLink(refs)
	if got != "https://nvd.nist.gov/vuln/detail/CVE-2023-1234" {
		t.Errorf("extractLink preferred ADVISORY, got %q", got)
	}
}

func TestExtractLinkFallback(t *testing.T) {
	t.Parallel()

	refs := []reference{
		{Type: "PACKAGE", URL: "https://pypi.org/project/django"},
		{Type: "WEB", URL: "https://example.com/info"},
	}

	got := extractLink(refs)
	if got != "https://example.com/info" {
		t.Errorf("extractLink should fall back to WEB, got %q", got)
	}
}

func TestExtractLinkEmpty(t *testing.T) {
	t.Parallel()

	got := extractLink(nil)
	if got != "" {
		t.Errorf("extractLink(nil) = %q, want empty", got)
	}
}

func TestCollectUniqueIDs(t *testing.T) {
	t.Parallel()

	batch := &batchResponse{
		Results: []batchResult{
			{Vulns: []vulnRef{
				{ID: "CVE-A"},
				{ID: "CVE-B"},
			}},
			{Vulns: []vulnRef{
				{ID: "CVE-B"},
				{ID: "CVE-C"},
			}},
			{Vulns: nil},
		},
	}

	ids := collectUniqueIDs(batch)
	if len(ids) != 3 {
		t.Fatalf("len = %d, want 3", len(ids))
	}

	seen := make(map[string]bool)
	for _, id := range ids {
		if seen[id] {
			t.Errorf("duplicate ID: %s", id)
		}
		seen[id] = true
	}
}
