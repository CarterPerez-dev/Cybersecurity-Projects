/*
©AngelaMos | 2026
completion_test.go
*/

package scanner

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestCompletionScanner_CleanScript(t *testing.T) {
	path := filepath.Join(
		testdataDir(), "completion", "clean-completion",
	)

	findings := ScanFileForPatterns(
		path, completionScannerName, mitreCompletion,
	)

	if len(findings) > 0 {
		t.Errorf(
			"clean completion produced %d findings, want 0",
			len(findings),
		)
		for _, f := range findings {
			t.Logf("  finding: %s (%s)", f.Title, f.Evidence)
		}
	}
}

func TestCompletionScanner_MaliciousScript(t *testing.T) {
	path := filepath.Join(
		testdataDir(), "completion", "malicious-completion",
	)

	findings := ScanFileForPatterns(
		path, completionScannerName, mitreCompletion,
	)

	if len(findings) == 0 {
		t.Fatal(
			"malicious completion produced no findings",
		)
	}

	hasHigh := false
	for _, f := range findings {
		if f.Severity >= types.SeverityHigh {
			hasHigh = true
		}
	}

	if !hasHigh {
		t.Error(
			"expected high+ severity for curl|bash in completion",
		)
	}
}
