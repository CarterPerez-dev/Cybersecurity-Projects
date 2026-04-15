/*
©AngelaMos | 2026
profile_test.go
*/

package scanner

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestProfileScanner_CleanBashrc(t *testing.T) {
	path := filepath.Join(
		testdataDir(), "profiles", "clean-bashrc",
	)
	findings := ScanFileForPatterns(
		path, profileScannerName, mitreProfile,
	)

	if len(findings) > 0 {
		t.Errorf(
			"clean bashrc produced %d findings, want 0",
			len(findings),
		)
		for _, f := range findings {
			t.Logf("  finding: %s (%s)", f.Title, f.Evidence)
		}
	}
}

func TestProfileScanner_InjectedBashrc(t *testing.T) {
	path := filepath.Join(
		testdataDir(), "profiles", "injected-bashrc",
	)
	findings := ScanFileForPatterns(
		path, profileScannerName, mitreProfile,
	)

	if len(findings) < 3 {
		t.Fatalf(
			"injected bashrc: got %d findings, want >= 3",
			len(findings),
		)
	}

	hasCritical := false
	hasHigh := false
	for _, f := range findings {
		if f.Severity == types.SeverityCritical {
			hasCritical = true
		}
		if f.Severity == types.SeverityHigh {
			hasHigh = true
		}
	}

	if !hasCritical {
		t.Error("expected critical for LD_PRELOAD")
	}
	if !hasHigh {
		t.Error("expected high for alias hijack or curl|bash")
	}
}
