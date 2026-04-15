/*
©AngelaMos | 2026
motd_test.go
*/

package scanner

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestMOTDScanner_CleanScript(t *testing.T) {
	path := filepath.Join(
		testdataDir(), "motd", "clean-motd",
	)

	findings := ScanFileForPatterns(
		path, motdScannerName, mitreMOTD,
	)

	if len(findings) > 0 {
		t.Errorf(
			"clean motd produced %d findings, want 0",
			len(findings),
		)
		for _, f := range findings {
			t.Logf("  finding: %s (%s)", f.Title, f.Evidence)
		}
	}
}

func TestMOTDScanner_SuspiciousScript(t *testing.T) {
	path := filepath.Join(
		testdataDir(), "motd", "suspicious-motd",
	)

	findings := ScanFileForPatterns(
		path, motdScannerName, mitreMOTD,
	)

	if len(findings) < 2 {
		t.Fatalf(
			"suspicious motd: got %d findings, want >= 2",
			len(findings),
		)
	}

	hasHigh := false
	hasMedium := false
	for _, f := range findings {
		if f.Severity >= types.SeverityHigh {
			hasHigh = true
		}
		if f.Severity >= types.SeverityMedium {
			hasMedium = true
		}
	}

	if !hasHigh {
		t.Error("expected high+ severity for curl|bash")
	}
	if !hasMedium {
		t.Error("expected medium+ severity for nohup")
	}
}
