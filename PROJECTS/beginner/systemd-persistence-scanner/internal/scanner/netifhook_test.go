/*
©AngelaMos | 2026
netifhook_test.go
*/

package scanner

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestNetIfHookScanner_CleanHook(t *testing.T) {
	path := filepath.Join(
		testdataDir(), "netifhook", "clean-hook",
	)

	findings := ScanFileForPatterns(
		path, netifhookScannerName, mitreNetifhook,
	)

	if len(findings) > 0 {
		t.Errorf(
			"clean network hook produced %d findings, want 0",
			len(findings),
		)
		for _, f := range findings {
			t.Logf("  finding: %s (%s)", f.Title, f.Evidence)
		}
	}
}

func TestNetIfHookScanner_MaliciousHook(t *testing.T) {
	path := filepath.Join(
		testdataDir(), "netifhook", "malicious-hook",
	)

	findings := ScanFileForPatterns(
		path, netifhookScannerName, mitreNetifhook,
	)

	if len(findings) == 0 {
		t.Fatal(
			"malicious network hook produced no findings",
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
			"expected high+ severity for wget|sh in network hook",
		)
	}
}
