/*
©AngelaMos | 2026
logrotate_test.go
*/

package scanner

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestLogrotateScanner_CleanConfig(t *testing.T) {
	l := &LogrotateScanner{}
	path := filepath.Join(
		testdataDir(), "logrotate", "clean-syslog",
	)

	findings := l.scanConfig(path)
	if len(findings) > 0 {
		t.Errorf(
			"clean logrotate config produced %d findings, want 0",
			len(findings),
		)
		for _, f := range findings {
			t.Logf("  finding: %s (%s)", f.Title, f.Evidence)
		}
	}
}

func TestLogrotateScanner_MaliciousConfig(t *testing.T) {
	l := &LogrotateScanner{}
	path := filepath.Join(
		testdataDir(), "logrotate", "malicious-app",
	)

	findings := l.scanConfig(path)
	if len(findings) == 0 {
		t.Fatal(
			"malicious logrotate config produced no findings",
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
			"expected high+ severity for curl|bash in postrotate",
		)
	}
}
