/*
©AngelaMos | 2026
xdg_test.go
*/

package scanner

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestXDGScanner_CleanDesktop(t *testing.T) {
	x := &XDGScanner{}
	path := filepath.Join(
		testdataDir(), "xdg", "clean.desktop",
	)

	findings := x.analyzeDesktop(path)
	if len(findings) > 0 {
		t.Errorf(
			"clean desktop file produced %d findings, want 0",
			len(findings),
		)
		for _, f := range findings {
			t.Logf("  finding: %s (%s)", f.Title, f.Evidence)
		}
	}
}

func TestXDGScanner_SuspiciousDesktop(t *testing.T) {
	x := &XDGScanner{}
	path := filepath.Join(
		testdataDir(), "xdg", "suspicious.desktop",
	)

	findings := x.analyzeDesktop(path)
	if len(findings) == 0 {
		t.Fatal(
			"suspicious desktop file produced no findings",
		)
	}

	hasHigh := false
	for _, f := range findings {
		if f.Severity >= types.SeverityHigh {
			hasHigh = true
		}
	}

	if !hasHigh {
		t.Error("expected high+ severity for curl|sh in Exec=")
	}
}

func TestXDGScanner_TmpDirDesktop(t *testing.T) {
	x := &XDGScanner{}
	path := filepath.Join(
		testdataDir(), "xdg", "tmpdir.desktop",
	)

	findings := x.analyzeDesktop(path)
	if len(findings) == 0 {
		t.Fatal(
			"tmp dir desktop file produced no findings",
		)
	}

	hasTmp := false
	for _, f := range findings {
		if strings.Contains(f.Title, "temp") ||
			strings.Contains(f.Title, "temporary") {
			hasTmp = true
		}
	}

	if !hasTmp {
		t.Error(
			"expected temp directory finding for /tmp path",
		)
	}
}
