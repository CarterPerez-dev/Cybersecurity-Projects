/*
©AngelaMos | 2026
initd_test.go
*/

package scanner

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestInitdScanner_RcLocal(t *testing.T) {
	i := &InitdScanner{}
	path := filepath.Join(
		testdataDir(), "initd", "rc.local",
	)

	findings := i.scanRcLocal(path)
	if len(findings) == 0 {
		t.Fatal("rc.local with content produced no findings")
	}

	hasContent := false
	hasHighOrAbove := false
	for _, f := range findings {
		if f.Title == "rc.local contains executable content" {
			hasContent = true
		}
		if f.Severity >= types.SeverityHigh {
			hasHighOrAbove = true
		}
	}

	if !hasContent {
		t.Error(
			"expected 'rc.local contains executable content' finding",
		)
	}
	if !hasHighOrAbove {
		t.Error(
			"expected high+ finding for wget|sh in rc.local",
		)
	}
}

func TestInitdScanner_EmptyRcLocal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rc.local")
	writeTestFile(t, path, "#!/bin/sh\n# nothing here\nexit 0\n")

	i := &InitdScanner{}
	findings := i.scanRcLocal(path)

	if len(findings) > 0 {
		t.Errorf(
			"empty rc.local produced %d findings, want 0",
			len(findings),
		)
	}
}
