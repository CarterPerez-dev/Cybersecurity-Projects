/*
©AngelaMos | 2026
sshrc_test.go
*/

package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestSSHRCScanner_Exists(t *testing.T) {
	root := t.TempDir()
	sshDir := filepath.Join(root, "etc", "ssh")
	if err := os.MkdirAll(sshDir, 0o750); err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(
		testdataDir(), "sshrc", "sshrc-malicious",
	)
	data, err := os.ReadFile(src) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(
		t, filepath.Join(sshDir, "sshrc"), string(data),
	)

	s := &SSHRCScanner{}
	findings := s.Scan(root)

	if len(findings) == 0 {
		t.Fatal("sshrc with content produced no findings")
	}

	hasExistence := false
	hasPattern := false
	for _, f := range findings {
		if f.Title == "System-wide sshrc login script exists" {
			hasExistence = true
		}
		if f.Severity >= types.SeverityMedium &&
			f.Title != "System-wide sshrc login script exists" {
			hasPattern = true
		}
	}

	if !hasExistence {
		t.Error("expected existence finding for sshrc")
	}
	if !hasPattern {
		t.Error(
			"expected pattern finding for curl in sshrc",
		)
	}
}

func TestSSHRCScanner_Missing(t *testing.T) {
	s := &SSHRCScanner{}
	findings := s.Scan(t.TempDir())

	if len(findings) > 0 {
		t.Errorf(
			"missing sshrc produced %d findings, want 0",
			len(findings),
		)
	}
}
