/*
©AngelaMos | 2026
generator_test.go
*/

package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestGeneratorScanner_MaliciousGenerator(t *testing.T) {
	root := t.TempDir()
	genDir := filepath.Join(
		root, "etc", "systemd", "system-generators",
	)
	if err := os.MkdirAll(genDir, 0o750); err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(
		testdataDir(), "generator", "malicious-generator",
	)
	data, err := os.ReadFile(src) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(
		t, filepath.Join(genDir, "backdoor-gen"), string(data),
	)

	g := &GeneratorScanner{}
	findings := g.Scan(root)

	if len(findings) == 0 {
		t.Fatal("generator with content produced no findings")
	}

	hasExistence := false
	hasPattern := false
	for _, f := range findings {
		if f.Title == "Systemd generator executable found" {
			hasExistence = true
		}
		if f.Severity >= types.SeverityHigh {
			hasPattern = true
		}
	}

	if !hasExistence {
		t.Error("expected existence finding for generator")
	}
	if !hasPattern {
		t.Error(
			"expected high+ finding for curl|bash in generator",
		)
	}
}

func TestGeneratorScanner_EmptyDir(t *testing.T) {
	g := &GeneratorScanner{}
	findings := g.Scan(t.TempDir())

	if len(findings) > 0 {
		t.Errorf(
			"empty generator dirs produced %d findings, want 0",
			len(findings),
		)
	}
}
