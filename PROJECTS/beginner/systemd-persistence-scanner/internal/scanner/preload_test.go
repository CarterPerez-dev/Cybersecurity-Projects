/*
©AngelaMos | 2026
preload_test.go
*/

package scanner

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestPreloadScanner_NonEmpty(t *testing.T) {
	p := &PreloadScanner{}
	path := filepath.Join(
		testdataDir(), "preload", "ld.so.preload",
	)

	findings := p.scanPreloadFile(path)
	if len(findings) == 0 {
		t.Fatal("ld.so.preload with entry produced no findings")
	}

	if findings[0].Severity != types.SeverityCritical {
		t.Errorf(
			"severity = %v, want critical",
			findings[0].Severity,
		)
	}
}

func TestPreloadScanner_Environment(t *testing.T) {
	p := &PreloadScanner{}
	path := filepath.Join(
		testdataDir(), "preload", "environment",
	)

	findings := p.scanEnvironment(path)
	if len(findings) == 0 {
		t.Fatal("environment with LD_PRELOAD produced no findings")
	}

	if findings[0].Severity != types.SeverityCritical {
		t.Errorf(
			"severity = %v, want critical",
			findings[0].Severity,
		)
	}
}
