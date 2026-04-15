/*
©AngelaMos | 2026
baseline_test.go
*/

package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-baseline.json")

	findings := []types.Finding{
		{
			Scanner:  "cron",
			Severity: types.SeverityHigh,
			Title:    "test finding",
			Path:     "/etc/cron.d/malicious",
			Evidence: "curl | bash",
			MITRE:    "T1053.003",
		},
	}

	if err := Save(path, findings, "test-host"); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("baseline file not created: %v", err)
	}

	snap, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if snap.Hostname != "test-host" {
		t.Errorf(
			"hostname = %q, want %q",
			snap.Hostname, "test-host",
		)
	}

	if len(snap.Findings) != 1 {
		t.Fatalf(
			"findings count = %d, want 1",
			len(snap.Findings),
		)
	}

	if snap.Findings[0].Title != "test finding" {
		t.Errorf(
			"finding title = %q, want %q",
			snap.Findings[0].Title, "test finding",
		)
	}
}

func TestDiff(t *testing.T) {
	baselineFindings := []types.Finding{
		{
			Scanner: "cron",
			Title:   "known finding",
			Path:    "/etc/cron.d/legit",
		},
		{
			Scanner: "systemd",
			Title:   "known service",
			Path:    "/etc/systemd/system/app.service",
		},
	}

	snap := Snapshot{
		Version:  "1.0.0",
		Findings: baselineFindings,
	}

	current := []types.Finding{
		{
			Scanner: "cron",
			Title:   "known finding",
			Path:    "/etc/cron.d/legit",
		},
		{
			Scanner: "systemd",
			Title:   "known service",
			Path:    "/etc/systemd/system/app.service",
		},
		{
			Scanner: "cron",
			Title:   "new malicious entry",
			Path:    "/etc/cron.d/backdoor",
		},
	}

	newFindings := Diff(snap, current)
	if len(newFindings) != 1 {
		t.Fatalf(
			"diff count = %d, want 1",
			len(newFindings),
		)
	}

	if newFindings[0].Title != "new malicious entry" {
		t.Errorf(
			"new finding title = %q, want %q",
			newFindings[0].Title, "new malicious entry",
		)
	}
}
