/*
©AngelaMos | 2026
baseline.go

Baseline snapshot save, load, and diff operations

Saves the current scan findings as a JSON snapshot file. On
subsequent runs, loads the baseline and computes a diff showing
only new findings that were not present in the clean snapshot.
This reduces noise on systems with many legitimate persistence
entries.
*/

package baseline

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

type Snapshot struct {
	Version  string          `json:"version"`
	Hostname string          `json:"hostname"`
	Findings []types.Finding `json:"findings"`
}

func Save(
	path string, findings []types.Finding, hostname string,
) error {
	snap := Snapshot{
		Version:  types.Version,
		Hostname: hostname,
		Findings: findings,
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}

	if err := os.WriteFile(
		path, data, 0o600,
	); err != nil {
		return fmt.Errorf("writing baseline: %w", err)
	}

	return nil
}

func Load(path string) (Snapshot, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return Snapshot{}, fmt.Errorf(
			"reading baseline: %w", err,
		)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return Snapshot{}, fmt.Errorf(
			"parsing baseline: %w", err,
		)
	}
	return snap, nil
}

func Diff(
	baseline Snapshot, current []types.Finding,
) []types.Finding {
	known := make(map[string]bool, len(baseline.Findings))
	for _, f := range baseline.Findings {
		known[findingKey(f)] = true
	}

	var newFindings []types.Finding
	for _, f := range current {
		if !known[findingKey(f)] {
			newFindings = append(newFindings, f)
		}
	}
	return newFindings
}

func findingKey(f types.Finding) string {
	return f.Scanner + "|" + f.Path + "|" + f.Title
}
