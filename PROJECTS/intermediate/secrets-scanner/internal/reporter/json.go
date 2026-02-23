// ©AngelaMos | 2026
// json.go

package reporter

import (
	"encoding/json"
	"io"

	"github.com/CarterPerez-dev/portia/pkg/types"
)

type JSON struct{}

type jsonOutput struct {
	Findings []jsonFinding `json:"findings"`
	Summary  jsonSummary   `json:"summary"`
}

type jsonFinding struct {
	RuleID      string  `json:"rule_id"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Secret      string  `json:"secret"` //nolint:gosec
	Entropy     float64 `json:"entropy,omitempty"`
	File        string  `json:"file"`
	Line        int     `json:"line"`
	Commit      string  `json:"commit,omitempty"`
	Author      string  `json:"author,omitempty"`
	HIBPStatus  string  `json:"hibp_status,omitempty"`
	BreachCount int     `json:"breach_count,omitempty"`
}

type jsonSummary struct {
	TotalFiles    int    `json:"total_files"`
	TotalFindings int    `json:"total_findings"`
	TotalRules    int    `json:"total_rules"`
	Duration      string `json:"duration"`
	HIBPChecked   int    `json:"hibp_checked,omitempty"`
	HIBPBreached  int    `json:"hibp_breached,omitempty"`
}

func (j *JSON) Report(
	w io.Writer, result *types.ScanResult,
) error {
	output := jsonOutput{
		Summary: jsonSummary{
			TotalFiles:    result.TotalFiles,
			TotalFindings: len(result.Findings),
			TotalRules:    result.TotalRules,
			Duration:      result.Duration.String(),
			HIBPChecked:   result.HIBPChecked,
			HIBPBreached:  result.HIBPBreached,
		},
	}

	output.Findings = make([]jsonFinding, len(result.Findings))
	for i, f := range result.Findings {
		output.Findings[i] = jsonFinding{
			RuleID:      f.RuleID,
			Description: f.Description,
			Severity:    f.Severity.String(),
			Secret:      maskSecret(f.Secret),
			Entropy:     f.Entropy,
			File:        f.FilePath,
			Line:        f.LineNumber,
			Commit:      f.CommitSHA,
			Author:      f.Author,
			HIBPStatus:  f.HIBPStatus.String(),
			BreachCount: f.BreachCount,
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}
