// ©AngelaMos | 2026
// sarif.go

package reporter

import (
	"encoding/json"
	"io"

	"github.com/CarterPerez-dev/portia/pkg/types"
)

type SARIF struct{}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func (s *SARIF) Report(
	w io.Writer, result *types.ScanResult,
) error {
	ruleMap := make(map[string]bool)
	var sarifRules []sarifRule

	for _, f := range result.Findings {
		if ruleMap[f.RuleID] {
			continue
		}
		ruleMap[f.RuleID] = true
		sarifRules = append(sarifRules, sarifRule{
			ID:               f.RuleID,
			ShortDescription: sarifMessage{Text: f.Description},
			DefaultConfig: sarifRuleConfig{
				Level: severityToSARIF(f.Severity),
			},
		})
	}

	var results []sarifResult
	for _, f := range result.Findings {
		r := sarifResult{
			RuleID:  f.RuleID,
			Level:   severityToSARIF(f.Severity),
			Message: sarifMessage{Text: f.Description},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.FilePath,
						},
						Region: sarifRegion{
							StartLine: f.LineNumber,
						},
					},
				},
			},
		}

		props := make(map[string]any)
		if f.CommitSHA != "" {
			props["commit"] = f.CommitSHA
		}
		if f.Entropy > 0 {
			props["entropy"] = f.Entropy
		}
		if f.HIBPStatus == types.HIBPBreached {
			props["hibp_breached"] = true
			props["breach_count"] = f.BreachCount
		}
		if len(props) > 0 {
			r.Properties = props
		}

		results = append(results, r)
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema: "https://raw.githubusercontent.com/" +
			"oasis-tcs/sarif-spec/main/sarif-2.1/" +
			"schema/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "portia",
						Version: "1.0.0",
						Rules:   sarifRules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func severityToSARIF(sev types.Severity) string {
	switch sev {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	case types.SeverityLow:
		return "note"
	default:
		return "note"
	}
}
