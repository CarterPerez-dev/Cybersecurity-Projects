/*
AngelaMos | 2026
json.go
*/

package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/CarterPerez-dev/docksec/internal/finding"
)

type JSONReporter struct {
	w      io.Writer
	closer func() error
}

type jsonReport struct {
	Version   string        `json:"version"`
	Timestamp string        `json:"timestamp"`
	Summary   jsonSummary   `json:"summary"`
	Findings  []jsonFinding `json:"findings"`
}

type jsonSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
}

type jsonFinding struct {
	ID          string        `json:"id"`
	RuleID      string        `json:"rule_id"`
	Title       string        `json:"title"`
	Description string        `json:"description,omitempty"`
	Severity    string        `json:"severity"`
	Category    string        `json:"category,omitempty"`
	Target      jsonTarget    `json:"target"`
	Location    *jsonLocation `json:"location,omitempty"`
	Remediation string        `json:"remediation,omitempty"`
	References  []string      `json:"references,omitempty"`
	CISControl  *jsonCIS      `json:"cis_control,omitempty"`
	Timestamp   string        `json:"timestamp"`
}

type jsonTarget struct {
	Type string `json:"type"`
	Name string `json:"name"`
	ID   string `json:"id,omitempty"`
}

type jsonLocation struct {
	Path   string `json:"path"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

type jsonCIS struct {
	ID          string `json:"id"`
	Section     string `json:"section,omitempty"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Scored      bool   `json:"scored"`
	Level       int    `json:"level"`
}

func (r *JSONReporter) Report(findings finding.Collection) error {
	defer func() {
		if r.closer != nil {
			_ = r.closer()
		}
	}()

	report := r.buildReport(findings)

	enc := json.NewEncoder(r.w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	return enc.Encode(report)
}

func (r *JSONReporter) buildReport(findings finding.Collection) jsonReport {
	counts := findings.CountBySeverity()
	bySeverity := make(map[string]int)
	for sev, count := range counts {
		bySeverity[sev.String()] = count
	}

	jsonFindings := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		jsonFindings = append(jsonFindings, r.convertFinding(f))
	}

	return jsonReport{
		Version:   "1.0.0",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Summary: jsonSummary{
			Total:      len(findings),
			BySeverity: bySeverity,
		},
		Findings: jsonFindings,
	}
}

func (r *JSONReporter) convertFinding(f *finding.Finding) jsonFinding {
	jf := jsonFinding{
		ID:          f.ID,
		RuleID:      f.RuleID,
		Title:       f.Title,
		Description: f.Description,
		Severity:    f.Severity.String(),
		Category:    f.Category,
		Target: jsonTarget{
			Type: string(f.Target.Type),
			Name: f.Target.Name,
			ID:   f.Target.ID,
		},
		Remediation: f.Remediation,
		References:  f.References,
		Timestamp:   f.Timestamp.UTC().Format(time.RFC3339),
	}

	if f.Location != nil {
		jf.Location = &jsonLocation{
			Path:   f.Location.Path,
			Line:   f.Location.Line,
			Column: f.Location.Column,
		}
	}

	if f.CISControl != nil {
		jf.CISControl = &jsonCIS{
			ID:          f.CISControl.ID,
			Section:     f.CISControl.Section,
			Title:       f.CISControl.Title,
			Description: f.CISControl.Description,
			Scored:      f.CISControl.Scored,
			Level:       f.CISControl.Level,
		}
	}

	return jf
}
