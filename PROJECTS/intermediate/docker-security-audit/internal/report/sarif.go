/*
AngelaMos | 2026
sarif.go
*/

package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/CarterPerez-dev/docksec/internal/config"
	"github.com/CarterPerez-dev/docksec/internal/finding"
)

type SARIFReporter struct {
	w      io.Writer
	closer func() error
}

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription,omitempty"`
	Help             sarifMessage        `json:"help,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
	DefaultConfig    sarifDefaultConfig  `json:"defaultConfiguration"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string                `json:"ruleId"`
	RuleIndex           int                   `json:"ruleIndex"`
	Level               string                `json:"level"`
	Message             sarifMessage          `json:"message"`
	Locations           []sarifLocation       `json:"locations,omitempty"`
	PartialFingerprints map[string]string     `json:"partialFingerprints,omitempty"`
	Properties          sarifResultProperties `json:"properties,omitempty"`
}

type sarifResultProperties struct {
	SecuritySeverity string `json:"security-severity,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	EndTimeUTC          string `json:"endTimeUtc"`
}

func (r *SARIFReporter) Report(findings finding.Collection) error {
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

func (r *SARIFReporter) buildReport(findings finding.Collection) sarifReport {
	rulesMap := make(map[string]int)
	var rules []sarifRule
	var results []sarifResult

	for _, f := range findings {
		if len(results) >= config.SARIFMaxResults {
			break
		}

		ruleIndex, exists := rulesMap[f.RuleID]
		if !exists {
			ruleIndex = len(rules)
			rulesMap[f.RuleID] = ruleIndex
			rules = append(rules, r.buildRule(f))
		}

		results = append(results, r.buildResult(f, ruleIndex))
	}

	return sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "docksec",
						Version:        "1.0.0",
						InformationURI: "https://github.com/angelamos/docksec",
						Rules:          rules,
					},
				},
				Results: results,
				Invocations: []sarifInvocation{
					{
						ExecutionSuccessful: true,
						EndTimeUTC: time.Now().
							UTC().
							Format(time.RFC3339),
					},
				},
			},
		},
	}
}

func (r *SARIFReporter) buildRule(f *finding.Finding) sarifRule {
	rule := sarifRule{
		ID:   f.RuleID,
		Name: f.RuleID,
		ShortDescription: sarifMessage{
			Text: f.Title,
		},
		DefaultConfig: sarifDefaultConfig{
			Level: r.severityToLevel(f.Severity),
		},
		Properties: sarifRuleProperties{
			SecuritySeverity: r.severityToScore(f.Severity),
			Tags:             []string{"security", "docker"},
		},
	}

	if f.Description != "" {
		rule.FullDescription = sarifMessage{Text: f.Description}
	}

	if f.Remediation != "" {
		rule.Help = sarifMessage{Text: f.Remediation}
	}

	if len(f.References) > 0 {
		rule.HelpURI = f.References[0]
	}

	if f.CISControl != nil {
		rule.Properties.Tags = append(
			rule.Properties.Tags,
			"CIS",
			"CIS-"+f.CISControl.ID,
		)
	}

	return rule
}

func (r *SARIFReporter) buildResult(
	f *finding.Finding,
	ruleIndex int,
) sarifResult {
	result := sarifResult{
		RuleID:    f.RuleID,
		RuleIndex: ruleIndex,
		Level:     r.severityToLevel(f.Severity),
		Message: sarifMessage{
			Text: r.buildMessage(f),
		},
		PartialFingerprints: map[string]string{
			"primaryLocationLineHash": r.fingerprint(f),
		},
		Properties: sarifResultProperties{
			SecuritySeverity: r.severityToScore(f.Severity),
		},
	}

	uri := r.buildURI(f)
	if uri != "" {
		loc := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{
					URI: uri,
				},
			},
		}

		if f.Location != nil && f.Location.Line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{
				StartLine: f.Location.Line,
			}
			if f.Location.Column > 0 {
				loc.PhysicalLocation.Region.StartColumn = f.Location.Column
			}
		}

		result.Locations = []sarifLocation{loc}
	}

	return result
}

func (r *SARIFReporter) buildMessage(f *finding.Finding) string {
	msg := f.Title
	if f.Description != "" {
		msg += ": " + f.Description
	}
	return msg
}

func (r *SARIFReporter) buildURI(f *finding.Finding) string {
	if f.Location != nil && f.Location.Path != "" {
		return f.Location.Path
	}

	switch f.Target.Type {
	case finding.TargetDockerfile, finding.TargetCompose:
		return f.Target.Name
	case finding.TargetContainer, finding.TargetImage:
		return fmt.Sprintf("docker://%s/%s", f.Target.Type, f.Target.Name)
	case finding.TargetDaemon:
		return "docker://daemon"
	}

	return ""
}

func (r *SARIFReporter) fingerprint(f *finding.Finding) string {
	data := f.RuleID + "|" + string(f.Target.Type) + "|" + f.Target.Name
	if f.Location != nil {
		data += fmt.Sprintf("|%s:%d", f.Location.Path, f.Location.Line)
	}
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

func (r *SARIFReporter) severityToLevel(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	case finding.SeverityLow, finding.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

func (r *SARIFReporter) severityToScore(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical:
		return "9.0"
	case finding.SeverityHigh:
		return "7.0"
	case finding.SeverityMedium:
		return "5.0"
	case finding.SeverityLow:
		return "3.0"
	case finding.SeverityInfo:
		return "1.0"
	default:
		return "0.0"
	}
}
