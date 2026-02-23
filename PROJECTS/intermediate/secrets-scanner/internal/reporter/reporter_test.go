// ©AngelaMos | 2026
// reporter_test.go

package reporter

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/portia/pkg/types"
)

func testResult() *types.ScanResult {
	return &types.ScanResult{
		Findings: []types.Finding{
			{ //nolint:gosec
				RuleID:      "aws-access-key-id",
				Description: "AWS Access Key ID",
				Severity:    types.SeverityCritical,
				Match:       `AKIAIOSFODNN7EXAMPLE`,
				Secret:      "AKIAIOSFODNN7EXAMPLE",
				FilePath:    "src/config.py",
				LineNumber:  42,
				LineContent: `aws_key = "AKIAIOSFODNN7EXAMPLE"`,
				CommitSHA:   "abc123def456",
				Author:      "dev@example.com",
				HIBPStatus:  types.HIBPBreached,
				BreachCount: 1500,
			},
			{ //nolint:gosec
				RuleID:      "generic-password",
				Description: "Password in Assignment",
				Severity:    types.SeverityHigh,
				Match:       `password = "xK9mP2vL5nQ8"`,
				Secret:      "xK9mP2vL5nQ8",
				Entropy:     4.12,
				FilePath:    "config.yaml",
				LineNumber:  10,
				LineContent: `password = "xK9mP2vL5nQ8"`,
				HIBPStatus:  types.HIBPClean,
			},
		},
		TotalFiles:    100,
		TotalRules:    50,
		TotalFindings: 2,
		HIBPChecked:   2,
		HIBPBreached:  1,
		Duration:      1500 * time.Millisecond,
	}
}

func TestNewReporter(t *testing.T) {
	t.Parallel()

	assert.IsType(t, &Terminal{}, New("terminal"))
	assert.IsType(t, &Terminal{}, New(""))
	assert.IsType(t, &JSON{}, New("json"))
	assert.IsType(t, &SARIF{}, New("sarif"))
}

func TestTerminalReportWithFindings(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := &Terminal{}
	err := r.Report(&buf, testResult())
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "2 secret(s) detected")
	assert.Contains(t, output, "aws-access-key-id")
	assert.Contains(t, output, "src/config.py")
	assert.Contains(t, output, "FOUND IN BREACHES")
	assert.Contains(t, output, "not found in breaches")
	assert.Contains(t, output, "4.12")
	assert.Contains(t, output, "abc123de")
}

func TestTerminalReportNoFindings(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := &Terminal{}
	result := &types.ScanResult{
		TotalRules: 50,
		Duration:   500 * time.Millisecond,
	}
	err := r.Report(&buf, result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "No secrets detected")
}

func TestJSONReport(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := &JSON{}
	err := r.Report(&buf, testResult())
	require.NoError(t, err)

	var output jsonOutput
	require.NoError(t, json.Unmarshal(buf.Bytes(), &output))

	assert.Len(t, output.Findings, 2)
	assert.Equal(t, "aws-access-key-id", output.Findings[0].RuleID)
	assert.Equal(t, "CRITICAL", output.Findings[0].Severity)
	assert.NotContains(t, output.Findings[0].Secret, "AKIAIOSFODNN7EXAMPLE")
	assert.Equal(t, 100, output.Summary.TotalFiles)
	assert.Equal(t, 2, output.Summary.TotalFindings)
	assert.Equal(t, 50, output.Summary.TotalRules)
}

func TestJSONReportNoFindings(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := &JSON{}
	result := &types.ScanResult{TotalRules: 50}
	err := r.Report(&buf, result)
	require.NoError(t, err)

	var output jsonOutput
	require.NoError(t, json.Unmarshal(buf.Bytes(), &output))
	assert.Empty(t, output.Findings)
}

func TestSARIFReport(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := &SARIF{}
	err := r.Report(&buf, testResult())
	require.NoError(t, err)

	var log sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))

	assert.Equal(t, "2.1.0", log.Version)
	require.Len(t, log.Runs, 1)

	run := log.Runs[0]
	assert.Equal(t, "portia", run.Tool.Driver.Name)
	assert.Len(t, run.Results, 2)

	assert.Equal(t, "aws-access-key-id", run.Results[0].RuleID)
	assert.Equal(t, "error", run.Results[0].Level)
	assert.Equal(t,
		"src/config.py",
		run.Results[0].Locations[0].PhysicalLocation.
			ArtifactLocation.URI,
	)
	assert.Equal(t,
		42,
		run.Results[0].Locations[0].PhysicalLocation.Region.StartLine,
	)
}

func TestSARIFReportNoFindings(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := &SARIF{}
	result := &types.ScanResult{TotalRules: 50}
	err := r.Report(&buf, result)
	require.NoError(t, err)

	var log sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))
	assert.Empty(t, log.Runs[0].Results)
}

func TestMaskSecret(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input string
		want  string
	}{
		"short secret": {
			input: "abc",
			want:  "***",
		},
		"medium secret": {
			input: "AKIAIOSFODNN7EXA",
			want:  "AKIA********7EXA",
		},
		"long secret": { //nolint:gosec
			input: "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
			want:  "sk_liv********************zdp7dc",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := maskSecret(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTruncateSHA(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "abc123de", truncateSHA("abc123def456"))
	assert.Equal(t, "short", truncateSHA("short"))
}

func TestSeverityToSARIF(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "error", severityToSARIF(types.SeverityCritical))
	assert.Equal(t, "error", severityToSARIF(types.SeverityHigh))
	assert.Equal(t, "warning", severityToSARIF(types.SeverityMedium))
	assert.Equal(t, "note", severityToSARIF(types.SeverityLow))
}
