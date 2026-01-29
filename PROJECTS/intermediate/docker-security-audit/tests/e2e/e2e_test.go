/*
AngelaMos | 2026
e2e_test.go
*/

package e2e_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/docksec/internal/analyzer"
	"github.com/CarterPerez-dev/docksec/internal/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2E_DockerfileAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx := context.Background()

	t.Run("analyze bad-secrets.Dockerfile end-to-end", func(t *testing.T) {
		path := filepath.Join("..", "testdata", "dockerfiles", "bad-secrets.Dockerfile")

		require.FileExists(t, path, "Test file should exist")

		a := analyzer.NewDockerfileAnalyzer(path)

		findings, err := a.Analyze(ctx)
		require.NoError(t, err, "Analyze should not return error")
		require.NotEmpty(t, findings, "Should have findings")

		assert.True(t, findings.HasSeverityAtOrAbove(finding.SeverityHigh),
			"Should detect HIGH+ severity issues")

		counts := findings.CountBySeverity()
		t.Logf("Findings by severity: %+v", counts)
		t.Logf("Total findings: %d", findings.Total())

		assert.Greater(t, counts[finding.SeverityHigh], 0,
			"Should have HIGH severity findings")
	})

	t.Run("analyze good-security.Dockerfile end-to-end", func(t *testing.T) {
		path := filepath.Join("..", "testdata", "dockerfiles", "good-security.Dockerfile")

		require.FileExists(t, path, "Test file should exist")

		a := analyzer.NewDockerfileAnalyzer(path)

		findings, err := a.Analyze(ctx)
		require.NoError(t, err, "Analyze should not return error")

		assert.False(t, findings.HasSeverityAtOrAbove(finding.SeverityHigh),
			"Good Dockerfile should have no HIGH+ findings")

		counts := findings.CountBySeverity()
		t.Logf("Findings by severity: %+v", counts)
		t.Logf("Total findings: %d", findings.Total())
	})
}

func TestE2E_ComposeAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx := context.Background()

	t.Run("analyze bad-docker-socket.yml end-to-end", func(t *testing.T) {
		path := filepath.Join("..", "testdata", "compose", "bad-docker-socket.yml")

		require.FileExists(t, path, "Test file should exist")

		a := analyzer.NewComposeAnalyzer(path)

		findings, err := a.Analyze(ctx)
		require.NoError(t, err, "Analyze should not return error")
		require.NotEmpty(t, findings, "Should have findings")

		assert.True(t, findings.HasSeverityAtOrAbove(finding.SeverityCritical),
			"Should detect CRITICAL issues")

		counts := findings.CountBySeverity()
		t.Logf("Findings by severity: %+v", counts)
		t.Logf("Total findings: %d", findings.Total())

		assert.Greater(t, counts[finding.SeverityCritical], 0,
			"Should have CRITICAL findings for Docker socket")
	})

	t.Run("analyze good-production.yml end-to-end", func(t *testing.T) {
		path := filepath.Join("..", "testdata", "compose", "good-production.yml")

		require.FileExists(t, path, "Test file should exist")

		a := analyzer.NewComposeAnalyzer(path)

		findings, err := a.Analyze(ctx)
		require.NoError(t, err, "Analyze should not return error")

		assert.False(t, findings.HasSeverityAtOrAbove(finding.SeverityCritical),
			"Production compose should have no CRITICAL findings")

		counts := findings.CountBySeverity()
		t.Logf("Findings by severity: %+v", counts)
		t.Logf("Total findings: %d", findings.Total())
	})
}

func TestE2E_MultipleFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx := context.Background()

	files := []struct {
		path       string
		analyzer   func(string) analyzer.Analyzer
		wantIssues bool
	}{
		{
			path:       filepath.Join("..", "testdata", "dockerfiles", "bad-secrets.Dockerfile"),
			analyzer:   func(p string) analyzer.Analyzer { return analyzer.NewDockerfileAnalyzer(p) },
			wantIssues: true,
		},
		{
			path:       filepath.Join("..", "testdata", "dockerfiles", "good-minimal.Dockerfile"),
			analyzer:   func(p string) analyzer.Analyzer { return analyzer.NewDockerfileAnalyzer(p) },
			wantIssues: false,
		},
		{
			path:       filepath.Join("..", "testdata", "compose", "bad-privileged.yml"),
			analyzer:   func(p string) analyzer.Analyzer { return analyzer.NewComposeAnalyzer(p) },
			wantIssues: true,
		},
		{
			path:       filepath.Join("..", "testdata", "compose", "good-production.yml"),
			analyzer:   func(p string) analyzer.Analyzer { return analyzer.NewComposeAnalyzer(p) },
			wantIssues: false,
		},
	}

	t.Run("analyze multiple files in sequence", func(t *testing.T) {
		var allFindings finding.Collection

		for _, f := range files {
			require.FileExists(t, f.path, "File should exist: %s", f.path)

			a := f.analyzer(f.path)
			findings, err := a.Analyze(ctx)
			require.NoError(t, err, "Analyze should not error for %s", f.path)

			if f.wantIssues {
				assert.NotEmpty(t, findings, "File %s should have findings", f.path)
			}

			allFindings = append(allFindings, findings...)
			t.Logf("%s: %d findings", f.path, len(findings))
		}

		t.Logf("Total findings across all files: %d", allFindings.Total())
		assert.NotEmpty(t, allFindings, "Should have findings across all files")

		counts := allFindings.CountBySeverity()
		t.Logf("Overall severity distribution: %+v", counts)
	})
}

func TestE2E_FindingProperties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx := context.Background()
	path := filepath.Join("..", "testdata", "compose", "bad-caps.yml")

	a := analyzer.NewComposeAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	t.Run("findings have required fields", func(t *testing.T) {
		for _, f := range findings {
			assert.NotEmpty(t, f.ID, "Finding should have ID")
			assert.NotEmpty(t, f.RuleID, "Finding should have RuleID")
			assert.NotEmpty(t, f.Title, "Finding should have Title")
			assert.NotEmpty(t, f.Description, "Finding should have Description")
			assert.NotEmpty(t, f.Category, "Finding should have Category")
			assert.NotEmpty(t, f.Remediation, "Finding should have Remediation")
			assert.NotZero(t, f.Severity, "Finding should have Severity")
			assert.NotEmpty(t, f.Target.Type, "Finding should have Target.Type")
			assert.NotEmpty(t, f.Target.Name, "Finding should have Target.Name")
		}
	})

	t.Run("findings have location info", func(t *testing.T) {
		hasLocation := false
		for _, f := range findings {
			if f.Location != nil {
				hasLocation = true
				assert.NotEmpty(t, f.Location.Path, "Location should have Path")
				assert.Greater(t, f.Location.Line, 0, "Location should have Line > 0")
				break
			}
		}
		assert.True(t, hasLocation, "At least one finding should have location info")
	})

	t.Run("CIS findings have CIS control info", func(t *testing.T) {
		hasCIS := false
		for _, f := range findings {
			if len(f.RuleID) >= 4 && f.RuleID[:4] == "CIS-" {
				hasCIS = true
				if f.CISControl != nil {
					assert.NotEmpty(t, f.CISControl.ID, "CISControl should have ID")
					assert.NotEmpty(t, f.CISControl.Title, "CISControl should have Title")
				}
				break
			}
		}
		assert.True(t, hasCIS, "Should have at least one CIS finding")
	})
}

func TestE2E_SeverityFiltering(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx := context.Background()
	path := filepath.Join("..", "testdata", "compose", "bad-docker-socket.yml")

	a := analyzer.NewComposeAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	t.Run("filter by severity", func(t *testing.T) {
		critical := findings.BySeverity(finding.SeverityCritical)
		high := findings.BySeverity(finding.SeverityHigh)
		medium := findings.BySeverity(finding.SeverityMedium)

		t.Logf("CRITICAL: %d, HIGH: %d, MEDIUM: %d", len(critical), len(high), len(medium))

		assert.NotEmpty(t, critical, "Should have CRITICAL findings")

		for _, f := range critical {
			assert.Equal(t, finding.SeverityCritical, f.Severity)
		}
	})

	t.Run("filter at or above severity", func(t *testing.T) {
		highAndAbove := findings.AtOrAbove(finding.SeverityHigh)
		mediumAndAbove := findings.AtOrAbove(finding.SeverityMedium)

		assert.NotEmpty(t, highAndAbove, "Should have HIGH+ findings")
		assert.GreaterOrEqual(t, len(mediumAndAbove), len(highAndAbove),
			"MEDIUM+ should include HIGH+ findings")

		for _, f := range highAndAbove {
			assert.GreaterOrEqual(t, f.Severity, finding.SeverityHigh)
		}
	})
}

func TestE2E_FileNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx := context.Background()

	t.Run("nonexistent Dockerfile", func(t *testing.T) {
		path := filepath.Join("..", "testdata", "dockerfiles", "does-not-exist.Dockerfile")

		a := analyzer.NewDockerfileAnalyzer(path)
		_, err := a.Analyze(ctx)

		assert.Error(t, err, "Should return error for missing file")
		assert.True(t, os.IsNotExist(err), "Error should be file not found")
	})

	t.Run("nonexistent compose file", func(t *testing.T) {
		path := filepath.Join("..", "testdata", "compose", "does-not-exist.yml")

		a := analyzer.NewComposeAnalyzer(path)
		_, err := a.Analyze(ctx)

		assert.Error(t, err, "Should return error for missing file")
	})
}
