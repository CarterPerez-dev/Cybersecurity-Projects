/*
AngelaMos | 2026
dockerfile_test.go
*/

package integration_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/docksec/internal/analyzer"
	"github.com/CarterPerez-dev/docksec/internal/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDockerfileAnalyzer_BadSecrets(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(
		"..",
		"testdata",
		"dockerfiles",
		"bad-secrets.Dockerfile",
	)

	a := analyzer.NewDockerfileAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

	t.Run("detects hardcoded secrets", func(t *testing.T) {
		assert.True(t, findings.HasSeverityAtOrAbove(finding.SeverityHigh),
			"Should detect HIGH or CRITICAL severity secrets")

		secretTypes := []string{
			"AWS",
			"github",
			"database",
			"stripe",
			"openai",
		}
		for _, secretType := range secretTypes {
			hasSecret := false
			for _, f := range findings {
				if containsIgnoreCase(f.Title, secretType) ||
					containsIgnoreCase(f.Description, secretType) {
					hasSecret = true
					break
				}
			}
			assert.True(t, hasSecret, "Should detect %s secrets", secretType)
		}
	})

	t.Run("detects sensitive environment variable names", func(t *testing.T) {
		sensitiveVars := false
		for _, f := range findings {
			if containsIgnoreCase(f.Title, "PASSWORD") ||
				containsIgnoreCase(f.Title, "API_KEY") ||
				containsIgnoreCase(f.Title, "SECRET") {
				sensitiveVars = true
				break
			}
		}
		assert.True(
			t,
			sensitiveVars,
			"Should detect sensitive env variable names",
		)
	})

	t.Run("has CIS 4.10 finding", func(t *testing.T) {
		hasCIS410 := false
		for _, f := range findings {
			if f.RuleID == "CIS-4.10" {
				hasCIS410 = true
				break
			}
		}
		assert.True(t, hasCIS410, "Should have CIS-4.10 finding for secrets")
	})
}

func TestDockerfileAnalyzer_BadRootUser(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(
		"..",
		"testdata",
		"dockerfiles",
		"bad-root-user.Dockerfile",
	)

	a := analyzer.NewDockerfileAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

	t.Run("detects missing USER instruction", func(t *testing.T) {
		hasNoUser := false
		for _, f := range findings {
			if f.RuleID == "CIS-4.1" {
				hasNoUser = true
				assert.Equal(t, finding.SeverityMedium, f.Severity)
				break
			}
		}
		assert.True(t, hasNoUser, "Should detect missing USER instruction")
	})

	t.Run("detects missing HEALTHCHECK", func(t *testing.T) {
		hasNoHealthcheck := false
		for _, f := range findings {
			if f.RuleID == "CIS-4.6" {
				hasNoHealthcheck = true
				break
			}
		}
		assert.True(t, hasNoHealthcheck, "Should detect missing HEALTHCHECK")
	})
}

func TestDockerfileAnalyzer_BadPrivileged(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(
		"..",
		"testdata",
		"dockerfiles",
		"bad-privileged.Dockerfile",
	)

	a := analyzer.NewDockerfileAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

	t.Run("detects latest tag", func(t *testing.T) {
		hasLatestTag := false
		for _, f := range findings {
			if f.RuleID == "DS-LATEST-TAG" {
				hasLatestTag = true
				assert.Equal(t, finding.SeverityMedium, f.Severity)
				break
			}
		}
		assert.True(t, hasLatestTag, "Should detect :latest tag usage")
	})

	t.Run("detects missing USER", func(t *testing.T) {
		hasNoUser := false
		for _, f := range findings {
			if f.RuleID == "CIS-4.1" {
				hasNoUser = true
				break
			}
		}
		assert.True(t, hasNoUser, "Should detect missing USER instruction")
	})
}

func TestDockerfileAnalyzer_BadAddCommand(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(
		"..",
		"testdata",
		"dockerfiles",
		"bad-add-command.Dockerfile",
	)

	a := analyzer.NewDockerfileAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

	t.Run("detects ADD instead of COPY", func(t *testing.T) {
		hasAddIssue := false
		for _, f := range findings {
			if f.RuleID == "CIS-4.9" || f.RuleID == "DS-ADD-URL" {
				hasAddIssue = true
				break
			}
		}
		assert.True(t, hasAddIssue, "Should detect ADD usage issues")
	})

	t.Run("detects ADD with URL", func(t *testing.T) {
		hasAddURL := false
		for _, f := range findings {
			if f.RuleID == "DS-ADD-URL" {
				hasAddURL = true
				assert.Equal(t, finding.SeverityMedium, f.Severity)
				break
			}
		}
		assert.True(t, hasAddURL, "Should detect ADD with URL")
	})
}

func TestDockerfileAnalyzer_GoodMinimal(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(
		"..",
		"testdata",
		"dockerfiles",
		"good-minimal.Dockerfile",
	)

	a := analyzer.NewDockerfileAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

	t.Run("has no critical findings", func(t *testing.T) {
		assert.False(
			t,
			findings.HasSeverityAtOrAbove(finding.SeverityCritical),
			"Good Dockerfile should have no CRITICAL findings",
		)
	})

	t.Run("has no high severity findings", func(t *testing.T) {
		assert.False(t, findings.HasSeverityAtOrAbove(finding.SeverityHigh),
			"Good Dockerfile should have no HIGH findings")
	})

	t.Run("has USER instruction", func(t *testing.T) {
		hasNoUserFinding := false
		for _, f := range findings {
			if f.RuleID == "CIS-4.1" {
				hasNoUserFinding = true
			}
		}
		assert.False(
			t,
			hasNoUserFinding,
			"Should NOT have missing USER finding",
		)
	})

	t.Run("has HEALTHCHECK", func(t *testing.T) {
		hasNoHealthcheck := false
		for _, f := range findings {
			if f.RuleID == "CIS-4.6" {
				hasNoHealthcheck = true
			}
		}
		assert.False(
			t,
			hasNoHealthcheck,
			"Should NOT have missing HEALTHCHECK finding",
		)
	})
}

func TestDockerfileAnalyzer_GoodSecurity(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(
		"..",
		"testdata",
		"dockerfiles",
		"good-security.Dockerfile",
	)

	a := analyzer.NewDockerfileAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

	t.Run("has minimal findings", func(t *testing.T) {
		assert.LessOrEqual(t, len(findings), 2,
			"Best-practice Dockerfile should have very few findings")
	})

	t.Run("no critical or high findings", func(t *testing.T) {
		assert.False(
			t,
			findings.HasSeverityAtOrAbove(finding.SeverityHigh),
			"Best-practice Dockerfile should have no HIGH or CRITICAL findings",
		)
	})
}

func TestDockerfileAnalyzer_AllFiles(t *testing.T) {
	testCases := []struct {
		name             string
		file             string
		wantCritical     bool
		wantHigh         bool
		minFindings      int
		specificFindings []string
	}{
		{
			name:         "bad-secrets.Dockerfile",
			file:         "bad-secrets.Dockerfile",
			wantCritical: false,
			wantHigh:     true,
			minFindings:  5,
			specificFindings: []string{
				"CIS-4.10",
				"CIS-4.1",
			},
		},
		{
			name:         "bad-root-user.Dockerfile",
			file:         "bad-root-user.Dockerfile",
			wantCritical: false,
			wantHigh:     false,
			minFindings:  2,
			specificFindings: []string{
				"CIS-4.1",
				"CIS-4.6",
			},
		},
		{
			name:         "bad-privileged.Dockerfile",
			file:         "bad-privileged.Dockerfile",
			wantCritical: false,
			wantHigh:     false,
			minFindings:  1,
			specificFindings: []string{
				"DS-LATEST-TAG",
			},
		},
		{
			name:         "good-minimal.Dockerfile",
			file:         "good-minimal.Dockerfile",
			wantCritical: false,
			wantHigh:     false,
			minFindings:  0,
		},
		{
			name:         "good-security.Dockerfile",
			file:         "good-security.Dockerfile",
			wantCritical: false,
			wantHigh:     false,
			minFindings:  0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(
				"..",
				"testdata",
				"dockerfiles",
				tc.file,
			)

			a := analyzer.NewDockerfileAnalyzer(path)
			findings, err := a.Analyze(ctx)
			require.NoError(t, err, "Analyze should not return error")

			if tc.wantCritical {
				assert.True(
					t,
					findings.HasSeverityAtOrAbove(finding.SeverityCritical),
					"Should have CRITICAL findings",
				)
			}

			if tc.wantHigh {
				assert.True(
					t,
					findings.HasSeverityAtOrAbove(finding.SeverityHigh),
					"Should have HIGH findings",
				)
			}

			assert.GreaterOrEqual(t, len(findings), tc.minFindings,
				"Should have at least %d findings", tc.minFindings)

			for _, ruleID := range tc.specificFindings {
				found := false
				for _, f := range findings {
					if f.RuleID == ruleID {
						found = true
						break
					}
				}
				assert.True(
					t,
					found,
					"Should have finding with RuleID %s",
					ruleID,
				)
			}
		})
	}
}

func containsIgnoreCase(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	return contains(s, substr)
}

func toLower(s string) string {
	result := make([]rune, len(s))
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			result[i] = r + 32
		} else {
			result[i] = r
		}
	}
	return string(result)
}

func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
