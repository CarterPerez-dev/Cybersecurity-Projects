/*
AngelaMos | 2026
container_test.go
*/

package analyzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/docksec/internal/finding"
	"github.com/docker/docker/api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadContainerJSON(t *testing.T, filename string) types.ContainerJSON {
	t.Helper()

	path := filepath.Join("..", "..", "tests", "testdata", "containers", filename)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read container JSON file")

	var container types.ContainerJSON
	err = json.Unmarshal(data, &container)
	require.NoError(t, err, "Failed to unmarshal container JSON")

	return container
}

func TestContainerAnalyzer_PrivilegedContainer(t *testing.T) {
	container := loadContainerJSON(t, "privileged-container.json")

	analyzer := &ContainerAnalyzer{}
	findings := analyzer.analyzeContainer(container)

	t.Run("detects privileged mode", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.4" {
				found = true
				assert.Equal(t, finding.SeverityCritical, f.Severity)
				assert.Contains(t, f.Target.Name, "dangerous-container")
				break
			}
		}
		assert.True(t, found, "Should detect privileged: true")
	})

	t.Run("detects critical capabilities", func(t *testing.T) {
		criticalCaps := []string{"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE"}
		for _, capName := range criticalCaps {
			found := false
			for _, f := range findings {
				if containsIgnoreCase(f.Title, capName) {
					found = true
					assert.Equal(t, finding.SeverityCritical, f.Severity,
						"Capability %s should be CRITICAL", capName)
					break
				}
			}
			assert.True(t, found, "Should detect capability %s", capName)
		}
	})

	t.Run("detects high severity capabilities", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if containsIgnoreCase(f.Title, "NET_ADMIN") {
				found = true
				assert.GreaterOrEqual(t, f.Severity, finding.SeverityHigh)
				break
			}
		}
		assert.True(t, found, "Should detect NET_ADMIN capability")
	})

	t.Run("detects docker socket mount", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.31" {
				found = true
				assert.Equal(t, finding.SeverityCritical, f.Severity)
				break
			}
		}
		assert.True(t, found, "Should detect Docker socket mount")
	})

	t.Run("detects sensitive path mounts", func(t *testing.T) {
		sensitivePaths := []string{
			"/etc/passwd",
			"/root/.ssh",
			"/proc",
			"/sys",
			"/",
		}
		foundCount := 0
		for _, path := range sensitivePaths {
			for _, f := range findings {
				if containsIgnoreCase(f.Title, path) &&
					f.RuleID == "CIS-5.5" {
					foundCount++
					assert.GreaterOrEqual(t, f.Severity, finding.SeverityHigh,
						"Mount %s should be HIGH or CRITICAL", path)
					break
				}
			}
		}
		assert.GreaterOrEqual(t, foundCount, 3,
			"Should detect multiple sensitive path mounts")
	})

	t.Run("detects host PID mode", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.15" {
				found = true
				assert.Equal(t, finding.SeverityHigh, f.Severity)
				break
			}
		}
		assert.True(t, found, "Should detect pid: host")
	})

	t.Run("detects host IPC mode", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.16" {
				found = true
				assert.Equal(t, finding.SeverityHigh, f.Severity)
				break
			}
		}
		assert.True(t, found, "Should detect ipc: host")
	})

	t.Run("detects host network mode", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.9" {
				found = true
				assert.Equal(t, finding.SeverityHigh, f.Severity)
				break
			}
		}
		assert.True(t, found, "Should detect network_mode: host")
	})

	t.Run("detects missing memory limit", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.10" {
				found = true
				assert.Equal(t, finding.SeverityMedium, f.Severity)
				break
			}
		}
		assert.True(t, found, "Should detect missing memory limit")
	})

	t.Run("detects missing CPU limit", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.11" {
				found = true
				assert.Equal(t, finding.SeverityMedium, f.Severity)
				break
			}
		}
		assert.True(t, found, "Should detect missing CPU limit")
	})

	t.Run("detects missing PIDs limit", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.28" {
				found = true
				assert.Equal(t, finding.SeverityMedium, f.Severity)
				break
			}
		}
		assert.True(t, found, "Should detect missing PIDs limit")
	})

	t.Run("detects no read-only root filesystem", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.12" {
				found = true
				assert.Equal(t, finding.SeverityMedium, f.Severity)
				break
			}
		}
		assert.True(t, found, "Should detect writable root filesystem")
	})

	t.Run("has many critical findings", func(t *testing.T) {
		criticalCount := 0
		for _, f := range findings {
			if f.Severity == finding.SeverityCritical {
				criticalCount++
			}
		}
		assert.GreaterOrEqual(t, criticalCount, 5,
			"Should have at least 5 CRITICAL findings")
	})

	t.Run("has high severity findings", func(t *testing.T) {
		highCount := 0
		for _, f := range findings {
			if f.Severity >= finding.SeverityHigh {
				highCount++
			}
		}
		assert.GreaterOrEqual(t, highCount, 10,
			"Should have at least 10 HIGH+ severity findings")
	})
}

func TestContainerAnalyzer_SecureContainer(t *testing.T) {
	container := loadContainerJSON(t, "secure-container.json")

	analyzer := &ContainerAnalyzer{}
	findings := analyzer.analyzeContainer(container)

	t.Run("no privileged mode", func(t *testing.T) {
		hasPrivileged := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.4" {
				hasPrivileged = true
			}
		}
		assert.False(t, hasPrivileged, "Should NOT have privileged finding")
	})

	t.Run("no critical capabilities", func(t *testing.T) {
		criticalCapCount := 0
		for _, f := range findings {
			if f.RuleID == "CIS-5.3" &&
				f.Severity == finding.SeverityCritical {
				criticalCapCount++
			}
		}
		assert.Equal(t, 0, criticalCapCount,
			"Should have no CRITICAL capability findings")
	})

	t.Run("no docker socket mount", func(t *testing.T) {
		hasSocket := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.31" {
				hasSocket = true
			}
		}
		assert.False(t, hasSocket, "Should NOT have docker socket mount")
	})

	t.Run("no sensitive path mounts", func(t *testing.T) {
		sensitiveMountCount := 0
		for _, f := range findings {
			if f.RuleID == "CIS-5.5" && f.Severity >= finding.SeverityHigh {
				sensitiveMountCount++
			}
		}
		assert.Equal(t, 0, sensitiveMountCount,
			"Should have no sensitive path mounts")
	})

	t.Run("no host namespace modes", func(t *testing.T) {
		hostNamespaces := []string{"CIS-5.9", "CIS-5.15", "CIS-5.16"}
		for _, ruleID := range hostNamespaces {
			found := false
			for _, f := range findings {
				if f.RuleID == ruleID {
					found = true
				}
			}
			assert.False(t, found, "Should NOT have %s finding", ruleID)
		}
	})

	t.Run("has memory limit", func(t *testing.T) {
		hasNoMemLimit := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.10" {
				hasNoMemLimit = true
			}
		}
		assert.False(t, hasNoMemLimit, "Should have memory limit configured")
	})

	t.Run("has CPU limit", func(t *testing.T) {
		hasNoCPULimit := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.11" {
				hasNoCPULimit = true
			}
		}
		assert.False(t, hasNoCPULimit, "Should have CPU limit configured")
	})

	t.Run("has PIDs limit", func(t *testing.T) {
		hasNoPIDsLimit := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.28" {
				hasNoPIDsLimit = true
			}
		}
		assert.False(t, hasNoPIDsLimit, "Should have PIDs limit configured")
	})

	t.Run("has read-only root filesystem", func(t *testing.T) {
		hasNoReadOnly := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.12" {
				hasNoReadOnly = true
			}
		}
		assert.False(
			t,
			hasNoReadOnly,
			"Should have read-only root filesystem",
		)
	})

	t.Run("no critical findings", func(t *testing.T) {
		assert.False(
			t,
			findings.HasSeverityAtOrAbove(finding.SeverityCritical),
			"Secure container should have no CRITICAL findings",
		)
	})

	t.Run("minimal high findings", func(t *testing.T) {
		highCount := 0
		for _, f := range findings {
			if f.Severity >= finding.SeverityHigh {
				highCount++
			}
		}
		assert.LessOrEqual(t, highCount, 2,
			"Secure container should have minimal HIGH findings")
	})

	t.Run("total findings count", func(t *testing.T) {
		assert.LessOrEqual(t, len(findings), 5,
			"Secure container should have very few findings total")
	})
}

func TestContainerAnalyzer_TargetInfo(t *testing.T) {
	container := loadContainerJSON(t, "privileged-container.json")

	analyzer := &ContainerAnalyzer{}
	findings := analyzer.analyzeContainer(container)

	require.NotEmpty(t, findings, "Should have findings")

	t.Run("target has correct type", func(t *testing.T) {
		for _, f := range findings {
			assert.Equal(t, finding.TargetContainer, f.Target.Type)
		}
	})

	t.Run("target has container name", func(t *testing.T) {
		for _, f := range findings {
			assert.Equal(t, "dangerous-container", f.Target.Name)
			break
		}
	})

	t.Run("target has container ID", func(t *testing.T) {
		for _, f := range findings {
			assert.NotEmpty(t, f.Target.ID)
			assert.Equal(
				t,
				"abc123def456789012345678901234567890123456789012345678901234567890",
				f.Target.ID,
			)
			break
		}
	})
}

func TestContainerAnalyzer_CategoryAndRemediation(t *testing.T) {
	container := loadContainerJSON(t, "privileged-container.json")

	analyzer := &ContainerAnalyzer{}
	findings := analyzer.analyzeContainer(container)

	require.NotEmpty(t, findings, "Should have findings")

	t.Run("findings have category", func(t *testing.T) {
		for _, f := range findings {
			assert.Equal(t, string(CategoryContainerRuntime), f.Category)
		}
	})

	t.Run("findings have remediation", func(t *testing.T) {
		for _, f := range findings {
			assert.NotEmpty(t, f.Remediation,
				"Finding %s should have remediation", f.RuleID)
		}
	})

	t.Run("CIS findings have control info", func(t *testing.T) {
		for _, f := range findings {
			if len(f.RuleID) >= 4 && f.RuleID[:4] == "CIS-" {
				assert.NotNil(t, f.CISControl,
					"CIS finding %s should have CISControl", f.RuleID)
			}
		}
	})
}

func TestContainerAnalyzer_Comparison(t *testing.T) {
	privileged := loadContainerJSON(t, "privileged-container.json")
	secure := loadContainerJSON(t, "secure-container.json")

	analyzer := &ContainerAnalyzer{}

	privilegedFindings := analyzer.analyzeContainer(privileged)
	secureFindings := analyzer.analyzeContainer(secure)

	t.Run("privileged has more findings than secure", func(t *testing.T) {
		assert.Greater(t, len(privilegedFindings), len(secureFindings),
			"Privileged container should have more findings")
	})

	t.Run(
		"privileged has critical findings, secure does not",
		func(t *testing.T) {
			assert.True(
				t,
				privilegedFindings.HasSeverityAtOrAbove(
					finding.SeverityCritical,
				),
				"Privileged should have CRITICAL findings",
			)
			assert.False(
				t,
				secureFindings.HasSeverityAtOrAbove(finding.SeverityCritical),
				"Secure should NOT have CRITICAL findings",
			)
		},
	)

	t.Run("severity distribution differs", func(t *testing.T) {
		privCritical := privilegedFindings.BySeverity(
			finding.SeverityCritical,
		)
		secureCritical := secureFindings.BySeverity(finding.SeverityCritical)

		assert.Greater(t, len(privCritical), len(secureCritical),
			"Privileged should have more CRITICAL findings")
	})
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
