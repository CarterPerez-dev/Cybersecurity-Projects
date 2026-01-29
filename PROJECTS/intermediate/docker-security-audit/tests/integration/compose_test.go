/*
AngelaMos | 2026
compose_test.go
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

func TestComposeAnalyzer_BadDockerSocket(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(
		"..",
		"testdata",
		"compose",
		"bad-docker-socket.yml",
	)

	a := analyzer.NewComposeAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

	t.Run("detects privileged mode", func(t *testing.T) {
		hasPrivileged := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.4" {
				hasPrivileged = true
				assert.Equal(t, finding.SeverityCritical, f.Severity)
				break
			}
		}
		assert.True(t, hasPrivileged, "Should detect privileged: true")
	})

	t.Run("detects docker socket mount", func(t *testing.T) {
		hasDockerSocket := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.31" {
				hasDockerSocket = true
				assert.Equal(t, finding.SeverityCritical, f.Severity)
				break
			}
		}
		assert.True(t, hasDockerSocket, "Should detect Docker socket mount")
	})

	t.Run("detects dangerous capabilities", func(t *testing.T) {
		dangerousCaps := []string{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"}
		for _, capName := range dangerousCaps {
			found := false
			for _, f := range findings {
				if containsIgnoreCase(f.Title, capName) {
					found = true
					assert.GreaterOrEqual(t, f.Severity, finding.SeverityHigh,
						"Capability %s should be HIGH or CRITICAL", capName)
					break
				}
			}
			assert.True(t, found, "Should detect capability %s", capName)
		}
	})

	t.Run("detects host network mode", func(t *testing.T) {
		hasHostNet := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.9" {
				hasHostNet = true
				assert.Equal(t, finding.SeverityHigh, f.Severity)
				break
			}
		}
		assert.True(t, hasHostNet, "Should detect network_mode: host")
	})

	t.Run("detects hardcoded secrets", func(t *testing.T) {
		hasSecrets := false
		for _, f := range findings {
			if f.RuleID == "CIS-4.10" &&
				containsIgnoreCase(f.Description, "secret") {
				hasSecrets = true
				break
			}
		}
		assert.True(
			t,
			hasSecrets,
			"Should detect hardcoded secrets in environment",
		)
	})

	t.Run("detects sensitive path mounts", func(t *testing.T) {
		sensitivePaths := []string{"/etc/passwd", "/root/.ssh"}
		for _, path := range sensitivePaths {
			found := false
			for _, f := range findings {
				if containsIgnoreCase(f.Title, path) ||
					containsIgnoreCase(f.Description, path) {
					found = true
					break
				}
			}
			assert.True(t, found, "Should detect mount of %s", path)
		}
	})

	t.Run("has critical findings", func(t *testing.T) {
		assert.True(
			t,
			findings.HasSeverityAtOrAbove(finding.SeverityCritical),
			"Should have CRITICAL severity findings",
		)
	})
}

func TestComposeAnalyzer_BadPrivileged(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(
		"..",
		"testdata",
		"compose",
		"bad-privileged.yml",
	)

	a := analyzer.NewComposeAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

	t.Run("detects privileged container", func(t *testing.T) {
		hasPrivileged := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.4" {
				hasPrivileged = true
				break
			}
		}
		assert.True(t, hasPrivileged, "Should detect privileged: true")
	})

	t.Run("detects pid host mode", func(t *testing.T) {
		hasPidHost := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.15" {
				hasPidHost = true
				assert.Equal(t, finding.SeverityHigh, f.Severity)
				break
			}
		}
		assert.True(t, hasPidHost, "Should detect pid: host")
	})

	t.Run("detects ipc host mode", func(t *testing.T) {
		hasIpcHost := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.16" {
				hasIpcHost = true
				assert.Equal(t, finding.SeverityHigh, f.Severity)
				break
			}
		}
		assert.True(t, hasIpcHost, "Should detect ipc: host")
	})

	t.Run("detects sensitive filesystem mounts", func(t *testing.T) {
		hasSensitiveMounts := 0
		for _, f := range findings {
			if f.RuleID == "CIS-5.5" {
				hasSensitiveMounts++
			}
		}
		assert.GreaterOrEqual(t, hasSensitiveMounts, 2,
			"Should detect multiple sensitive filesystem mounts")
	})
}

func TestComposeAnalyzer_BadCaps(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join("..", "testdata", "compose", "bad-caps.yml")

	a := analyzer.NewComposeAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

	t.Run("detects critical capabilities", func(t *testing.T) {
		criticalCaps := []string{
			"SYS_MODULE",
			"SYS_RAWIO",
			"SYS_PTRACE",
			"SYS_ADMIN",
			"MAC_ADMIN",
			"BPF",
		}

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
			assert.True(
				t,
				found,
				"Should detect critical capability %s",
				capName,
			)
		}
	})

	t.Run("detects high severity capabilities", func(t *testing.T) {
		highCaps := []string{"DAC_OVERRIDE", "NET_ADMIN"}

		for _, capName := range highCaps {
			found := false
			for _, f := range findings {
				if containsIgnoreCase(f.Title, capName) {
					found = true
					assert.GreaterOrEqual(t, f.Severity, finding.SeverityHigh,
						"Capability %s should be HIGH or CRITICAL", capName)
					break
				}
			}
			assert.True(t, found, "Should detect capability %s", capName)
		}
	})

	t.Run("has multiple critical findings", func(t *testing.T) {
		criticalCount := 0
		for _, f := range findings {
			if f.Severity == finding.SeverityCritical {
				criticalCount++
			}
		}
		assert.GreaterOrEqual(
			t,
			criticalCount,
			5,
			"Should have at least 5 CRITICAL findings for dangerous capabilities",
		)
	})
}

func TestComposeAnalyzer_BadMounts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join("..", "testdata", "compose", "bad-mounts.yml")

	a := analyzer.NewComposeAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

	t.Run("detects container runtime sockets", func(t *testing.T) {
		hasDockerSocket := false
		hasContainerdSocket := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.31" {
				if containsIgnoreCase(f.Title, "docker.sock") ||
					containsIgnoreCase(f.Description, "docker.sock") {
					hasDockerSocket = true
					assert.Equal(t, finding.SeverityCritical, f.Severity)
				}
			}
			if containsIgnoreCase(f.Title, "containerd") ||
				containsIgnoreCase(f.Description, "containerd") {
				hasContainerdSocket = true
			}
		}
		assert.True(t, hasDockerSocket || hasContainerdSocket,
			"Should detect at least one container runtime socket mount")
	})

	t.Run("detects system config directories", func(t *testing.T) {
		paths := []string{"/etc", "/etc/passwd", "/etc/shadow"}
		for _, path := range paths {
			found := false
			for _, f := range findings {
				if containsIgnoreCase(f.Title, path) {
					found = true
					break
				}
			}
			assert.True(t, found, "Should detect %s mount", path)
		}
	})

	t.Run("detects kubernetes directories", func(t *testing.T) {
		paths := []string{"/etc/kubernetes", "/var/lib/kubelet"}
		for _, path := range paths {
			found := false
			for _, f := range findings {
				if containsIgnoreCase(f.Title, path) {
					found = true
					assert.Equal(t, finding.SeverityCritical, f.Severity)
					break
				}
			}
			assert.True(t, found, "Should detect %s mount", path)
		}
	})

	t.Run("detects device mounts", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if containsIgnoreCase(f.Title, "/dev") {
				found = true
				assert.Equal(t, finding.SeverityCritical, f.Severity)
				break
			}
		}
		assert.True(t, found, "Should detect /dev mount")
	})

	t.Run("detects proc and sys mounts", func(t *testing.T) {
		paths := []string{"/proc", "/sys"}
		for _, path := range paths {
			found := false
			for _, f := range findings {
				if containsIgnoreCase(f.Title, path) {
					found = true
					assert.Equal(t, finding.SeverityCritical, f.Severity)
					break
				}
			}
			assert.True(t, found, "Should detect %s mount", path)
		}
	})

	t.Run("has many critical findings", func(t *testing.T) {
		criticalCount := 0
		for _, f := range findings {
			if f.Severity == finding.SeverityCritical {
				criticalCount++
			}
		}
		assert.GreaterOrEqual(t, criticalCount, 10,
			"Should have many CRITICAL findings for sensitive mounts")
	})
}

func TestComposeAnalyzer_BadSecrets(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(
		"..",
		"testdata",
		"compose",
		"bad-secrets.yml",
	)

	a := analyzer.NewComposeAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

	t.Run("detects hardcoded AWS credentials", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if containsIgnoreCase(f.Title, "AWS") ||
				containsIgnoreCase(f.Description, "AWS") {
				found = true
				assert.GreaterOrEqual(t, f.Severity, finding.SeverityHigh)
				break
			}
		}
		assert.True(t, found, "Should detect AWS credentials")
	})

	t.Run("detects database passwords", func(t *testing.T) {
		dbTypes := []string{
			"DATABASE_URL",
			"MONGODB_URI",
			"POSTGRES_PASSWORD",
		}
		for _, dbType := range dbTypes {
			found := false
			for _, f := range findings {
				if containsIgnoreCase(f.Title, dbType) {
					found = true
					break
				}
			}
			assert.True(t, found, "Should detect %s", dbType)
		}
	})

	t.Run("detects API keys", func(t *testing.T) {
		apis := []string{"STRIPE", "GITHUB", "OPENAI"}
		for _, api := range apis {
			found := false
			for _, f := range findings {
				if containsIgnoreCase(f.Title, api) ||
					containsIgnoreCase(f.Description, api) {
					found = true
					break
				}
			}
			assert.True(t, found, "Should detect %s API key", api)
		}
	})

	t.Run("has many high severity findings", func(t *testing.T) {
		highCount := 0
		for _, f := range findings {
			if f.Severity >= finding.SeverityHigh {
				highCount++
			}
		}
		assert.GreaterOrEqual(t, highCount, 10,
			"Should have many HIGH severity findings for secrets")
	})
}

func TestComposeAnalyzer_BadNoLimits(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(
		"..",
		"testdata",
		"compose",
		"bad-no-limits.yml",
	)

	a := analyzer.NewComposeAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

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

	t.Run("detects missing user", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if f.RuleID == "CIS-4.1" {
				found = true
				break
			}
		}
		assert.True(t, found, "Should detect missing user specification")
	})

	t.Run("detects no read-only filesystem", func(t *testing.T) {
		found := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.12" {
				found = true
				break
			}
		}
		assert.True(t, found, "Should detect missing read_only: true")
	})
}

func TestComposeAnalyzer_GoodProduction(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(
		"..",
		"testdata",
		"compose",
		"good-production.yml",
	)

	a := analyzer.NewComposeAnalyzer(path)
	findings, err := a.Analyze(ctx)
	require.NoError(t, err)

	t.Run("has no critical findings", func(t *testing.T) {
		assert.False(
			t,
			findings.HasSeverityAtOrAbove(finding.SeverityCritical),
			"Production compose should have no CRITICAL findings",
		)
	})

	t.Run("has minimal high findings", func(t *testing.T) {
		highCount := 0
		for _, f := range findings {
			if f.Severity >= finding.SeverityHigh {
				highCount++
			}
		}
		assert.LessOrEqual(t, highCount, 2,
			"Production compose should have minimal HIGH findings")
	})

	t.Run("no privileged containers", func(t *testing.T) {
		hasPrivileged := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.4" {
				hasPrivileged = true
			}
		}
		assert.False(t, hasPrivileged, "Should NOT have privileged finding")
	})

	t.Run("no docker socket mounts", func(t *testing.T) {
		hasSocket := false
		for _, f := range findings {
			if f.RuleID == "CIS-5.31" {
				hasSocket = true
			}
		}
		assert.False(t, hasSocket, "Should NOT have docker socket mount")
	})

	t.Run("no hardcoded secrets", func(t *testing.T) {
		secretsCount := 0
		for _, f := range findings {
			if containsIgnoreCase(f.Title, "secret") &&
				f.Severity >= finding.SeverityHigh {
				secretsCount++
			}
		}
		assert.Equal(t, 0, secretsCount, "Should have no hardcoded secrets")
	})
}

func TestComposeAnalyzer_AllFiles(t *testing.T) {
	testCases := []struct {
		name             string
		file             string
		wantCritical     bool
		wantHigh         bool
		minFindings      int
		specificFindings []string
	}{
		{
			name:         "bad-docker-socket.yml",
			file:         "bad-docker-socket.yml",
			wantCritical: true,
			wantHigh:     true,
			minFindings:  8,
			specificFindings: []string{
				"CIS-5.4",
				"CIS-5.31",
				"CIS-5.9",
			},
		},
		{
			name:         "bad-privileged.yml",
			file:         "bad-privileged.yml",
			wantCritical: true,
			wantHigh:     true,
			minFindings:  5,
			specificFindings: []string{
				"CIS-5.4",
				"CIS-5.15",
				"CIS-5.16",
			},
		},
		{
			name:         "bad-caps.yml",
			file:         "bad-caps.yml",
			wantCritical: true,
			wantHigh:     true,
			minFindings:  6,
			specificFindings: []string{
				"CIS-5.3",
			},
		},
		{
			name:         "bad-secrets.yml",
			file:         "bad-secrets.yml",
			wantCritical: false,
			wantHigh:     true,
			minFindings:  10,
			specificFindings: []string{
				"CIS-4.10",
			},
		},
		{
			name:         "good-production.yml",
			file:         "good-production.yml",
			wantCritical: false,
			wantHigh:     false,
			minFindings:  0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join("..", "testdata", "compose", tc.file)

			a := analyzer.NewComposeAnalyzer(path)
			findings, err := a.Analyze(ctx)
			require.NoError(t, err, "Analyze should not return error")

			if tc.wantCritical {
				assert.True(
					t,
					findings.HasSeverityAtOrAbove(finding.SeverityCritical),
					"Should have CRITICAL findings",
				)
			} else {
				assert.False(t, findings.HasSeverityAtOrAbove(finding.SeverityCritical),
					"Should NOT have CRITICAL findings")
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
