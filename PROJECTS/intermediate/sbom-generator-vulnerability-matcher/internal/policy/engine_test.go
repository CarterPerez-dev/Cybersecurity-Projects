// ©AngelaMos | 2026
// engine_test.go

package policy

import (
	"testing"
	"time"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluatePassesClean(t *testing.T) {
	p := &Policy{MaxSeverity: "high"}
	report := &types.VulnReport{
		Matches: []types.VulnMatch{
			{Vulnerability: types.Vulnerability{Severity: types.SeverityMedium, ID: "CVE-TEST"}},
		},
	}

	result := Evaluate(p, report, nil)
	assert.True(t, result.Passed)
	assert.Empty(t, result.Violations)
}

func TestEvaluateFailsCritical(t *testing.T) {
	p := &Policy{MaxSeverity: "medium"}
	report := &types.VulnReport{
		Matches: []types.VulnMatch{
			{Vulnerability: types.Vulnerability{Severity: types.SeverityCritical, ID: "CVE-2024-0001"}},
		},
	}

	result := Evaluate(p, report, nil)
	assert.False(t, result.Passed)
	require.NotEmpty(t, result.Violations)
	assert.Equal(t, "max_severity", result.Violations[0].Rule)
}

func TestEvaluateMaxDepth(t *testing.T) {
	p := &Policy{MaxDepth: 3}

	root := types.Package{Name: "root", PURL: "pkg:test/root@1.0.0"}
	g := types.NewDependencyGraph(root)
	deep := types.Package{Name: "deep", PURL: "pkg:test/deep@1.0.0", DepthLevel: 5}
	g.AddPackage(deep)

	result := Evaluate(p, &types.VulnReport{}, []*types.DependencyGraph{g})
	assert.False(t, result.Passed)
	require.NotEmpty(t, result.Violations)
	assert.Equal(t, "max_depth", result.Violations[0].Rule)
}

func TestEvaluateMaxDepthPasses(t *testing.T) {
	p := &Policy{MaxDepth: 10}

	root := types.Package{Name: "root", PURL: "pkg:test/root@1.0.0"}
	g := types.NewDependencyGraph(root)
	shallow := types.Package{Name: "shallow", PURL: "pkg:test/shallow@1.0.0", DepthLevel: 2}
	g.AddPackage(shallow)

	result := Evaluate(p, &types.VulnReport{}, []*types.DependencyGraph{g})
	assert.True(t, result.Passed)
}

func TestLoadPolicyYAML(t *testing.T) {
	yml := `
max_severity: medium
max_depth: 5
max_age_days: 365
`
	p, err := ParsePolicy([]byte(yml))
	require.NoError(t, err)
	assert.Equal(t, "medium", p.MaxSeverity)
	assert.Equal(t, 5, p.MaxDepth)
	assert.Equal(t, 365, p.MaxAgeDays)
}

func TestEvaluateMaxAgeFails(t *testing.T) {
	p := &Policy{MaxAgeDays: 90}
	report := &types.VulnReport{
		Matches: []types.VulnMatch{
			{
				Vulnerability: types.Vulnerability{
					ID:        "CVE-2023-0001",
					Published: time.Now().AddDate(0, 0, -180),
				},
			},
		},
	}

	result := Evaluate(p, report, nil)
	assert.False(t, result.Passed)
	require.NotEmpty(t, result.Violations)
	assert.Equal(t, "max_age_days", result.Violations[0].Rule)
}

func TestEvaluateMaxAgePasses(t *testing.T) {
	p := &Policy{MaxAgeDays: 90}
	report := &types.VulnReport{
		Matches: []types.VulnMatch{
			{
				Vulnerability: types.Vulnerability{
					ID:        "CVE-2024-0001",
					Published: time.Now().AddDate(0, 0, -30),
				},
			},
		},
	}

	result := Evaluate(p, report, nil)
	assert.True(t, result.Passed)
	assert.Empty(t, result.Violations)
}

func TestEvaluateMaxAgeSkipsZeroPublished(t *testing.T) {
	p := &Policy{MaxAgeDays: 90}
	report := &types.VulnReport{
		Matches: []types.VulnMatch{
			{
				Vulnerability: types.Vulnerability{
					ID: "CVE-2024-0001",
				},
			},
		},
	}

	result := Evaluate(p, report, nil)
	assert.True(t, result.Passed)
}

func TestEvaluateEmptyPolicy(t *testing.T) {
	p := &Policy{}
	report := &types.VulnReport{
		Matches: []types.VulnMatch{
			{Vulnerability: types.Vulnerability{Severity: types.SeverityCritical}},
		},
	}

	result := Evaluate(p, report, nil)
	assert.True(t, result.Passed)
}
