// ©AngelaMos | 2026
// engine.go

package policy

import (
	"fmt"
	"time"

	"github.com/CarterPerez-dev/bomber/internal/graph"
	"github.com/CarterPerez-dev/bomber/pkg/types"
)

func Evaluate(
	p *Policy,
	report *types.VulnReport,
	graphs []*types.DependencyGraph,
) *types.CheckResult {
	result := &types.CheckResult{Passed: true}

	if p.MaxSeverity != "" {
		threshold := types.ParseSeverity(p.MaxSeverity)
		for _, m := range report.Matches {
			if m.Vulnerability.Severity.Rank() > threshold.Rank() {
				v := m.Vulnerability
				result.Violations = append(result.Violations, types.PolicyViolation{
					Rule:    "max_severity",
					Message: fmt.Sprintf("%s has severity %s (max allowed: %s)", v.ID, v.Severity, p.MaxSeverity),
					Package: m.Package,
					Vuln:    &v,
				})
				result.Passed = false
			}
		}
	}

	if p.MaxAgeDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -p.MaxAgeDays)
		for _, m := range report.Matches {
			if !m.Vulnerability.Published.IsZero() && m.Vulnerability.Published.Before(cutoff) {
				v := m.Vulnerability
				result.Violations = append(result.Violations, types.PolicyViolation{
					Rule: "max_age_days",
					Message: fmt.Sprintf(
						"%s published %s (older than %d days)",
						v.ID, v.Published.Format("2006-01-02"), p.MaxAgeDays,
					),
					Package: m.Package,
					Vuln:    &v,
				})
				result.Passed = false
			}
		}
	}

	if p.MaxDepth > 0 {
		for _, g := range graphs {
			depth := graph.MaxDepth(g)
			if depth > p.MaxDepth {
				result.Violations = append(result.Violations, types.PolicyViolation{
					Rule:    "max_depth",
					Message: fmt.Sprintf("dependency depth %d exceeds maximum %d", depth, p.MaxDepth),
				})
				result.Passed = false
			}
		}
	}

	return result
}
