// ©AngelaMos | 2026
// terminal.go

package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/CarterPerez-dev/bomber/internal/graph"
	"github.com/CarterPerez-dev/bomber/internal/ui"
	"github.com/CarterPerez-dev/bomber/pkg/types"
)

func PrintScanSummary(w io.Writer, result *types.ScanResult) {
	fmt.Fprintf(w, "  %s Scanned %d packages (%d direct",
		ui.Check, result.TotalPkgs, result.DirectPkgs)

	transitive := result.TotalPkgs - result.DirectPkgs
	if transitive > 0 {
		fmt.Fprintf(w, ", %d transitive", transitive)
	}
	fmt.Fprintln(w, ")")

	if len(result.Ecosystems) > 0 {
		names := make([]string, len(result.Ecosystems))
		for i, e := range result.Ecosystems {
			names[i] = e.String()
		}
		fmt.Fprintf(w, "  %s Ecosystems: %s\n", ui.Bullet, strings.Join(names, ", "))
	}

	for _, g := range result.Graphs {
		cycles := graph.DetectCycles(g)
		if len(cycles) > 0 {
			fmt.Fprintf(w, "  %s Circular dependencies detected in %s\n",
				ui.Warning, g.Root.Name)
		}
	}

	fmt.Fprintln(w)
}

func PrintVulnReport(w io.Writer, report *types.VulnReport) {
	if len(report.Matches) == 0 {
		fmt.Fprintf(w, "  %s No vulnerabilities found\n\n", ui.Green(ui.Check))
		return
	}

	bySev := map[types.Severity][]types.VulnMatch{}
	for _, m := range report.Matches {
		bySev[m.Vulnerability.Severity] = append(bySev[m.Vulnerability.Severity], m)
	}

	order := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
	}

	for _, sev := range order {
		matches := bySev[sev]
		if len(matches) == 0 {
			continue
		}

		sort.Slice(matches, func(i, j int) bool {
			return matches[i].Vulnerability.Score > matches[j].Vulnerability.Score
		})

		header := fmt.Sprintf("%s (%d)", sev, len(matches))
		switch sev {
		case types.SeverityCritical:
			fmt.Fprintf(w, "  %s\n", ui.Red(header))
		case types.SeverityHigh:
			fmt.Fprintf(w, "  %s\n", ui.Yellow(header))
		case types.SeverityMedium:
			fmt.Fprintf(w, "  %s\n", ui.Cyan(header))
		default:
			fmt.Fprintf(w, "  %s\n", ui.Dim(header))
		}

		for _, m := range matches {
			v := m.Vulnerability
			fmt.Fprintf(w, "    %s\n", m.Package.PURL)
			fmt.Fprintf(w, "    %s", v.ID)
			if v.Summary != "" {
				summary := v.Summary
				if len(summary) > 60 {
					summary = summary[:57] + "..."
				}
				fmt.Fprintf(w, " %s %s", ui.Arrow, summary)
			}
			if v.Score > 0 {
				fmt.Fprintf(w, " (CVSS %.1f)", v.Score)
			}
			fmt.Fprintln(w)
			if v.FixVersion != "" {
				fmt.Fprintf(w, "    Fix: upgrade to %s\n", v.FixVersion)
			}
			fmt.Fprintln(w)
		}
	}
}

func PrintCheckResult(w io.Writer, result *types.CheckResult) {
	if result.Passed {
		fmt.Fprintf(w, "  %s Policy: %s\n\n", ui.Check, ui.Green("PASS"))
		return
	}

	fmt.Fprintf(w, "  %s Policy: %s\n\n", ui.Cross, ui.Red("FAIL"))
	for _, v := range result.Violations {
		fmt.Fprintf(w, "    %s [%s] %s\n", ui.Cross, v.Rule, v.Message)
	}
	fmt.Fprintln(w)
}
