/*
©AngelaMos | 2026
terminal.go

Color-coded terminal output formatter for scan results

Renders findings grouped by severity with color-coded labels,
file paths, evidence snippets, and MITRE technique IDs. Prints
a summary banner with counts per severity level.
*/

package report

import (
	"fmt"
	"sort"

	"github.com/CarterPerez-dev/sentinel/internal/ui"
	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

var severityColor = map[types.Severity]func(
	a ...any,
) string{
	types.SeverityCritical: ui.HiRedBold,
	types.SeverityHigh:     ui.RedBold,
	types.SeverityMedium:   ui.YellowBold,
	types.SeverityLow:      ui.CyanBold,
	types.SeverityInfo:     ui.Dim,
}

func PrintTerminal(result types.ScanResult) {
	findings := result.Findings
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Severity > findings[j].Severity
	})

	if len(findings) == 0 {
		fmt.Printf(
			"  %s No persistence indicators found.\n\n",
			ui.GreenBold(ui.Check),
		)
		printSummary(result)
		return
	}

	fmt.Printf("  %s\n\n", ui.Dim(ui.HRule(56)))

	for _, f := range findings {
		colorFn := severityColor[f.Severity]
		label := colorFn(
			fmt.Sprintf("[%s]", f.Severity.Label()),
		)
		fmt.Printf("  %s %s\n", label, f.Title)
		fmt.Printf(
			"         %s %s\n",
			ui.Dim("Path:"),
			ui.Cyan(f.Path),
		)
		if f.Evidence != "" {
			fmt.Printf(
				"         %s %s\n",
				ui.Dim("Evidence:"),
				truncateEvidence(f.Evidence),
			)
		}
		fmt.Printf(
			"         %s %s\n\n",
			ui.Dim("MITRE:"),
			ui.Blue(f.MITRE),
		)
	}

	printSummary(result)
}

func printSummary(result types.ScanResult) {
	s := result.Summary
	fmt.Printf("  %s\n", ui.Dim(ui.HRule(56)))
	fmt.Printf(
		"  %s %s %s %s %s %s %s %s %s %s\n",
		ui.Dim("Summary:"),
		ui.HiRedBold(fmt.Sprintf("%d", s.Critical)),
		ui.Dim("critical"),
		ui.RedBold(fmt.Sprintf("%d", s.High)),
		ui.Dim("high"),
		ui.YellowBold(fmt.Sprintf("%d", s.Medium)),
		ui.Dim("medium"),
		ui.CyanBold(fmt.Sprintf("%d", s.Low)),
		ui.Dim("low"),
		ui.Dim(fmt.Sprintf("%d info", s.Info)),
	)
	fmt.Printf(
		"  %s Completed in %dms\n\n",
		ui.Dim(ui.Timer),
		result.DurationMs,
	)
}

const maxEvidenceLen = 100

func truncateEvidence(s string) string {
	if len(s) <= maxEvidenceLen {
		return s
	}
	return s[:maxEvidenceLen] + "..."
}
