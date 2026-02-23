// ©AngelaMos | 2026
// terminal.go

package reporter

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/CarterPerez-dev/portia/internal/ui"
	"github.com/CarterPerez-dev/portia/pkg/types"
)

type Terminal struct{}

type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

func (ew *errWriter) println(args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintln(ew.w, args...)
}

func (t *Terminal) Report(
	w io.Writer, result *types.ScanResult,
) error {
	ew := &errWriter{w: w}

	if len(result.Findings) == 0 {
		ew.printf("\n%s %s\n\n",
			ui.Check,
			ui.Green("No secrets detected"),
		)
		t.printSummary(ew, result)
		return ew.err
	}

	ew.printf("\n%s %s\n\n",
		ui.Warning,
		ui.RedBold(fmt.Sprintf(
			"%d secret(s) detected",
			len(result.Findings),
		)),
	)

	sorted := make([]types.Finding, len(result.Findings))
	copy(sorted, result.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Severity.Rank() < sorted[j].Severity.Rank()
	})

	for i, f := range sorted {
		if i > 0 {
			ew.println()
		}
		t.printFinding(ew, &f)
	}

	t.printSummary(ew, result)
	return ew.err
}

func (t *Terminal) printFinding(
	ew *errWriter, f *types.Finding,
) {
	sevColor := severityColor(f.Severity)

	ew.printf("%s %s - %s\n",
		ui.HiGreen(ui.Diamond),
		sevColor(f.Severity.String()),
		ui.HiWhite(f.Description),
	)

	ew.printf("  %s %s %s\n",
		ui.Green(ui.Arrow), ui.HiBlue("Rule:    "), ui.Cyan(f.RuleID))
	ew.printf("  %s %s %s\n",
		ui.Green(ui.Arrow), ui.HiBlue("File:    "),
		ui.WhiteBold(fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)))
	ew.printf(
		"  %s %s %s\n",
		ui.Green(
			ui.Arrow,
		),
		ui.HiBlue("Secret:  "),
		ui.YellowBold(maskSecret(f.Secret)),
	)

	if f.Entropy > 0 {
		ew.printf("  %s %s %s\n",
			ui.Green(ui.Arrow), ui.HiBlue("Entropy: "),
			ui.HiGreenUnderline(fmt.Sprintf("%.2f bits", f.Entropy)))
	}

	if f.CommitSHA != "" {
		ew.printf("  %s %s %s\n",
			ui.Green(ui.Arrow), ui.HiBlue("Commit:  "),
			ui.Magenta(truncateSHA(f.CommitSHA)))
	}
	if f.Author != "" {
		ew.printf("  %s %s %s\n",
			ui.Green(ui.Arrow), ui.HiBlue("Author:  "), f.Author)
	}

	if f.HIBPStatus == types.HIBPBreached {
		ew.printf("  %s Breached: %s (%d occurrences)\n",
			ui.Warning,
			ui.RedBold("FOUND IN BREACHES"),
			f.BreachCount,
		)
	} else if f.HIBPStatus == types.HIBPClean {
		ew.printf("  %s HIBP:     %s\n",
			ui.Shield, ui.Green("not found in breaches"))
	}

	if f.LineContent != "" {
		ew.printf("  %s %s %s\n",
			ui.Green(ui.Arrow), ui.HiBlue("Context: "),
			ui.RedItalic(truncateLine(f.LineContent, 100)))
	}
}

func (t *Terminal) printSummary(
	ew *errWriter, result *types.ScanResult,
) {
	ew.printf("\n%s\n", ui.HRule(50))
	ew.printf("  %s %s\n",
		ui.HiBlueBold("Scan completed in"),
		ui.GreenItalic(result.Duration.Round(1e6).String()))
	ew.printf("  %s %s\n",
		ui.HiBlueBold("Files:   "),
		ui.HiCyanItalic(fmt.Sprintf("%d", result.TotalFiles)))
	ew.printf("  %s %s\n",
		ui.HiBlueBold("Rules:   "),
		ui.HiCyanItalic(fmt.Sprintf("%d", result.TotalRules)))
	ew.printf("  %s %s\n",
		ui.HiBlueBold("Findings:"),
		findingsColor(len(result.Findings)))

	if result.HIBPChecked > 0 {
		ew.printf("  HIBP:     %d checked, %s breached\n",
			result.HIBPChecked,
			breachColor(result.HIBPBreached))
	}
	ew.printf("%s\n\n", ui.HRule(50))
}

func severityColor(
	sev types.Severity,
) func(a ...interface{}) string {
	switch sev {
	case types.SeverityCritical:
		return ui.RedBold
	case types.SeverityHigh:
		return ui.Red
	case types.SeverityMedium:
		return ui.Yellow
	case types.SeverityLow:
		return ui.Blue
	default:
		return ui.Blue
	}
}

func findingsColor(count int) string {
	s := fmt.Sprintf("%d", count)
	if count > 0 {
		return ui.RedBold(s)
	}
	return ui.Green(s)
}

func breachColor(count int) string {
	s := fmt.Sprintf("%d", count)
	if count > 0 {
		return ui.RedBold(s)
	}
	return ui.Green(s)
}

func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	visible := 4
	if len(secret) > 20 {
		visible = 6
	}
	return secret[:visible] +
		strings.Repeat("*", len(secret)-visible*2) +
		secret[len(secret)-visible:]
}

func truncateSHA(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

func truncateLine(line string, maxLen int) string {
	line = strings.TrimSpace(line)
	if len(line) <= maxLen {
		return line
	}
	return line[:maxLen-3] + "..."
}
