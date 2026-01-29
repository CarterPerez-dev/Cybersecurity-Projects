/*
AngelaMos | 2026
terminal.go
*/

package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/CarterPerez-dev/docksec/internal/finding"
)

const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorGray    = "\033[90m"
)

type TerminalReporter struct {
	w       io.Writer
	closer  func() error
	colored bool
}

func (r *TerminalReporter) Report(findings finding.Collection) error {
	defer func() {
		if r.closer != nil {
			_ = r.closer()
		}
	}()

	if len(findings) == 0 {
		r.printLine(colorGreen, "No security issues found.")
		return nil
	}

	r.printHeader(findings)
	r.printFindings(findings)
	r.printSummary(findings)

	return nil
}

func (r *TerminalReporter) printHeader(findings finding.Collection) {
	r.printLine(colorBold, "")
	r.printLine(colorBold, "Security Scan Results")
	r.printLine(colorBold, strings.Repeat("=", 60))
	_, _ = fmt.Fprintln(r.w)
}

func (r *TerminalReporter) printFindings(findings finding.Collection) {
	grouped := r.groupByCategory(findings)

	categories := make([]string, 0, len(grouped))
	for cat := range grouped {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	for _, category := range categories {
		catFindings := grouped[category]
		r.printCategory(category, catFindings)
	}
}

func (r *TerminalReporter) printCategory(
	category string,
	findings finding.Collection,
) {
	r.printLine(colorBold+colorCyan, "[ "+category+" ]")
	_, _ = fmt.Fprintln(r.w)

	sorted := r.sortBySeverity(findings)

	for _, f := range sorted {
		r.printFinding(f)
	}

	_, _ = fmt.Fprintln(r.w)
}

func (r *TerminalReporter) printFinding(f *finding.Finding) {
	sevColor := r.severityColor(f.Severity)
	sevLabel := fmt.Sprintf("[%-8s]", f.Severity.String())

	r.print(sevColor, sevLabel)
	r.print(colorWhite, " ")
	r.print(colorBold, f.Title)
	_, _ = fmt.Fprintln(r.w)

	r.print(colorGray, "           ")
	r.print(colorGray, "Target: ")
	r.printLine(colorWhite, f.Target.String())

	if f.Location != nil {
		r.print(colorGray, "           ")
		r.print(colorGray, "Location: ")
		r.printLine(colorWhite, f.Location.String())
	}

	if f.Description != "" {
		r.print(colorGray, "           ")
		wrapped := r.wrapText(f.Description, 60)
		for i, line := range wrapped {
			if i > 0 {
				r.print(colorGray, "           ")
			}
			r.printLine(colorGray, line)
		}
	}

	if f.Remediation != "" {
		r.print(colorGray, "           ")
		r.print(colorGreen, "Fix: ")
		wrapped := r.wrapText(f.Remediation, 55)
		for i, line := range wrapped {
			if i > 0 {
				r.print(colorGray, "                ")
			}
			r.printLine(colorWhite, line)
		}
	}

	if f.CISControl != nil {
		r.print(colorGray, "           ")
		r.print(colorBlue, "CIS: ")
		r.printLine(colorWhite, f.CISControl.ID+" - "+f.CISControl.Title)
	}

	_, _ = fmt.Fprintln(r.w)
}

func (r *TerminalReporter) printSummary(findings finding.Collection) {
	counts := findings.CountBySeverity()

	r.printLine(colorBold, strings.Repeat("-", 60))
	r.printLine(colorBold, "Summary")
	_, _ = fmt.Fprintln(r.w)

	r.print(colorWhite, "  Total findings: ")
	r.printLine(colorBold, fmt.Sprintf("%d", len(findings)))
	_, _ = fmt.Fprintln(r.w)

	severities := []finding.Severity{
		finding.SeverityCritical,
		finding.SeverityHigh,
		finding.SeverityMedium,
		finding.SeverityLow,
		finding.SeverityInfo,
	}

	for _, sev := range severities {
		count := counts[sev]
		if count > 0 {
			r.print(colorWhite, "  ")
			r.print(
				r.severityColor(sev),
				fmt.Sprintf("%-10s", sev.String()+":"),
			)
			r.printLine(colorWhite, fmt.Sprintf("%d", count))
		}
	}

	_, _ = fmt.Fprintln(r.w)
}

func (r *TerminalReporter) groupByCategory(
	findings finding.Collection,
) map[string]finding.Collection {
	grouped := make(map[string]finding.Collection)
	for _, f := range findings {
		cat := f.Category
		if cat == "" {
			cat = "General"
		}
		grouped[cat] = append(grouped[cat], f)
	}
	return grouped
}

func (r *TerminalReporter) sortBySeverity(
	findings finding.Collection,
) finding.Collection {
	sorted := make(finding.Collection, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Severity > sorted[j].Severity
	})
	return sorted
}

func (r *TerminalReporter) severityColor(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical:
		return colorMagenta + colorBold
	case finding.SeverityHigh:
		return colorRed
	case finding.SeverityMedium:
		return colorYellow
	case finding.SeverityLow:
		return colorBlue
	case finding.SeverityInfo:
		return colorCyan
	default:
		return colorWhite
	}
}

func (r *TerminalReporter) print(color, text string) {
	if r.colored {
		_, _ = fmt.Fprint(r.w, color, text, colorReset)
	} else {
		_, _ = fmt.Fprint(r.w, text)
	}
}

func (r *TerminalReporter) printLine(color, text string) {
	if r.colored {
		_, _ = fmt.Fprintln(r.w, color, text, colorReset)
	} else {
		_, _ = fmt.Fprintln(r.w, text)
	}
}

func (r *TerminalReporter) wrapText(text string, width int) []string {
	if len(text) <= width {
		return []string{text}
	}

	var lines []string
	words := strings.Fields(text)
	var currentLine strings.Builder

	for _, word := range words {
		if currentLine.Len()+len(word)+1 > width {
			if currentLine.Len() > 0 {
				lines = append(lines, currentLine.String())
				currentLine.Reset()
			}
		}
		if currentLine.Len() > 0 {
			currentLine.WriteString(" ")
		}
		currentLine.WriteString(word)
	}

	if currentLine.Len() > 0 {
		lines = append(lines, currentLine.String())
	}

	return lines
}
