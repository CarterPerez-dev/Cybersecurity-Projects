/*
©AngelaMos | 2026
scan.go

Scan subcommand that runs all persistence scanners

Executes every registered scanner against the target root, filters
findings by minimum severity, tallies results, and renders output
in terminal or JSON format.
*/

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/sentinel/internal/config"
	"github.com/CarterPerez-dev/sentinel/internal/report"
	"github.com/CarterPerez-dev/sentinel/internal/scanner"
	"github.com/CarterPerez-dev/sentinel/internal/ui"
	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func init() {
	rootCmd.AddCommand(scanCmd)
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for persistence mechanisms",
	RunE:  runScan,
}

func runScan(cmd *cobra.Command, _ []string) error {
	minSev := types.ParseSeverity(flagMinSeverity)
	hostname, err := os.Hostname()
	if err != nil {
		hostname = fallbackHostname
	}

	ignoreList, err := config.LoadIgnoreFile(flagIgnoreFile)
	if err != nil {
		return err
	}

	var sp *ui.Spinner
	if !flagJSON {
		sp = ui.NewSpinner("Scanning persistence mechanisms...")
		sp.Start()
	}

	start := time.Now()
	findings := scanner.RunAll(flagRoot)
	duration := time.Since(start)

	if sp != nil {
		sp.Stop()
	}

	findings = ignoreList.Filter(findings)
	filtered := filterBySeverity(findings, minSev)

	result := types.ScanResult{
		Version:    types.Version,
		ScanTime:   start,
		Hostname:   hostname,
		Findings:   filtered,
		Summary:    types.Tally(filtered),
		DurationMs: duration.Milliseconds(),
	}

	if flagJSON {
		return report.PrintJSON(result)
	}

	scannerNames := make([]string, 0, len(scanner.All()))
	for _, s := range scanner.All() {
		scannerNames = append(scannerNames, s.Name())
	}

	fmt.Printf(
		"  %s Scanned %d modules across %s\n\n",
		ui.GreenBold(ui.Check),
		len(scannerNames),
		flagRoot,
	)

	report.PrintTerminal(result)
	return nil
}

func filterBySeverity(
	findings []types.Finding, min types.Severity,
) []types.Finding {
	if min == types.SeverityInfo {
		return findings
	}

	var filtered []types.Finding
	for _, f := range findings {
		if f.Severity >= min {
			filtered = append(filtered, f)
		}
	}
	return filtered
}
