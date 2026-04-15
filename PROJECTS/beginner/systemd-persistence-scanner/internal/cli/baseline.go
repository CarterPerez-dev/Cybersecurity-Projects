/*
©AngelaMos | 2026
baseline.go

Baseline subcommand for save and diff operations

The save subcommand runs a full scan and saves findings as a JSON
baseline snapshot. The diff subcommand runs a fresh scan and shows
only findings that are new since the baseline was taken.
*/

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/sentinel/internal/baseline"
	"github.com/CarterPerez-dev/sentinel/internal/config"
	"github.com/CarterPerez-dev/sentinel/internal/report"
	"github.com/CarterPerez-dev/sentinel/internal/scanner"
	"github.com/CarterPerez-dev/sentinel/internal/ui"
	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

var flagBaselinePath string

func init() {
	baselineCmd.PersistentFlags().StringVar(
		&flagBaselinePath, "file", "sentinel-baseline.json",
		"path to baseline snapshot file",
	)
	baselineCmd.AddCommand(baselineSaveCmd)
	baselineCmd.AddCommand(baselineDiffCmd)
	rootCmd.AddCommand(baselineCmd)
}

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage baseline snapshots",
}

var baselineSaveCmd = &cobra.Command{
	Use:   "save",
	Short: "Save current state as baseline",
	RunE:  runBaselineSave,
}

var baselineDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show changes since baseline",
	RunE:  runBaselineDiff,
}

func runBaselineSave(_ *cobra.Command, _ []string) error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = fallbackHostname
	}

	var sp *ui.Spinner
	if !flagJSON {
		sp = ui.NewSpinner("Scanning for baseline...")
		sp.Start()
	}

	findings := scanner.RunAll(flagRoot)

	if sp != nil {
		sp.Stop()
	}

	if err := baseline.Save(
		flagBaselinePath, findings, hostname,
	); err != nil {
		return err
	}

	fmt.Printf(
		"  %s Baseline saved to %s (%d findings)\n\n",
		ui.GreenBold(ui.Check),
		ui.Cyan(flagBaselinePath),
		len(findings),
	)
	return nil
}

func runBaselineDiff(_ *cobra.Command, _ []string) error {
	snap, err := baseline.Load(flagBaselinePath)
	if err != nil {
		return fmt.Errorf(
			"load baseline %s: %w",
			flagBaselinePath, err,
		)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = fallbackHostname
	}
	minSev := types.ParseSeverity(flagMinSeverity)

	var sp *ui.Spinner
	if !flagJSON {
		sp = ui.NewSpinner("Scanning and comparing to baseline...")
		sp.Start()
	}

	start := time.Now()
	current := scanner.RunAll(flagRoot)
	duration := time.Since(start)

	if sp != nil {
		sp.Stop()
	}

	ignoreList, err := config.LoadIgnoreFile(flagIgnoreFile)
	if err != nil {
		return err
	}

	newFindings := baseline.Diff(snap, current)
	newFindings = ignoreList.Filter(newFindings)
	filtered := filterBySeverity(newFindings, minSev)

	result := types.ScanResult{
		Version:    types.Version,
		ScanTime:   start,
		Hostname:   hostname,
		Findings:   filtered,
		Summary:    types.Tally(filtered),
		DurationMs: duration.Milliseconds(),
	}

	if !flagJSON {
		fmt.Printf(
			"  %s Baseline: %d known %s New: %d findings\n\n",
			ui.CyanBold(ui.Diamond),
			len(snap.Findings),
			ui.Dim("|"),
			len(filtered),
		)
	}

	if flagJSON {
		return report.PrintJSON(result)
	}

	report.PrintTerminal(result)
	return nil
}
