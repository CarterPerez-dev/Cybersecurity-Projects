// ©AngelaMos | 2026
// check.go

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/bomber/internal/parser"
	"github.com/CarterPerez-dev/bomber/internal/policy"
	"github.com/CarterPerez-dev/bomber/internal/report"
	"github.com/CarterPerez-dev/bomber/internal/scanner"
	"github.com/CarterPerez-dev/bomber/internal/ui"
)

var policyFile string

var checkCmd = &cobra.Command{
	Use:   "check [path]",
	Short: "Evaluate SBOM against a policy",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runCheck,
}

func init() {
	checkCmd.Flags().StringVarP(
		&policyFile, "policy", "p", "policy.yaml",
		"policy file path",
	)
}

func runCheck(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	pol, err := policy.LoadPolicy(policyFile)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	reg := parser.NewRegistry()
	parser.RegisterAll(reg)

	s := scanner.New(reg)
	result, err := s.Scan(path)
	if err != nil {
		return err
	}

	sp := ui.NewSpinner("Querying vulnerability databases...")
	if formatFlag != "json" {
		sp.Start()
	}

	vulnReport, err := queryVulns(cmd.Context(), result)

	if formatFlag != "json" {
		sp.Stop()
	}
	if err != nil {
		return err
	}

	checkResult := policy.Evaluate(pol, vulnReport, result.Graphs)

	if formatFlag == "json" {
		return report.WriteJSON(os.Stdout, result, vulnReport, checkResult)
	}

	ui.PrintBanner()
	report.PrintScanSummary(os.Stdout, result)
	report.PrintVulnReport(os.Stdout, vulnReport)
	report.PrintCheckResult(os.Stdout, checkResult)

	if !checkResult.Passed {
		os.Exit(1)
	}

	return nil
}
