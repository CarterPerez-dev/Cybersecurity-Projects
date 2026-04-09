// ©AngelaMos | 2026
// scan.go

package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/bomber/internal/parser"
	"github.com/CarterPerez-dev/bomber/internal/report"
	"github.com/CarterPerez-dev/bomber/internal/scanner"
	"github.com/CarterPerez-dev/bomber/internal/ui"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a directory for dependencies",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScan,
}

func runScan(_ *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	reg := parser.NewRegistry()
	parser.RegisterAll(reg)

	s := scanner.New(reg)
	result, err := s.Scan(path)
	if err != nil {
		return err
	}

	if formatFlag == "json" {
		return report.WriteJSON(os.Stdout, result, nil, nil)
	}

	ui.PrintBanner()
	report.PrintScanSummary(os.Stdout, result)
	return nil
}
