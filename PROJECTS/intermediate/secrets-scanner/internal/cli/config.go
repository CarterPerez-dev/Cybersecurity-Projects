// ©AngelaMos | 2026
// config.go

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/portia/internal/rules"
	"github.com/CarterPerez-dev/portia/internal/ui"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show configuration and rule information",
}

var configRulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List all available detection rules",
	RunE:  runConfigRules,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show active configuration",
	RunE:  runConfigShow,
}

func init() {
	configCmd.AddCommand(configRulesCmd)
	configCmd.AddCommand(configShowCmd)
}

func runConfigRules(_ *cobra.Command, _ []string) error {
	reg := rules.NewRegistry()
	rules.RegisterBuiltins(reg)

	all := reg.All()
	fmt.Fprintf(os.Stdout, "\n%s %s\n\n", //nolint:errcheck
		ui.Shield,
		ui.CyanBold(fmt.Sprintf("%d detection rules", len(all))),
	)

	for _, r := range all {
		sevColor := ui.Cyan
		switch r.Severity.String() {
		case "CRITICAL":
			sevColor = ui.RedBold
		case "HIGH":
			sevColor = ui.Red
		case "MEDIUM":
			sevColor = ui.Yellow
		}

		fmt.Fprintf(os.Stdout, "  %s %-40s %s  %s\n", //nolint:errcheck
			ui.Diamond,
			ui.White(r.ID),
			sevColor(fmt.Sprintf("%-8s", r.Severity)),
			r.Description,
		)
	}

	fmt.Fprintln(os.Stdout) //nolint:errcheck
	return nil
}

func runConfigShow(_ *cobra.Command, _ []string) error {
	fmt.Fprintf(os.Stdout, "\n%s Active Configuration\n\n", //nolint:errcheck
		ui.Arrow)
	fmt.Fprintf( //nolint:errcheck
		os.Stdout,
		"  Format:     %s\n",
		format,
	)
	fmt.Fprintf( //nolint:errcheck
		os.Stdout,
		"  Verbose:    %t\n",
		verbose,
	)
	fmt.Fprintf( //nolint:errcheck
		os.Stdout,
		"  No Color:   %t\n",
		noColor,
	)
	fmt.Fprintf( //nolint:errcheck
		os.Stdout,
		"  HIBP:       %t\n",
		enableHIBP,
	)
	fmt.Fprintf( //nolint:errcheck
		os.Stdout,
		"  Max Size:   %d bytes\n",
		maxSize,
	)
	if len(excludes) > 0 {
		fmt.Fprintf(os.Stdout, "  Excludes:   %v\n", excludes) //nolint:errcheck
	}
	if cfg != nil && len(cfg.Rules.Disable) > 0 {
		fmt.Fprintf(os.Stdout, "  Disabled:   %v\n", //nolint:errcheck
			cfg.Rules.Disable)
	}
	fmt.Fprintln(os.Stdout) //nolint:errcheck
	return nil
}
