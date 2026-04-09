// ©AngelaMos | 2026
// root.go

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/bomber/internal/config"
	"github.com/CarterPerez-dev/bomber/internal/ui"
)

var (
	formatFlag string
	verbose    bool
	noColor    bool
	noCache    bool
)

var rootCmd = &cobra.Command{
	Use:     "bomber",
	Short:   "SBOM generator & vulnerability matcher",
	Version: config.ToolVersion,
	Long: `Bomber scans project directories for dependencies, generates SBOM
documents in SPDX 2.3 and CycloneDX 1.5 formats, and cross-references
packages against vulnerability databases.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s %s\n",
			ui.Cross, ui.Red(err.Error()))
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGTERM,
	)
	defer cancel()

	return rootCmd.ExecuteContext(ctx)
}

func init() {
	cobra.OnInitialize(initGlobals)

	rootCmd.PersistentFlags().StringVarP(
		&formatFlag, "format", "f", "terminal",
		"output format: terminal, json",
	)
	rootCmd.PersistentFlags().BoolVarP(
		&verbose, "verbose", "v", false,
		"verbose output",
	)
	rootCmd.PersistentFlags().BoolVar(
		&noColor, "no-color", false,
		"disable colored output",
	)
	rootCmd.PersistentFlags().BoolVar(
		&noCache, "no-cache", false,
		"disable vulnerability cache",
	)

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(vulnCmd)
	rootCmd.AddCommand(checkCmd)

	defaultHelp := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(
		func(cmd *cobra.Command, args []string) {
			if cmd.Root() == cmd {
				ui.PrintBannerWithArt()
			} else {
				ui.PrintBanner()
			}
			defaultHelp(cmd, args)
		},
	)
}

func initGlobals() {
	if noColor {
		color.NoColor = true
	}
}
