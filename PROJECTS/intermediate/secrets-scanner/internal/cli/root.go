// ©AngelaMos | 2026
// root.go

package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/portia/internal/config"
	"github.com/CarterPerez-dev/portia/internal/ui"
)

var (
	cfgFile    string
	format     string
	verbose    bool
	noColor    bool
	excludes   []string
	maxSize    int64
	enableHIBP bool
)

var rootCmd = &cobra.Command{
	Use:   "portia",
	Short: "Secrets scanner for codebases and git repositories",
	Long: `Portia scans codebases and git history for leaked secrets,
API keys, passwords, tokens, and private keys.`,
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
		rootCmd.Context(), os.Interrupt, syscall.SIGTERM,
	)
	defer cancel()

	rootCmd.SetContext(ctx)
	return rootCmd.ExecuteContext(ctx)
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(
		&cfgFile, "config", "",
		"config file (default .portia.toml)",
	)
	rootCmd.PersistentFlags().StringVarP(
		&format, "format", "f", "",
		"output format: terminal, json, sarif",
	)
	rootCmd.PersistentFlags().BoolVarP(
		&verbose, "verbose", "v", false,
		"verbose output",
	)
	rootCmd.PersistentFlags().BoolVar(
		&noColor, "no-color", false,
		"disable colored output",
	)
	rootCmd.PersistentFlags().StringSliceVarP(
		&excludes, "exclude", "e", nil,
		"paths to exclude (repeatable)",
	)
	rootCmd.PersistentFlags().Int64Var(
		&maxSize, "max-size", 0,
		"max file size in bytes (default 1MB)",
	)
	rootCmd.PersistentFlags().BoolVar(
		&enableHIBP, "hibp", false,
		"enable HIBP breach verification",
	)

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(gitCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(pyprojectCmd)

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

var cfg *config.Config

func initConfig() {
	if noColor {
		color.NoColor = true
	}

	loaded, err := config.Load(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s config error: %s\n",
			ui.Warning, err)
	}
	if loaded != nil {
		cfg = loaded
	} else {
		cfg = &config.Config{}
	}

	if format == "" && cfg.Output.Format != "" {
		format = cfg.Output.Format
	}
	if format == "" {
		format = "terminal"
	}

	if !verbose && cfg.Output.Verbose {
		verbose = true
	}
	if !noColor && cfg.Output.NoColor {
		noColor = true
		color.NoColor = true
	}
	if !enableHIBP && cfg.HIBP.Enabled {
		enableHIBP = true
	}
	if maxSize == 0 && cfg.Scan.MaxFileSize > 0 {
		maxSize = cfg.Scan.MaxFileSize
	}
	if len(excludes) == 0 && len(cfg.Scan.Excludes) > 0 {
		excludes = cfg.Scan.Excludes
	}
}
