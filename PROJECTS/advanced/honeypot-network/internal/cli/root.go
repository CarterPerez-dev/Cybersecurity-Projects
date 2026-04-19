/*
©AngelaMos | 2026
root.go

Cobra root command and CLI entry point for hive

Configures the root command with global persistent flags and
registers all subcommands. Signal handling via NotifyContext
ensures graceful shutdown on SIGINT/SIGTERM.
*/

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/ui"
)

var (
	flagConfig  string
	flagVerbose bool
	flagNoColor bool
)

func Execute() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer cancel()

	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "hive",
		Short: "Multi-service honeypot network",
		Long: `hive deploys a network of realistic honeypots (SSH, HTTP, FTP,
SMB, MySQL, Redis) that capture attacker behavior, map activity to
MITRE ATT&CK techniques, and generate threat intelligence.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if flagNoColor {
				color.NoColor = true
			}
		},
	}

	pflags := root.PersistentFlags()
	pflags.StringVarP(
		&flagConfig,
		"config", "c",
		config.DefaultConfigPath,
		"Path to config file",
	)
	pflags.BoolVarP(
		&flagVerbose,
		"verbose", "v",
		false,
		"Enable verbose logging",
	)
	pflags.BoolVar(
		&flagNoColor,
		"no-color",
		false,
		"Disable colored output",
	)

	root.AddCommand(
		newServeCmd(),
		newMigrateCmd(),
		newKeygenCmd(),
		newVersionCmd(),
	)

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			ui.PrintBanner()
			fmt.Printf("  Version:  %s\n", config.ToolVersion)
			fmt.Printf("  Module:   github.com/CarterPerez-dev/hive\n")
		},
	}
}

func loadConfig() (*config.Config, error) {
	return config.Load(flagConfig)
}
