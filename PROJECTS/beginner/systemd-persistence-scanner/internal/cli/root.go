/*
©AngelaMos | 2026
root.go

Root cobra command and global flag definitions

Defines the sentinel root command with persistent flags for JSON
output, minimum severity filtering, verbose mode, and custom scan
root. Subcommands are attached in their respective init functions.
*/

package cli

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/sentinel/internal/ui"
)

const fallbackHostname = "unknown"

var (
	flagJSON        bool
	flagMinSeverity string
	flagVerbose     bool
	flagRoot        string
	flagIgnoreFile  string
)

var rootCmd = &cobra.Command{
	Use:   "sentinel",
	Short: "Linux persistence mechanism scanner",
	Long: `sentinel scans a Linux system for persistence mechanisms
across systemd, cron, shell profiles, SSH, LD_PRELOAD,
kernel modules, udev rules, init.d, XDG autostart, at jobs,
MOTD scripts, and PAM modules.`,
	PersistentPreRun: func(
		cmd *cobra.Command, args []string,
	) {
		configureLogging()
		if !flagJSON {
			ui.PrintBanner()
		}
	},
}

func configureLogging() {
	level := slog.LevelWarn
	if flagVerbose {
		level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(
		os.Stderr,
		&slog.HandlerOptions{Level: level},
	)
	slog.SetDefault(slog.New(handler))
}

func init() {
	rootCmd.PersistentFlags().BoolVar(
		&flagJSON, "json", false,
		"output results as JSON",
	)
	rootCmd.PersistentFlags().StringVar(
		&flagMinSeverity, "min-severity", "info",
		"minimum severity to report (info|low|medium|high|critical)",
	)
	rootCmd.PersistentFlags().BoolVar(
		&flagVerbose, "verbose", false,
		"enable verbose logging",
	)
	rootCmd.PersistentFlags().StringVar(
		&flagRoot, "root", "/",
		"filesystem root to scan (for testing or chroot)",
	)
	rootCmd.PersistentFlags().StringVar(
		&flagIgnoreFile, "ignore-file", "",
		"path to .sentinel-ignore.yml for suppressing findings",
	)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
