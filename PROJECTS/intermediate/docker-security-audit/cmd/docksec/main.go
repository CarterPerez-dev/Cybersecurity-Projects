/*
AngelaMos | 2026
main.go
*/

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"github.com/CarterPerez-dev/docksec/internal/benchmark"
	"github.com/CarterPerez-dev/docksec/internal/config"
	"github.com/CarterPerez-dev/docksec/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
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
	cfg := config.New()

	root := &cobra.Command{
		Use:   "docksec",
		Short: "Docker security audit tool",
		Long: `docksec scans Docker environments for security misconfigurations,
validates against CIS Docker Benchmark controls, and generates
actionable remediation reports.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newScanCmd(cfg),
		newVersionCmd(),
		newBenchmarkCmd(),
	)

	return root
}

func newScanCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan Docker environment for security issues",
		Long: `Scan running containers, images, Dockerfiles, and docker-compose files
for security misconfigurations and CIS Docker Benchmark violations.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), cfg)
		},
	}

	flags := cmd.Flags()

	flags.StringSliceVarP(&cfg.Targets, "target", "t", []string{"all"},
		"Scan targets: all, containers, daemon, images")

	flags.StringSliceVarP(&cfg.Files, "file", "f", nil,
		"Dockerfile or docker-compose.yml files to scan")

	flags.StringVarP(&cfg.Output, "output", "o", "terminal",
		"Output format: terminal, json, sarif, junit")

	flags.StringVar(&cfg.OutputFile, "output-file", "",
		"Write output to file instead of stdout")

	flags.StringSliceVar(&cfg.Severity, "severity", nil,
		"Filter by severity: info, low, medium, high, critical")

	flags.StringSliceVar(&cfg.CISControls, "cis", nil,
		"Filter by specific CIS control IDs (e.g., 5.4,5.31)")

	flags.StringSliceVar(&cfg.ExcludeContainers, "exclude-container", nil,
		"Exclude containers by name pattern")

	flags.StringSliceVar(&cfg.IncludeContainers, "include-container", nil,
		"Include only containers matching name pattern")

	flags.StringVar(
		&cfg.FailOn,
		"fail-on",
		"",
		"Exit with code 1 if findings at or above severity: low, medium, high, critical",
	)

	flags.BoolVarP(&cfg.Quiet, "quiet", "q", false,
		"Minimal output (counts only)")

	flags.BoolVarP(&cfg.Verbose, "verbose", "v", false,
		"Verbose output for debugging")

	flags.IntVar(&cfg.Workers, "workers", config.DefaultWorkerCount,
		"Number of concurrent workers")

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("docksec %s\n", version)
			fmt.Printf("  commit:  %s\n", commit)
			fmt.Printf("  built:   %s\n", buildDate)
		},
	}
}

func newBenchmarkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "CIS Docker Benchmark information",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List all available CIS controls",
			RunE: func(cmd *cobra.Command, args []string) error {
				return listBenchmarkControls()
			},
		},
		&cobra.Command{
			Use:   "show [control-id]",
			Short: "Show details of a specific CIS control",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return showBenchmarkControl(args[0])
			},
		},
	)

	return cmd
}

func runScan(ctx context.Context, cfg *config.Config) (err error) {
	s, err := scanner.New(cfg)
	if err != nil {
		return fmt.Errorf("initializing scanner: %w", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("closing scanner: %w", closeErr)
		}
	}()

	return s.Run(ctx)
}

func listBenchmarkControls() error {
	controls := benchmark.All()
	if len(controls) == 0 {
		fmt.Println("No CIS controls registered.")
		return nil
	}

	sort.Slice(controls, func(i, j int) bool {
		return controls[i].ID < controls[j].ID
	})

	grouped := make(map[string][]benchmark.Control)
	for _, c := range controls {
		grouped[c.Section] = append(grouped[c.Section], c)
	}

	sections := make([]string, 0, len(grouped))
	for section := range grouped {
		sections = append(sections, section)
	}
	sort.Strings(sections)

	fmt.Println("CIS Docker Benchmark Controls")
	fmt.Println("==============================")
	fmt.Println()

	for _, section := range sections {
		fmt.Printf("[%s]\n", section)
		for _, c := range grouped[section] {
			levelStr := fmt.Sprintf("L%d", c.Level)
			scoredStr := "  "
			if c.Scored {
				scoredStr = "S "
			}
			fmt.Printf(
				"  %s %-6s %s %s\n",
				scoredStr,
				c.ID,
				levelStr,
				c.Title,
			)
		}
		fmt.Println()
	}

	fmt.Printf("Total: %d controls\n", len(controls))
	fmt.Println()
	fmt.Println("Legend: S = Scored, L1/L2 = CIS Level")

	return nil
}

func showBenchmarkControl(id string) error {
	control, found := benchmark.Get(id)
	if !found {
		return fmt.Errorf("control %q not found", id)
	}

	fmt.Printf("CIS Control: %s\n", control.ID)
	fmt.Println("============" + repeatChar('=', len(control.ID)))
	fmt.Println()

	fmt.Printf("Section:     %s\n", control.Section)
	fmt.Printf("Title:       %s\n", control.Title)
	fmt.Printf("Severity:    %s\n", control.Severity.String())
	fmt.Printf("Level:       %d\n", control.Level)
	fmt.Printf("Scored:      %t\n", control.Scored)
	fmt.Println()

	fmt.Println("Description:")
	fmt.Printf("  %s\n", control.Description)
	fmt.Println()

	fmt.Println("Remediation:")
	fmt.Printf("  %s\n", control.Remediation)
	fmt.Println()

	if len(control.References) > 0 {
		fmt.Println("References:")
		for _, ref := range control.References {
			fmt.Printf("  - %s\n", ref)
		}
	}

	return nil
}

func repeatChar(c rune, n int) string {
	result := make([]rune, n)
	for i := range result {
		result[i] = c
	}
	return string(result)
}
