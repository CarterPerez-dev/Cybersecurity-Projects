// ©AngelaMos | 2026
// scrape.go

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/nadezhda/internal/fetch"
	"github.com/CarterPerez-dev/nadezhda/internal/ingest"
	"github.com/CarterPerez-dev/nadezhda/internal/source"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

const (
	statusNotModified = "304"
	statusError       = "error"
	statusOK          = "ok"
	dash              = "-"
)

var scrapeSource string

var scrapeCmd = &cobra.Command{
	Use:   "scrape",
	Short: "Ingest all enabled sources once",
	RunE:  runScrape,
}

func init() {
	scrapeCmd.Flags().StringVar(&scrapeSource, "source", "", "ingest only this source by name")
	rootCmd.AddCommand(scrapeCmd)
}

func runScrape(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	srcs, err := source.Load(cfg.SourcesPath)
	if err != nil {
		return err
	}

	targets, err := selectTargets(srcs, scrapeSource)
	if err != nil {
		return err
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	fc := fetch.New(fetch.Options{
		UserAgent:    cfg.Fetch.UserAgent,
		PerHostRate:  cfg.Fetch.PerHostRate,
		PerHostBurst: cfg.Fetch.PerHostBurst,
		Timeout:      time.Duration(cfg.Fetch.TimeoutSeconds) * time.Second,
		MaxRetries:   cfg.Fetch.MaxRetries,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	summary, err := ingest.Run(ctx, fc, st, cfg, targets, time.Now())
	if err != nil {
		return err
	}

	printSummary(cmd, summary)
	return nil
}

func selectTargets(srcs []source.Source, only string) ([]source.Source, error) {
	if only != "" {
		for _, s := range srcs {
			if s.Name == only {
				return []source.Source{s}, nil
			}
		}
		return nil, fmt.Errorf("scrape: unknown source %q", only)
	}
	return source.Enabled(srcs), nil
}

func printSummary(cmd *cobra.Command, summary ingest.Summary) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%-18s %-8s %-8s %-5s %-5s %-5s\n", "SOURCE", "STATUS", "PARSED", "NEW", "DUP", "ERR")
	for _, r := range summary.Results {
		fmt.Fprintf(out, "%-18s %-8s %-8s %-5s %-5s %-5s\n",
			r.Name, status(r), count(r, r.Parsed), count(r, r.New), count(r, r.Duplicates), count(r, r.ItemErrors))
	}
	newArticles, duplicates, failed := summary.Totals()
	fmt.Fprintf(out, "\n%d new, %d duplicate across %d sources (%d failed)\n",
		newArticles, duplicates, len(summary.Results), failed)
	for _, r := range summary.Results {
		if r.Err != nil {
			fmt.Fprintf(out, "  %s: %v\n", r.Name, r.Err)
		}
	}
}

func status(r ingest.SourceResult) string {
	switch {
	case r.Err != nil:
		return statusError
	case r.NotModified:
		return statusNotModified
	default:
		return statusOK
	}
}

func count(r ingest.SourceResult, n int) string {
	if r.Err != nil || r.NotModified {
		return dash
	}
	return fmt.Sprintf("%d", n)
}
