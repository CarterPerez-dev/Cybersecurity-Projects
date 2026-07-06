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

	"github.com/CarterPerez-dev/nadezhda/internal/cluster"
	"github.com/CarterPerez-dev/nadezhda/internal/config"
	"github.com/CarterPerez-dev/nadezhda/internal/enrich"
	"github.com/CarterPerez-dev/nadezhda/internal/fetch"
	"github.com/CarterPerez-dev/nadezhda/internal/ingest"
	"github.com/CarterPerez-dev/nadezhda/internal/source"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

const secondsPerHour = 3600

const enrichBudget = 5 * time.Minute

const (
	statusNotModified = "304"
	statusError       = "error"
	statusOK          = "ok"
	dash              = "-"
)

var (
	scrapeSource   string
	scrapeNoEnrich bool
)

var scrapeCmd = &cobra.Command{
	Use:   "scrape",
	Short: "Ingest all enabled sources once",
	RunE:  runScrape,
}

func init() {
	scrapeCmd.Flags().StringVar(&scrapeSource, "source", "", "ingest only this source by name")
	scrapeCmd.Flags().BoolVar(&scrapeNoEnrich, "no-enrich", false, "skip the keyless CVE enrichment pass")
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

	now := time.Now()
	summary, err := ingest.Run(ctx, fc, st, cfg, targets, now)
	if err != nil {
		return err
	}
	printSummary(cmd, summary)

	sinceUnix := now.Unix() - int64(cfg.Cluster.LookbackHours)*secondsPerHour
	windowSeconds := int64(cfg.Cluster.WindowHours) * secondsPerHour
	stats, err := cluster.Rebuild(st, cfg.Cluster.TitleJaccard, windowSeconds, sinceUnix)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%d clusters (%d multi-source, largest %d)\n",
		stats.Total, stats.MultiSource, stats.LargestSize)

	if !scrapeNoEnrich {
		enrichAfterScrape(ctx, cmd, cfg, st)
	}
	return nil
}

func enrichAfterScrape(ctx context.Context, cmd *cobra.Command, cfg config.Config, st *store.Store) {
	out := cmd.OutOrStdout()
	ectx, cancel := context.WithTimeout(ctx, enrichBudget)
	defer cancel()

	stats, err := enrich.Run(ectx, st, buildEnrichClients(cfg), time.Now(), cfg.Enrich.CacheTTLHours, cfg.Enrich.NegativeTTLHours)
	if err != nil {
		if done := stats.Enriched + stats.NotFound; done > 0 {
			fmt.Fprintf(out, "enriched %d/%d CVEs before stopping: %v\n", done, stats.Total, err)
		} else {
			fmt.Fprintf(out, "enrich skipped: %v (news is unaffected)\n", err)
		}
		return
	}
	if stats.Total == 0 {
		return
	}
	fmt.Fprintf(out, "enriched %d/%d CVEs (%d KEV, %d not found)\n",
		stats.Enriched, stats.Total, stats.KEVHits, stats.NotFound)
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
	fmt.Fprintf(out, "%-18s %-8s %-8s %-5s %-5s %-5s %-5s\n", "SOURCE", "STATUS", "PARSED", "NEW", "DUP", "CVE", "ERR")
	totalCVEs := 0
	for _, r := range summary.Results {
		totalCVEs += r.CVEs
		fmt.Fprintf(out, "%-18s %-8s %-8s %-5s %-5s %-5s %-5s\n",
			r.Name, status(r), count(r, r.Parsed), count(r, r.New), count(r, r.Duplicates), count(r, r.CVEs), count(r, r.ItemErrors))
	}
	newArticles, duplicates, failed := summary.Totals()
	fmt.Fprintf(out, "\n%d new, %d duplicate, %d CVE refs across %d sources (%d failed)\n",
		newArticles, duplicates, totalCVEs, len(summary.Results), failed)
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
