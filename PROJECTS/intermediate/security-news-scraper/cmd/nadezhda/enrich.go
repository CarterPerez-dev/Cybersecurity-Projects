// ©AngelaMos | 2026
// enrich.go

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/nadezhda/internal/config"
	"github.com/CarterPerez-dev/nadezhda/internal/cve"
	"github.com/CarterPerez-dev/nadezhda/internal/enrich"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

const nvdAPIKeyEnv = "NVD_API_KEY"

var enrichCmd = &cobra.Command{
	Use:   "enrich",
	Short: "Refresh CVE intelligence (CVE List / NVD, CISA KEV, EPSS) for extracted CVEs",
	Long:  "Refresh CVE intelligence for extracted CVEs. Keyless by default (CVE Program, CISA KEV, EPSS); uses NVD only when NVD_API_KEY is set. scrape already runs this automatically, so this command is for manually refreshing.",
	RunE:  runEnrich,
}

func init() {
	rootCmd.AddCommand(enrichCmd)
}

func runEnrich(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	stats, err := enrich.Run(ctx, st, buildEnrichClients(cfg), time.Now(), cfg.Enrich.CacheTTLHours, cfg.Enrich.NegativeTTLHours)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"enriched %d/%d CVEs (%d not found, %d KEV, %d errors)\n",
		stats.Enriched, stats.Total, stats.NotFound, stats.KEVHits, stats.Errors)
	return nil
}

func buildEnrichClients(cfg config.Config) enrich.Clients {
	httpClient := &http.Client{Timeout: time.Duration(cfg.Fetch.TimeoutSeconds) * time.Second}
	return enrich.Clients{
		Core: buildCoreSource(httpClient, nvdAPIKey(cfg)),
		KEV:  cve.NewKEVClient(httpClient, cve.KEVEndpoint),
		EPSS: cve.NewEPSSClient(httpClient, cve.EPSSEndpoint),
	}
}

func buildCoreSource(httpClient *http.Client, apiKey string) cve.CVESource {
	if apiKey != "" {
		return cve.NewNVDClient(httpClient, cve.NVDEndpoint, apiKey)
	}
	return cve.NewCVEListClient(httpClient, cve.CVEListEndpoint)
}

func nvdAPIKey(cfg config.Config) string {
	if k := os.Getenv(nvdAPIKeyEnv); k != "" {
		return k
	}
	return cfg.Enrich.NVDAPIKey
}
