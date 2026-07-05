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

	"github.com/CarterPerez-dev/nadezhda/internal/cve"
	"github.com/CarterPerez-dev/nadezhda/internal/enrich"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

const nvdAPIKeyEnv = "NVD_API_KEY"

var enrichCmd = &cobra.Command{
	Use:   "enrich",
	Short: "Enrich extracted CVEs with NVD, CISA KEV, and EPSS intelligence",
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

	httpClient := &http.Client{Timeout: time.Duration(cfg.Fetch.TimeoutSeconds) * time.Second}
	apiKey := os.Getenv(nvdAPIKeyEnv)
	if apiKey == "" {
		apiKey = cfg.Enrich.NVDAPIKey
	}
	clients := enrich.Clients{
		NVD:  cve.NewNVDClient(httpClient, cve.NVDEndpoint, apiKey),
		KEV:  cve.NewKEVClient(httpClient, cve.KEVEndpoint),
		EPSS: cve.NewEPSSClient(httpClient, cve.EPSSEndpoint),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	stats, err := enrich.Run(ctx, st, clients, time.Now(), cfg.Enrich.CacheTTLHours, cfg.Enrich.NegativeTTLHours)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"enriched %d/%d CVEs (%d not in NVD, %d KEV, %d errors)\n",
		stats.Enriched, stats.Total, stats.NotFound, stats.KEVHits, stats.Errors)
	return nil
}
