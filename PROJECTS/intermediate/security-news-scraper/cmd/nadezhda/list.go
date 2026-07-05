// ©AngelaMos | 2026
// list.go

package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

const (
	defaultListLimit = 50
	dateLayout       = "2006-01-02"
	noDate           = "----------"
)

var (
	listSource  string
	listSince   string
	listMinCVSS float64
	listKEV     bool
	listKeyword string
	listLimit   int
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored articles with filters",
	RunE:  runList,
}

func init() {
	listCmd.Flags().StringVar(&listSource, "source", "", "filter by source name")
	listCmd.Flags().StringVar(&listSince, "since", "", "only articles published within this window (e.g. 24h, 168h)")
	listCmd.Flags().Float64Var(&listMinCVSS, "min-cvss", 0, "only articles referencing a CVE with CVSS >= this")
	listCmd.Flags().BoolVar(&listKEV, "kev", false, "only articles referencing a KEV-listed CVE")
	listCmd.Flags().StringVar(&listKeyword, "keyword", "", "filter by keyword in title or summary")
	listCmd.Flags().IntVar(&listLimit, "limit", defaultListLimit, "maximum rows to show")
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	filter := store.ListFilter{
		Source:  listSource,
		MinCVSS: listMinCVSS,
		KEV:     listKEV,
		Keyword: listKeyword,
		Limit:   listLimit,
	}
	if listSince != "" {
		d, err := time.ParseDuration(listSince)
		if err != nil {
			return fmt.Errorf("invalid --since %q: %w", listSince, err)
		}
		filter.Since = time.Now().Add(-d).Unix()
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	articles, err := st.ListArticles(filter)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%-10s  %-16s  %s\n", "DATE", "SOURCE", "TITLE")
	for _, a := range articles {
		fmt.Fprintf(out, "%-10s  %-16s  %s\n", formatDate(a.PublishedAt), a.SourceName, a.Title)
	}
	fmt.Fprintf(out, "\n%d article(s)\n", len(articles))
	return nil
}

func formatDate(unix int64) string {
	if unix == 0 {
		return noDate
	}
	return time.Unix(unix, 0).UTC().Format(dateLayout)
}
