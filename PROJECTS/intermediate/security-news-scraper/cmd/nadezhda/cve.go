// ©AngelaMos | 2026
// cve.go

package main

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

const naValue = "n/a"

var cveCmd = &cobra.Command{
	Use:   "cve CVE-YYYY-NNNN",
	Short: "Show an enriched CVE and the articles mentioning it",
	Args:  cobra.ExactArgs(1),
	RunE:  runCVE,
}

func init() {
	rootCmd.AddCommand(cveCmd)
}

func runCVE(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	id := strings.ToUpper(args[0])
	c, err := st.GetCVE(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%s not found; run 'nadezhda scrape' to discover it", id)
		}
		return err
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%s\n", c.ID)
	if c.EnrichedAt == 0 {
		fmt.Fprintln(out, "  not enriched yet; run 'nadezhda enrich'")
	} else {
		fmt.Fprintf(out, "  CVSS: %s\n", cvssLine(c))
		fmt.Fprintf(out, "  CWE:  %s\n", orNA(c.CWE))
		fmt.Fprintf(out, "  KEV:  %s\n", kevLine(c))
		fmt.Fprintf(out, "  EPSS: %s\n", epssLine(c))
		if c.Description != "" {
			fmt.Fprintf(out, "\n  %s\n", c.Description)
		}
	}

	articles, err := st.ArticlesForCVE(id)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\nMentioned in %d article(s):\n", len(articles))
	for _, a := range articles {
		fmt.Fprintf(out, "  [%s] %s\n    %s\n", a.SourceName, a.Title, a.CanonicalURL)
	}
	return nil
}

func cvssLine(c store.CVE) string {
	if c.CVSSScore == nil {
		return naValue
	}
	return fmt.Sprintf("%.1f %s (%s)  %s", *c.CVSSScore, orNA(c.CVSSSeverity), orNA(c.CVSSVersion), c.CVSSVector)
}

func kevLine(c store.CVE) string {
	if !c.IsKEV {
		return "no"
	}
	ransom := "no"
	if c.KEVRansomware {
		ransom = "yes"
	}
	return fmt.Sprintf("yes (added %s, ransomware: %s)", orNA(c.KEVDateAdded), ransom)
}

func epssLine(c store.CVE) string {
	if c.EPSS == nil || c.EPSSPercentile == nil {
		return naValue
	}
	return fmt.Sprintf("%.5f (percentile %.5f)", *c.EPSS, *c.EPSSPercentile)
}

func orNA(s string) string {
	if s == "" {
		return naValue
	}
	return s
}
