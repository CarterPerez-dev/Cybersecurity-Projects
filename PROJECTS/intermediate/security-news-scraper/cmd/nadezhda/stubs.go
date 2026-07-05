// ©AngelaMos | 2026
// stubs.go

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func notImplemented(milestone string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("%s is not implemented yet (%s)", cmd.Name(), milestone)
	}
}

func init() {
	stubs := []struct {
		use       string
		short     string
		milestone string
	}{
		{"digest", "Render a ranked digest to Markdown or JSON", "milestone M4"},
		{"tui", "Browse aggregated news in an interactive terminal UI", "milestone M5"},
		{"ideate", "Generate content angles from ranked clusters via an AI provider", "milestone M6"},
		{"watch", "Run as a daemon, re-ingesting on an interval", "milestone M7"},
	}
	for _, s := range stubs {
		rootCmd.AddCommand(&cobra.Command{
			Use:   s.use,
			Short: s.short,
			RunE:  notImplemented(s.milestone),
		})
	}
}
