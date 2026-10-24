// ©AngelaMos | 2026
// history.go

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CarterPerez-dev/khaos/internal/record"
	"github.com/CarterPerez-dev/khaos/internal/statedir"
	"github.com/spf13/cobra"
)

func newRunsCmd() *cobra.Command {
	return &cobra.Command{
		Use: "runs [directory]", Short: "list saved run records",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := statedir.Default()
			if err != nil {
				return err
			}
			dir := paths.Runs()
			if len(args) == 1 {
				dir = args[0]
			}
			entries, err := os.ReadDir(dir)
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				path := filepath.Join(dir, entry.Name(), record.RecordFile)
				rec, err := record.Read(path)
				if err != nil {
					return fmt.Errorf("read %s: %w", path, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s/%s\n",
					rec.RunID, rec.Started, rec.Experiment.Name,
					rec.Verdict.Epistemic, rec.Verdict.Direction)
			}
			return nil
		},
	}
}

func newShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <run-id-or-run.json>",
		Short: "read a saved run and verify its events",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			if filepath.Base(path) == path && path != record.RecordFile {
				paths, err := statedir.Default()
				if err != nil {
					return err
				}
				path = filepath.Join(paths.Run(path), record.RecordFile)
			}
			rec, err := record.Read(path)
			if err != nil {
				return err
			}
			return writeShownRecord(cmd, rec)
		},
	}
}

func writeShownRecord(cmd *cobra.Command, rec record.Record) error {
	body, err := record.Encode(rec)
	if err != nil {
		return err
	}
	_, err = cmd.OutOrStdout().Write(body)
	return err
}
