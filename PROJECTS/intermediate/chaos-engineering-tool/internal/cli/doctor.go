// ©AngelaMos | 2026
// doctor.go

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/render"
	"github.com/CarterPerez-dev/khaos/internal/theme"
	"github.com/spf13/cobra"
)

const (
	doctorShort = "diagnose the environment and name the fix for anything broken"
	doctorLong  = `doctor resolves the Docker endpoint the same way khaos itself does, checks that
the daemon answers, and counts the containers that have consented to fault
injection. Every failed check names the cause and the command that fixes it.

A check that could not run is reported as skipped rather than hidden, so a
passing report never means a check was quietly not performed.`

	markPass    = "ok  "
	markFail    = "fail"
	markSkipped = "skip"
	checkWidth  = 20
	rowFormat   = "%s%s %s %s\n"
	fixFormat   = "%s%s\n"
)

var errNotReady = errors.New("environment is not ready")

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: doctorShort,
		Long:  doctorLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd.Context(), cmd.OutOrStdout())
		},
	}
}

func runDoctor(ctx context.Context, out io.Writer) error {
	checks := dockerx.Diagnose(ctx)
	healthy := true

	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}

	for _, check := range checks {
		if check.Status == dockerx.StatusFail {
			healthy = false
		}

		if _, err := fmt.Fprintf(out, rowFormat,
			render.Indent,
			statusMark(check.Status),
			theme.Fg(theme.TextNormal, render.Pad(check.Name, checkWidth)),
			theme.Fg(theme.TextDim, check.Detail)); err != nil {
			return err
		}

		if check.Fix == "" {
			continue
		}

		if _, err := fmt.Fprintf(
			out,
			fixFormat,
			render.FixIndent,
			theme.Fg(
				theme.TextBright,
				render.FixPrefix+check.Fix,
			),
		); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}

	if !healthy {
		return errNotReady
	}
	return nil
}

func statusMark(status dockerx.Status) string {
	switch status {
	case dockerx.StatusPass:
		return theme.Fg(theme.StateHeld, markPass)
	case dockerx.StatusSkipped:
		return theme.Fg(theme.StateUndetermined, markSkipped)
	default:
		return theme.Fg(theme.StatePermitted, markFail)
	}
}
