// ©AngelaMos | 2026
// targets.go

package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/render"
	"github.com/CarterPerez-dev/khaos/internal/theme"
	"github.com/spf13/cobra"
)

const (
	flagProject = "project"
	flagAll     = "all"

	targetsShort = "discover containers that have consented to fault injection"
	targetsLong  = `targets lists every container carrying the ` + dockerx.LabelConsent + `=` + dockerx.ConsentValue + ` label,
and says for each one whether khaos would accept or refuse it as a target.

You never write a selector. You pick a name from this list.`

	projectUsage = "only consider containers in this compose project"
	allUsage     = "also show containers khaos would refuse, and why"

	headerName    = "TARGET"
	headerProject = "PROJECT"
	headerImage   = "IMAGE"
	headerStatus  = "STATUS"

	statusReady = "ready"
	colName     = 26
	colProject  = 18
	colImage    = 30

	emptyMessage  = "no consenting containers found"
	refusedHint   = "re-run with --all to see containers khaos refuses and why"
	refusedFormat = "%d refused. %s"
	rowLayout     = "%s%s%s%s%s\n"
	noteLayout    = "%s%s\n"
	endpointNote  = "daemon: %s"
	dashMarker    = "-"
)

func newTargetsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "targets",
		Short: targetsShort,
		Long:  targetsLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			project, err := cmd.Flags().GetString(flagProject)
			if err != nil {
				return err
			}
			all, err := cmd.Flags().GetBool(flagAll)
			if err != nil {
				return err
			}
			return runTargets(cmd.Context(), cmd.OutOrStdout(), project, all)
		},
	}

	cmd.Flags().String(flagProject, "", projectUsage)
	cmd.Flags().Bool(flagAll, false, allUsage)

	return cmd
}

func runTargets(
	ctx context.Context,
	out io.Writer,
	project string,
	all bool,
) error {
	client, err := dockerx.Open(ctx)
	if err != nil {
		return fmt.Errorf("%w (run `khaos doctor` for the fix)", err)
	}
	defer func() { _ = client.Close() }()

	filter := dockerx.Filter{Project: project}

	guard := dockerx.Guard{Project: project, SelfID: dockerx.SelfContainerID()}

	targets, err := client.Targets(ctx, filter)
	if err != nil {
		return err
	}

	fmt.Fprintln(out)
	fmt.Fprintf(
		out,
		noteLayout,
		render.Indent,
		theme.Fg(
			theme.TextFaint,
			fmt.Sprintf(endpointNote, client.Endpoint().Host),
		),
	)

	if len(targets) == 0 {
		printNoTargets(out)
		return nil
	}

	refused := printTargetTable(out, targets, guard, all)

	if refused > 0 && !all {
		fmt.Fprintln(out)
		fmt.Fprintf(
			out,
			noteLayout,
			render.Indent,
			theme.Fg(
				theme.TextDim,
				fmt.Sprintf(refusedFormat, refused, refusedHint),
			),
		)
	}
	fmt.Fprintln(out)

	return nil
}

// printNoTargets is its own answer because an empty table carries no fix.
func printNoTargets(out io.Writer) {
	fmt.Fprintf(
		out,
		noteLayout,
		render.Indent,
		theme.Fg(theme.TextNormal, emptyMessage),
	)
	fmt.Fprintf(
		out,
		noteLayout,
		render.Indent,
		theme.Fg(theme.TextDim, dockerx.FixNoTargets),
	)
	fmt.Fprintln(out)
}

// printTargetTable returns how many targets were REFUSED.
func printTargetTable(
	out io.Writer,
	targets []dockerx.Target,
	guard dockerx.Guard,
	all bool,
) int {
	fmt.Fprintf(out, rowLayout, render.Indent,
		theme.Fg(theme.TextFaint, render.Cell(headerName, colName)),
		theme.Fg(theme.TextFaint, render.Cell(headerProject, colProject)),
		theme.Fg(theme.TextFaint, render.Cell(headerImage, colImage)),
		theme.Fg(theme.TextFaint, headerStatus))

	refused := 0
	for _, target := range targets {
		refusal := dockerx.Refuse(target, guard)
		if refusal != nil {
			refused++
			if !all {
				continue
			}
		}

		status := theme.Fg(theme.StateHeld, statusReady)
		if refusal != nil {
			status = theme.Fg(theme.StateDenied, refusal.Predicate)
		}

		fmt.Fprintf(
			out,
			rowLayout,
			render.Indent,
			theme.Fg(theme.TextBright, render.Cell(target.Name, colName)),
			theme.Fg(
				theme.TextNormal,
				render.Cell(orDash(target.Project), colProject),
			),
			theme.Fg(theme.TextDim, render.Cell(target.Image, colImage)),
			status,
		)

		if all && refusal != nil {
			fmt.Fprintf(
				out,
				noteLayout,
				render.FixIndent,
				theme.Fg(theme.TextDim, refusal.Reason),
			)
			fixLine(out, refusal.Fix)
		}
	}

	return refused
}

func orDash(s string) string {
	if s == "" {
		return dashMarker
	}
	return s
}
