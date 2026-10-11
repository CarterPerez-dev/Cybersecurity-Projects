// ©AngelaMos | 2026
// rangecmd.go

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/rangelab"
	"github.com/CarterPerez-dev/khaos/internal/render"
	"github.com/CarterPerez-dev/khaos/internal/theme"
	"github.com/CarterPerez-dev/khaos/internal/verifier"
	"github.com/CarterPerez-dev/khaos/internal/workspace"
	"github.com/spf13/cobra"
)

var ErrUnknownFailMode = errors.New("the range has no such fail mode")

const (
	flagFailMode = "fail-mode"
	flagCacheTTL = "cache-ttl"
	flagPort     = "port"
	flagQuiet    = "quiet"

	rangeShort = "bring up a target stack that is deliberately breakable"
	rangeLong  = `The range is a small stack khaos ships so you have something to break before you
point it at anything you care about.

It is a gateway in front of an identity provider. Pause the provider and the
gateway has to decide what to do without it. In ` + "`--fail-mode closed`" + ` it refuses,
which is correct. In ` + "`--fail-mode open`" + ` it serves anyway, which is the defect
khaos exists to find, modelled on the Okta delegated-authentication advisory
where a cached decision was reachable only while the agent was unreachable.

Both containers carry the consent label, and the gateway's host port is a
random high one chosen at startup, so it never collides with anything already
running.`

	upShort     = "build and start the range, then wait until it answers"
	downShort   = "stop the range and remove everything it created"
	statusShort = "show whether the range is running and where to reach it"

	failModeUsage = "which bug the range carries. The introspecting gateways understand closed, open and stale-rearm; khaos's verifier gateway understands closed plus one mode per verifier defect, and `khaos range up --fail-mode ?` lists them all. An unrecognised value is refused rather than quietly leaving the range correct"
	cacheTTLUsage = "how long the gateway caches an authorization decision"
	portUsage     = "host port for the gateway; the default is a random high port chosen at startup"
	quietUsage    = "suppress compose build and start output"

	msgStarting        = "building and starting the range"
	msgPortRetry       = "host port %d was taken between the check and the bind; picking another"
	errPortBound       = "could not start the range on host port %d: %w"
	portAttempts       = 3
	msgRangeUp         = "range is up"
	msgRangeDown       = "range is down"
	msgRangeStopped    = "the range is not running; start it with `khaos range up`"
	msgFailMode        = "fail mode %s"
	msgTokenHint       = "a credential is issued on demand, so `khaos run` against the range needs no flags"
	msgPortHint        = "host port %d was chosen at random; pass --port to pin it"
	errUnknownFailMode = "%w: %q (known modes: %s)"

	msgTierDirect   = "docker-native tier  %s"
	msgTierProxied  = "proxy tier          %s, with khaos's fault proxy expected on host port %d"
	msgTierVerifier = "identity tier       %s, trusting khaos's provider as %s"
)

func newRangeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "range",
		Short: rangeShort,
		Long:  rangeLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newRangeUpCmd(), newRangeDownCmd(), newRangeStatusCmd())

	return cmd
}

func newRangeUpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "up",
		Short: upShort,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			failMode, err := cmd.Flags().GetString(flagFailMode)
			if err != nil {
				return err
			}
			cacheTTL, err := cmd.Flags().GetString(flagCacheTTL)
			if err != nil {
				return err
			}
			port, err := cmd.Flags().GetInt(flagPort)
			if err != nil {
				return err
			}
			quiet, err := cmd.Flags().GetBool(flagQuiet)
			if err != nil {
				return err
			}
			return runRangeUp(
				cmd.Context(),
				cmd.OutOrStdout(),
				failMode,
				cacheTTL,
				port,
				quiet,
			)
		},
	}

	cmd.Flags().String(flagFailMode, rangelab.FailModeShut, failModeUsage)
	cmd.Flags().String(flagCacheTTL, "2s", cacheTTLUsage)
	cmd.Flags().Int(flagPort, 0, portUsage)
	cmd.Flags().Bool(flagQuiet, false, quietUsage)

	return cmd
}

func newRangeDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: downShort,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			lab, err := rangelab.Locate(rangelab.Ports{})
			if err != nil {
				return err
			}

			work, err := workspace.OpenExclusive(cmd.Context())
			if err != nil {
				return err
			}
			defer work.Close()

			if err := lab.Down(cmd.Context(), io.Discard); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintln(out)
			say(out, msgRangeDown)
			fmt.Fprintln(out)

			return nil
		},
	}
}

func newRangeStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: statusShort,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRangeStatus(cmd.Context(), cmd.OutOrStdout())
		},
	}
}

// knownFailModes is every value the range answers to, across both kinds of
// gateway. The introspecting gateways understand three and khaos's verifier
// gateway understands ten, and an unrecognised value leaves EVERY gateway
// behaving correctly.
//
// That makes a typo the worst possible outcome: the range comes up, nothing is
// broken, and all eighteen identity experiments report a clean survival against
// a stack that was supposed to be carrying the bug. Refusing by name is the only
// safe behaviour, and the refusal lists what is available because nobody is
// going to remember ten mode names.
func knownFailModes() []string {
	modes := []string{
		rangelab.FailModeShut,
		rangelab.FailModeOpen,
		rangelab.FailModeStaleRearm,
	}

	for _, mode := range verifier.Modes() {
		if !slices.Contains(modes, mode) {
			modes = append(modes, mode)
		}
	}

	return modes
}

func runRangeUp(
	ctx context.Context,
	out io.Writer,
	failMode, cacheTTL string,
	port int,
	quiet bool,
) error {
	if !slices.Contains(knownFailModes(), failMode) {
		return fmt.Errorf(errUnknownFailMode, ErrUnknownFailMode, failMode,
			strings.Join(knownFailModes(), listSep))
	}

	work, err := workspace.OpenExclusive(ctx)
	if err != nil {
		return err
	}
	defer work.Close()

	progress := io.Writer(os.Stderr)
	if quiet {
		progress = io.Discard
	}

	fmt.Fprintln(out)
	say(out, msgStarting)

	pinned := port != 0
	var lab rangelab.Lab

	for attempt := range portAttempts {
		// Only the direct gateway's port is pinnable. The other two are khaos's
		// own plumbing: the second gateway's published port and the port that
		// gateway expects khaos's fault proxy on. Letting an operator pin those
		// would be a footgun with no use case.
		ports, err := rangelab.FreePorts()
		if err != nil {
			return err
		}

		if pinned {
			ports.Gateway = port
		}
		port = ports.Gateway

		lab, err = rangelab.Locate(ports)
		if err != nil {
			return err
		}

		err = lab.Up(ctx, progress, failMode, cacheTTL)
		if err == nil {
			break
		}

		if pinned || !rangelab.PortTaken(err) || attempt == portAttempts-1 {
			return fmt.Errorf(errPortBound, port, err)
		}

		note(out, fmt.Sprintf(msgPortRetry, port))
	}

	event(out, markOK, theme.StatusOK, msgRangeUp)
	note(out, fmt.Sprintf(msgFailMode, failMode))
	note(out, fmt.Sprintf(msgPortHint, lab.Port))
	note(out, msgTokenHint)
	fmt.Fprintln(out)

	// Printed from the containers rather than from what khaos just chose, which
	// is the same discipline the proxy port is read back under: the container is
	// the only authority on where it will actually dial and what issuer it will
	// actually trust. Printing khaos's intent instead would hide exactly the
	// mismatch this is most useful for.
	describeEntryPoints(ctx, out, work.Docker)

	return nil
}

func runRangeStatus(ctx context.Context, out io.Writer) error {
	work, err := workspace.OpenShared(ctx)
	if err != nil {
		return err
	}
	defer work.Close()

	targets, err := work.Docker.Targets(
		ctx,
		dockerx.Filter{Project: rangelab.ProjectName},
	)
	if err != nil {
		return err
	}

	fmt.Fprintln(out)

	if len(targets) == 0 {
		note(out, msgRangeStopped)
		fmt.Fprintln(out)
		return nil
	}

	for _, target := range targets {
		status := theme.Fg(theme.StatusOK, statusReady)
		if refusal := dockerx.Refuse(target, dockerx.Guard{}); refusal != nil {
			status = theme.Fg(theme.StatusWarn, refusal.Predicate)
		}

		fmt.Fprintf(out, rowLayout, render.Indent,
			theme.Fg(theme.TextBright, render.Cell(target.Name, colName)),
			theme.Fg(theme.TextNormal, render.Cell(target.Project, colProject)),
			theme.Fg(theme.TextDim, render.Cell(target.Image, colImage)),
			status)
	}

	fmt.Fprintln(out)

	// The entry points, which the container listing cannot give. It shows three
	// gateways with truncated names and says nothing about which one is reached
	// how, so an operator could not find the second or third tier from khaos's
	// own output at all. Each tier is probed at a different URL and the whole
	// point of running the same experiment against two of them is being able to
	// address both.
	describeEntryPoints(ctx, out, work.Docker)

	return nil
}

func describeEntryPoints(
	ctx context.Context,
	out io.Writer,
	reader rangelab.PortReader,
) {
	lab, err := rangelab.Discover(ctx, reader)
	if err != nil {
		return
	}

	say(out, fmt.Sprintf(msgTierDirect, lab.ProtectedURL()))

	if lab.ProxiedPort != 0 {
		say(
			out,
			fmt.Sprintf(
				msgTierProxied,
				lab.ProxiedProtectedURL(),
				lab.ProxyPort,
			),
		)
	}

	if lab.VerifierPort != 0 {
		say(
			out,
			fmt.Sprintf(
				msgTierVerifier,
				lab.VerifierProtectedURL(),
				lab.Issuer,
			),
		)
	}

	fmt.Fprintln(out)
}
