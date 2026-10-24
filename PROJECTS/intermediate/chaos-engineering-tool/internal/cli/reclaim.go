// ©AngelaMos | 2026
// reclaim.go

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/run"
	"github.com/CarterPerez-dev/khaos/internal/theme"
	"github.com/CarterPerez-dev/khaos/internal/workspace"
	"github.com/spf13/cobra"
)

const (
	flagExpiredOnly = "expired-only"
	flagInterval    = "interval"

	reclaimShort = "revert any fault left behind by a khaos that did not finish"
	reclaimLong  = `reclaim replays the write-ahead journal and reverts every fault that was never
reverted, whether khaos crashed, was killed outright, or lost its daemon.

Every revert is idempotent, so running this when nothing is outstanding is
safe and does nothing.

Without --expired-only this takes the exclusive lock, so it will refuse to run
while another khaos is holding a live fault rather than pull that fault out
from under it.`

	reapShort = "watch the journal and revert faults as their leases expire"
	reapLong  = `reap is the dead man's switch. It reverts a fault once its lease expires, so a
fault outlives a dead khaos by at most the remaining lease rather than forever.

It runs until you stop it, and it only ever touches faults whose lease has
already expired, so it is safe to leave running beside an active khaos. You do
not need it for an ordinary ` + "`khaos inject`" + `, which reverts its own fault when
you stop it; reap is what covers the case where khaos never gets the chance.

A fault it cannot revert is reported and retried on the next tick rather than
stopping the watch, because one stuck record must never disable the switch for
every other fault on the machine.`

	expiredOnlyUsage = "only revert faults whose lease has already expired, and do not take the exclusive lock"
	intervalUsage    = "how often to check the journal for expired leases"

	defaultReapInterval = 5 * time.Second

	msgNothing   = "nothing outstanding"
	msgReclaimed = "reclaimed %d fault(s)"
	msgWatching  = "watching %s every %s, until you stop it"
	msgStopped   = "stopped watching, %d fault(s) reclaimed"
	msgDamaged   = "the journal has a damaged line; khaos acted on every record it could read, but cannot promise that is all of them"

	errIntervalUsage = "%w: %s"
)

// A non-positive interval reaches time.NewTicker, which panics. Refused by
// name instead, before the workspace is opened and its lock taken.
var ErrIntervalNotPositive = errors.New(
	"the reap interval has to be longer than zero, or there is no tick to check the journal on",
)

func newReclaimCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reclaim",
		Short: reclaimShort,
		Long:  reclaimLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			expiredOnly, err := cmd.Flags().GetBool(flagExpiredOnly)
			if err != nil {
				return err
			}
			return runReclaim(cmd.Context(), cmd.OutOrStdout(), expiredOnly)
		},
	}

	cmd.Flags().Bool(flagExpiredOnly, false, expiredOnlyUsage)

	return cmd
}

func newReapCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reap",
		Short: reapShort,
		Long:  reapLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			interval, err := cmd.Flags().GetDuration(flagInterval)
			if err != nil {
				return err
			}
			return runReap(cmd.Context(), cmd.OutOrStdout(), interval)
		},
	}

	cmd.Flags().Duration(flagInterval, defaultReapInterval, intervalUsage)

	return cmd
}

func runReclaim(ctx context.Context, out io.Writer, expiredOnly bool) error {
	work, err := openFor(ctx, expiredOnly)
	if err != nil {
		return err
	}
	defer work.Close()

	fmt.Fprintln(out)
	sweep := run.Reclaim(
		ctx,
		work.Env(),
		work.Journal,
		time.Now().UTC(),
		expiredOnly,
	)
	report(out, sweep)

	if len(sweep.Results) == 0 {
		note(out, msgNothing)
	}
	fmt.Fprintln(out)

	if sweep.Failed() {
		return run.ErrRevertFailed
	}

	return sweep.Damage
}

func runReap(ctx context.Context, out io.Writer, interval time.Duration) error {
	// Before the workspace: a refusal that already took the lock cost the
	// operator something.
	if interval <= 0 {
		return fmt.Errorf(errIntervalUsage, ErrIntervalNotPositive, interval)
	}

	work, err := workspace.OpenShared(ctx)
	if err != nil {
		return err
	}
	defer work.Close()

	fmt.Fprintln(out)
	note(out, fmt.Sprintf(msgWatching, work.Journal.Path(), interval))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	reclaimed := 0
	failed := map[string]bool{}

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(out)
			note(out, fmt.Sprintf(msgStopped, reclaimed))
			fmt.Fprintln(out)
			return reapExit(work.Journal.Path(), failed, time.Now().UTC())
		case <-ticker.C:
			sweep := run.Reclaim(
				ctx,
				work.Env(),
				work.Journal,
				time.Now().UTC(),
				true,
			)
			report(out, sweep)
			reclaimed += sweep.Succeeded()
			for _, result := range sweep.Results {
				if result.Err != nil {
					failed[result.Record.MutationID] = true
				} else {
					delete(failed, result.Record.MutationID)
				}
			}
		}
	}
}

func reapExit(path string, failed map[string]bool, now time.Time) error {
	outstanding, damage := journal.Outstanding(path)
	for _, record := range outstanding {
		if failed[record.MutationID] || record.Expired(now) {
			return errors.Join(damage, run.ErrRevertFailed)
		}
	}
	return damage
}

func openFor(
	ctx context.Context,
	expiredOnly bool,
) (*workspace.Workspace, error) {
	if expiredOnly {
		return workspace.OpenShared(ctx)
	}
	return workspace.OpenExclusive(ctx)
}

func report(out io.Writer, sweep run.Sweep) {
	if sweep.Damage != nil {
		event(out, markError, theme.StatusError, msgDamaged)
	}

	for _, result := range sweep.Results {
		if result.Err != nil {
			event(
				out,
				markError,
				theme.StatusError,
				fmt.Sprintf(
					faultFormat,
					result.Record.Kind,
					result.Record.TargetName,
					result.Err,
				),
			)
			continue
		}
		event(
			out,
			markRevert,
			theme.StatusOK,
			fmt.Sprintf(
				leaseFormat,
				result.Record.Kind,
				result.Record.TargetName,
				result.Record.RunID,
				result.Record.LeaseID,
			),
		)
	}

	if sweep.Succeeded() > 0 {
		note(out, fmt.Sprintf(msgReclaimed, sweep.Succeeded()))
	}
}
