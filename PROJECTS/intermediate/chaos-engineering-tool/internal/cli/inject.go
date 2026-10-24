// ©AngelaMos | 2026
// inject.go

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/lease"
	"github.com/CarterPerez-dev/khaos/internal/run"
	"github.com/CarterPerez-dev/khaos/internal/theme"
	"github.com/CarterPerez-dev/khaos/internal/workspace"
	"github.com/spf13/cobra"
)

const (
	flagTTL     = "ttl"
	flagHold    = "hold"
	flagTimeout = "revert-timeout"

	injectShort = "apply a single fault to one target and hold it until you stop"

	ttlUsage     = "how long the fault may outlive khaos before `khaos reap` or the next khaos invocation reclaims it; it does NOT limit how long the fault is held while khaos is alive"
	holdUsage    = "hold the fault for this long and then revert, instead of holding until you interrupt"
	timeoutUsage = "give up waiting for the daemon during a revert after this long"

	markInject = "->"
	markRevert = "<-"
	markOK     = "ok"
	markError  = "!!"
	markPlan   = "plan"

	defaultRevertTimeout = 60 * time.Second
	holdDisabled         = time.Duration(0)

	msgInjected  = "fault applied, holding. press ctrl-c to revert"
	msgReverting = "reverting"
	msgReverted  = "reverted, target restored"
	msgHoldOver  = "hold elapsed"
	msgInterrupt = "interrupted, reverting now (do not kill khaos, the revert is running)"
	msgClamped   = "--ttl was raised to %s, the shortest lease khaos will issue"
	msgLeaseInfo = "run %s, lease %s, expires %s"

	errNotDirect = "%s acts on the path between a target and its dependency rather than on a container, and it exists only for as long as the run that owns khaos's proxy, so `khaos inject` cannot apply it on its own; run it as an experiment with `khaos run`, or pick one of: %s"
)

func newInjectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inject <kind> <target>",
		Short: injectShort,
		Long:  injectLong(),
		Example: "  khaos inject " + inject.KindPause + " shop-api-1\n" +
			"  khaos inject " + inject.KindDisconnect + " shop-api-1 --hold 30s",
		Args: cobra.MatchAll(cobra.ExactArgs(2), onlyKnownKind),
		RunE: func(cmd *cobra.Command, args []string) error {
			ttl, err := cmd.Flags().GetDuration(flagTTL)
			if err != nil {
				return err
			}
			hold, err := cmd.Flags().GetDuration(flagHold)
			if err != nil {
				return err
			}
			timeout, err := cmd.Flags().GetDuration(flagTimeout)
			if err != nil {
				return err
			}
			project, err := cmd.Flags().GetString(flagProject)
			if err != nil {
				return err
			}
			return runInject(cmd.Context(), cmd.OutOrStdout(),
				args[0], args[1], project, ttl, hold, timeout)
		},
		ValidArgsFunction: completeKinds,
	}

	cmd.Flags().Duration(flagTTL, lease.DefaultTTL, ttlUsage)
	cmd.Flags().Duration(flagHold, holdDisabled, holdUsage)
	cmd.Flags().Duration(flagTimeout, defaultRevertTimeout, timeoutUsage)
	cmd.Flags().String(flagProject, "", projectUsage)

	return cmd
}

func injectLong() string {
	return `inject applies one raw fault to one consenting target, holds it, and reverts it
when you stop the command.

Available kinds: ` + strings.Join(
		inject.DirectKinds(),
		", ",
	) + `

The fault carries a lease. Everything the revert will need is written to the
journal BEFORE the fault is applied, so a khaos killed outright still leaves a
record that fully describes how to put the target back. The next khaos
invocation reverts it, and ` + "`khaos reap`" + ` reverts it with no further
invocation at all.`
}

func onlyKnownKind(_ *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}

	if _, err := inject.Lookup(args[0]); err != nil {
		return err
	}

	// Refused by name, because attempting it fails deep inside the mutation
	// with a message about a proxy the operator never asked for.
	if !inject.IsDirect(args[0]) {
		return fmt.Errorf(
			errNotDirect,
			args[0],
			strings.Join(inject.DirectKinds(), ", "),
		)
	}

	return nil
}

func completeKinds(
	_ *cobra.Command,
	args []string,
	_ string,
) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return inject.DirectKinds(), cobra.ShellCompDirectiveNoFileComp
}

func runInject(
	ctx context.Context,
	out io.Writer,
	kind, name, project string,
	ttl, hold, timeout time.Duration,
) error {
	work, err := workspace.OpenExclusive(ctx)
	if err != nil {
		return err
	}
	defer work.Close()
	if err := work.RequireClean(); err != nil {
		return err
	}

	mutator, err := inject.Lookup(kind)
	if err != nil {
		return err
	}

	filter := dockerx.Filter{Project: project}
	guard := dockerx.Guard{Project: project, SelfID: dockerx.SelfContainerID()}

	planned, err := work.Docker.Accept(ctx, name, filter, guard)
	if err != nil {
		return err
	}

	fmt.Fprintln(out)
	event(out, markPlan, theme.TextFaint, mutator.Describe(work.Env(), planned))

	guard.ExpectedID = planned.ID
	confirmed, err := work.Docker.Accept(ctx, name, filter, guard)
	if err != nil {
		return err
	}

	session := run.NewSession(work.Env(), work.Journal, ttl)
	defer recoverInjection(ctx, out, session)

	if session.Lease().TTL() != ttl {
		note(out, fmt.Sprintf(msgClamped, session.Lease().TTL()))
	}

	if err := session.Inject(ctx, kind, confirmed); err != nil {
		return errors.Join(
			err,
			revert(withoutCancel(ctx, timeout), out, session),
		)
	}

	event(out, markInject, theme.StatusWarn, subject(kind, confirmed.Name))
	note(out, fmt.Sprintf(
		msgLeaseInfo,
		session.RunID(),
		session.Lease().ID(),
		session.Lease().ExpiresAt().Format(time.RFC3339),
	))
	say(out, msgInjected)

	waitErr := hold_(ctx, session, hold)

	switch {
	case errors.Is(waitErr, context.Canceled):
		fmt.Fprintln(out)
		say(out, msgInterrupt)
	case waitErr != nil:
		fmt.Fprintln(out)
		event(out, markError, theme.StatusError, waitErr.Error())
	default:
		say(out, msgHoldOver)
	}

	revertErr := revert(withoutCancel(ctx, timeout), out, session)

	if errors.Is(waitErr, context.Canceled) {
		return errors.Join(waitErr, revertErr)
	}

	return errors.Join(skipCancellation(waitErr), revertErr)
}

func recoverInjection(
	ctx context.Context,
	out io.Writer,
	session *run.Session,
) {
	if failure := recover(); failure != nil {
		cleanup, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), run.CleanupTimeout,
		)
		defer cancel()
		if err := revert(cleanup, out, session); err != nil {
			panic(fmt.Errorf("%v; emergency rollback failed: %w", failure, err))
		}
		panic(failure)
	}
}

func hold_(
	ctx context.Context,
	session *run.Session,
	hold time.Duration,
) error {
	keepCtx, stop := context.WithCancel(ctx)
	renewals := make(chan error, 1)

	go func() {
		renewals <- session.Lease().Keep(keepCtx, func(time.Time) error { return session.Renew() })
	}()

	defer func() {
		stop()
		<-renewals
	}()

	var timer <-chan time.Time
	if hold > holdDisabled {
		t := time.NewTimer(hold)
		defer t.Stop()
		timer = t.C
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-renewals:
		renewals <- err
		return err
	case <-timer:
		return nil
	}
}

func withoutCancel(ctx context.Context, timeout time.Duration) context.Context {
	detached := context.WithoutCancel(ctx)
	if timeout <= 0 {
		return detached
	}
	bounded, cancel := context.WithTimeout(detached, timeout)
	context.AfterFunc(bounded, cancel)
	return bounded
}

func skipCancellation(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func revert(ctx context.Context, out io.Writer, session *run.Session) error {
	say(out, msgReverting)

	err := session.RevertAll(ctx, func(record journal.Record, failure error) {
		if failure != nil {
			event(
				out,
				markError,
				theme.StatusError,
				fmt.Sprintf(
					faultFormat,
					record.Kind,
					record.TargetName,
					failure,
				),
			)
			return
		}
		event(
			out,
			markRevert,
			theme.StatusOK,
			subject(record.Kind, record.TargetName),
		)
	})
	if err != nil {
		fmt.Fprintln(out)
		return err
	}

	event(out, markOK, theme.StatusOK, msgReverted)
	fmt.Fprintln(out)

	return nil
}
