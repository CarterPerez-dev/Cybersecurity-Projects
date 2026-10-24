// ©AngelaMos | 2026
// workspace.go

package workspace

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/lock"
	"github.com/CarterPerez-dev/khaos/internal/run"
	"github.com/CarterPerez-dev/khaos/internal/statedir"
)

const errDockerHint = "%w (run `khaos doctor` for the fix)"

type Workspace struct {
	// Reconciled is what the startup sweep of EXPIRED orphans did.
	Reconciled run.Sweep

	Docker  *dockerx.Client
	Journal *journal.Journal
	Paths   statedir.Paths

	held *lock.Lock
}

func OpenExclusive(ctx context.Context) (*Workspace, error) {
	return open(ctx, true)
}

func OpenShared(ctx context.Context) (*Workspace, error) {
	return open(ctx, false)
}

func open(ctx context.Context, exclusive bool) (*Workspace, error) {
	paths, err := statedir.Default()
	if err != nil {
		return nil, err
	}

	var held *lock.Lock
	if exclusive {
		if held, err = lock.Acquire(paths.Lock()); err != nil {
			return nil, err
		}
	}

	log, err := journal.Open(paths.Journal())
	if err != nil {
		release(held)
		return nil, err
	}

	client, err := dockerx.Open(ctx)
	if err != nil {
		_ = log.Close()
		release(held)
		return nil, fmt.Errorf(errDockerHint, err)
	}

	work := &Workspace{Docker: client, Journal: log, Paths: paths, held: held}

	// The half of the `--ttl` promise that says "or the next khaos invocation
	// reclaims it". Expired leases only, and only on an exclusive open: a live
	// lease belongs to a session that is still running.
	if exclusive {
		work.Reconciled = run.Reclaim(
			ctx,
			work.Env(),
			log,
			time.Now().UTC(),
			true,
		)
	}

	return work, nil
}

func (w *Workspace) Env() inject.Env {
	return inject.Env{Docker: w.Docker}
}

func (w *Workspace) RequireClean() error {
	failures := []error{w.Reconciled.Damage}
	for _, result := range w.Reconciled.Results {
		if result.Err != nil {
			failures = append(failures, result.Err)
		}
	}
	if err := errors.Join(failures...); err != nil {
		return errors.Join(run.ErrRevertFailed, err)
	}
	live, err := journal.Outstanding(w.Journal.Path())
	if err != nil {
		return errors.Join(run.ErrRevertFailed, err)
	}
	for _, record := range live {
		if w.Docker != nil && record.Daemon != "" &&
			record.Daemon != w.Docker.Daemon() {
			continue
		}
		return fmt.Errorf(
			"%w: %s on %s remains outstanding",
			run.ErrRevertFailed, record.Kind, record.TargetName,
		)
	}
	return nil
}

func (w *Workspace) Close() {
	_ = w.Docker.Close()
	_ = w.Journal.Close()
	release(w.held)
}

func release(held *lock.Lock) {
	if held != nil {
		_ = held.Release()
	}
}
