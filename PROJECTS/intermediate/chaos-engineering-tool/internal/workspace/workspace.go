// ©AngelaMos | 2026
// workspace.go

package workspace

import (
	"context"
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
	// Reconciled is what the startup sweep of EXPIRED orphans did, so a command
	// can tell the operator that khaos cleaned up before it started rather than
	// leaving it to be discovered later.
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

	// The promise `khaos inject --ttl` makes is "before `khaos reap` or the next
	// khaos invocation reclaims it". Nothing implemented the second half: only
	// the explicit reclaim command and the reap loop ever called run.Reclaim, so
	// a fault whose controller was killed outlived its TTL indefinitely unless
	// the operator happened to run one of those two commands.
	//
	// EXPIRED leases only, and only on an exclusive open. A live lease belongs to
	// a session that is still running and reverting it would steal another run's
	// fault out from under it; a shared open is a read-only command and must not
	// mutate anything. That is the same split `khaos reap` already uses.
	if exclusive {
		work.Reconciled = run.Reclaim(ctx, work.Env(), log, time.Now().UTC(), true)
	}

	return work, nil
}

func (w *Workspace) Env() inject.Env {
	return inject.Env{Docker: w.Docker}
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
