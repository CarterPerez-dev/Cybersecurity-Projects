// ©AngelaMos | 2026
// reclaim.go

package run

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/lock"
)

// settleSuffix mirrors statedir.Paths.Settle.
const settleSuffix = ".settle"

const CleanupTimeout = 30 * time.Second

func holdSettle(ctx context.Context, path string) (func(), error) {
	bounded, cancel := context.WithTimeout(ctx, CleanupTimeout)
	defer cancel()
	held, err := lock.AcquireContext(bounded, path+settleSuffix)
	if err != nil {
		return nil, err
	}
	return func() { _ = held.Release() }, nil
}

func mutationPath(path, id string) string {
	return fmt.Sprintf("%s.%x.active", path, sha256.Sum256([]byte(id)))
}

type Reclaimed struct {
	Record journal.Record
	Err    error
}

var ErrOtherDaemon = errors.New(
	"that fault belongs to a different Docker daemon",
)

const errOtherDaemon = "%w: it was applied on %s and khaos is attached to %s; point khaos at that daemon and reclaim there"

type Sweep struct {
	Results []Reclaimed
	Damage  error
}

func (s Sweep) Failed() bool {
	for _, result := range s.Results {
		if result.Err != nil {
			return true
		}
	}
	return false
}

func (s Sweep) Succeeded() int {
	succeeded := 0
	for _, result := range s.Results {
		if result.Err == nil {
			succeeded++
		}
	}
	return succeeded
}

func Reclaim(
	ctx context.Context,
	env inject.Env,
	log *journal.Journal,
	now time.Time,
	expiredOnly bool,
) Sweep {
	release, err := holdSettle(ctx, log.Path())
	if err != nil {
		return Sweep{Damage: err}
	}
	defer release()

	return reclaimWith(ctx, env, log, now, expiredOnly, inject.Lookup)
}

func reclaimWith(
	ctx context.Context,
	env inject.Env,
	log *journal.Journal,
	now time.Time,
	expiredOnly bool,
	lookup Registry,
) Sweep {
	outstanding, damage := journal.Outstanding(log.Path())

	sweep := Sweep{
		Results: make([]Reclaimed, 0, len(outstanding)),
		Damage:  damage,
	}

	for i := len(outstanding) - 1; i >= 0; i-- {
		record := outstanding[i]

		if expiredOnly && !record.Expired(now) {
			continue
		}

		active, err := lock.Acquire(mutationPath(log.Path(), record.MutationID))
		if errors.Is(err, lock.ErrHeld) {
			continue
		}
		if err != nil {
			sweep.Results = append(
				sweep.Results, Reclaimed{Record: record, Err: err},
			)
			continue
		}
		_ = active.Release()

		// A fault on another daemon is left outstanding. Reverting it here
		// would not fail cleanly: the ID is NotFound on this daemon, which
		// khaos would read as the target being gone and write REVERTED.
		if mismatch := daemonMismatch(
			record,
			attachedDaemon(env),
		); mismatch != nil {
			sweep.Results = append(
				sweep.Results,
				Reclaimed{Record: record, Err: mismatch},
			)
			continue
		}

		cleanup, cancel := context.WithTimeout(ctx, CleanupTimeout)
		err = revertWith(cleanup, env, log, record, lookup)
		cancel()
		sweep.Results = append(sweep.Results, Reclaimed{
			Record: record,
			Err:    err,
		})
	}

	return sweep
}

func attachedDaemon(env inject.Env) string {
	if env.Docker == nil {
		return ""
	}
	return env.Docker.Daemon()
}

// daemonMismatch reports why this sweep must not touch a record. Unknown on
// either side gets the benefit of the doubt, or every record written before
// the field existed would be stranded.
func daemonMismatch(record journal.Record, here string) error {
	if here == "" || record.Daemon == "" {
		return nil
	}

	if record.Daemon == here {
		return nil
	}

	return fmt.Errorf(errOtherDaemon, ErrOtherDaemon,
		journal.ShortDaemon(record.Daemon), journal.ShortDaemon(here))
}
