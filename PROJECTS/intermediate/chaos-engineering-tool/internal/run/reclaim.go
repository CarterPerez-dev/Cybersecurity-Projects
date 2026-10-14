// ©AngelaMos | 2026
// reclaim.go

package run

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/lock"
)

// settleSuffix mirrors statedir.Paths.Settle.
const settleSuffix = ".settle"

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

// Reclaim settles outstanding mutations, holding the settle lock for the whole
// pass so a renewal and a sweep cannot undo each other's work. The lock is
// best-effort: a dead man's switch that will not fire is worse than one that
// races.
func Reclaim(
	ctx context.Context,
	env inject.Env,
	log *journal.Journal,
	now time.Time,
	expiredOnly bool,
) Sweep {
	if settle, err := lock.Acquire(log.Path() + settleSuffix); err == nil {
		defer func() { _ = settle.Release() }()
	}

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

		sweep.Results = append(sweep.Results, Reclaimed{
			Record: record,
			Err:    revertWith(ctx, env, log, record, lookup),
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
