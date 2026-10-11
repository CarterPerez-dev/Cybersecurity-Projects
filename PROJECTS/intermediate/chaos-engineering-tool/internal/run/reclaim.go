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

// settleSuffix mirrors statedir.Paths.Settle. The journal knows its own path and
// the lock sits beside it, so the two cannot drift to different files.
const settleSuffix = ".settle"

type Reclaimed struct {
	Record journal.Record
	Err    error
}

var ErrOtherDaemon = errors.New("that fault belongs to a different Docker daemon")

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

// Reclaim settles outstanding mutations. It holds the settle lock for the whole
// pass, so a renewal cannot read a record as live, stall, and then write back a
// fresh expiry for a fault this sweep has already undone — nor can this sweep
// revert a fault a renewal extended a moment earlier.
//
// The lock is advisory and best-effort: if it cannot be taken, the sweep still
// runs. A dead man's switch that refuses to fire because a lock file is
// unavailable is worse than one that races.
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

	sweep := Sweep{Results: make([]Reclaimed, 0, len(outstanding)), Damage: damage}

	for i := len(outstanding) - 1; i >= 0; i-- {
		record := outstanding[i]

		if expiredOnly && !record.Expired(now) {
			continue
		}

		// A fault on another daemon is left ALONE, and left outstanding.
		//
		// Reverting it here cannot work and does not fail cleanly: the container
		// ID does not exist on this daemon, the SDK says NotFound, khaos reads
		// that as "the target is gone so the fault went with it" and writes
		// REVERTED. The fault stays applied on the machine that actually has it
		// and no later sweep will ever look at it again.
		//
		// An empty daemon on the record is ambiguous rather than matching. It
		// predates this field or the daemon would not identify itself, and
		// settling it on a guess is the same irreversible mistake.
		if mismatch := daemonMismatch(record, attachedDaemon(env)); mismatch != nil {
			sweep.Results = append(sweep.Results, Reclaimed{Record: record, Err: mismatch})
			continue
		}

		sweep.Results = append(sweep.Results, Reclaimed{
			Record: record,
			Err:    revertWith(ctx, env, log, record, lookup),
		})
	}

	return sweep
}

// attachedDaemon is the identity of the daemon this sweep is attached to, or
// empty when there is no client.
func attachedDaemon(env inject.Env) string {
	if env.Docker == nil {
		return ""
	}
	return env.Docker.Daemon()
}

// daemonMismatch reports why this sweep must not touch a record, or nil when it
// may.
func daemonMismatch(record journal.Record, here string) error {
	// Unknown on either side is AMBIGUOUS, not a match and not a mismatch. A
	// record predating this field, or a daemon that would not identify itself,
	// gets the benefit of the doubt and is reverted: refusing instead would
	// strand every fault written before this existed.
	if here == "" || record.Daemon == "" {
		return nil
	}

	if record.Daemon == here {
		return nil
	}

	return fmt.Errorf(errOtherDaemon, ErrOtherDaemon,
		journal.ShortDaemon(record.Daemon), journal.ShortDaemon(here))
}
