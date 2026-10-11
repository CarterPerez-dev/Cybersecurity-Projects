// ©AngelaMos | 2026
// session.go

package run

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/lease"
	"github.com/CarterPerez-dev/khaos/internal/lock"
)

const (
	errPlan   = "plan %s for %s: %w"
	errApply  = "apply %s to %s: %w"
	errRevert = "revert %s on %s: %w"

	detailTargetGone = "the container no longer exists, so the fault went with it"
	detailTakenAway  = "another process reverted this fault before this run finished with it"
)

var ErrFaultsTakenAway = errors.New(
	"every fault this run was holding was reverted by something else, so the run no longer controls what it is measuring",
)

var ErrRevertFailed = errors.New(
	"one or more faults could not be reverted; run `khaos reclaim` once the cause is fixed",
)

type Progress func(record journal.Record, err error)

type Registry func(kind string) (inject.Mutator, error)

type Session struct {
	env    inject.Env
	log    *journal.Journal
	lease  *lease.Lease
	runID  string
	lookup Registry

	mu        sync.Mutex
	mutations []journal.Record
}

func NewSession(
	env inject.Env,
	log *journal.Journal,
	ttl time.Duration,
) *Session {
	return newSessionWith(env, log, ttl, inject.Lookup)
}

func newSessionWith(
	env inject.Env,
	log *journal.Journal,
	ttl time.Duration,
	lookup Registry,
) *Session {
	return &Session{
		env:    env,
		log:    log,
		lease:  lease.New(ttl),
		runID:  journal.NewID(),
		lookup: lookup,
	}
}

// daemon is the identity of the daemon this session is attached to, or empty
// when there is none. A session built without a client is a test session; an
// empty value is already the "khaos could not establish it" case the reclaim
// path treats as ambiguous rather than as a match.
func (s *Session) daemon() string {
	if s.env.Docker == nil {
		return ""
	}
	return s.env.Docker.Daemon()
}

func (s *Session) RunID() string {
	return s.runID
}

func (s *Session) Lease() *lease.Lease {
	return s.lease
}

func (s *Session) Inject(
	ctx context.Context,
	kind string,
	target dockerx.Target,
) error {
	mutator, err := s.lookup(kind)
	if err != nil {
		return err
	}

	payload, err := mutator.Plan(ctx, s.env, target)
	if err != nil {
		return fmt.Errorf(errPlan, kind, target.Name, err)
	}

	record := journal.Record{
		MutationID: journal.NewID(),
		RunID:      s.runID,
		LeaseID:    s.lease.ID(),
		Kind:       kind,
		Daemon:     s.daemon(),
		TargetID:   target.ID,
		TargetName: target.Name,
		Payload:    payload,
		Phase:      journal.PhasePending,
		ExpiresAt:  s.lease.ExpiresAt(),
	}

	if err := s.log.Append(record); err != nil {
		return err
	}

	applyErr := mutator.Apply(ctx, s.env, target, payload)
	record.At = time.Now().UTC()

	if applyErr != nil {
		record.Phase = journal.PhaseFailed
		record.Detail = applyErr.Error()
		s.remember(record)
		if err := s.log.Append(record); err != nil {
			return err
		}
		return fmt.Errorf(errApply, kind, target.Name, applyErr)
	}

	record.Phase = journal.PhaseApplied
	s.remember(record)

	return s.log.Append(record)
}

// Renew re-reads the journal before extending the lease. A mutation that some
// other process already reverted is dropped rather than resurrected, and a
// session whose faults have all been taken away stops renewing and says so,
// instead of continuing to claim a fault it no longer holds.
func (s *Session) Renew() error {
	// The same settle lock Reclaim takes. Reading the outstanding set and
	// appending the renewal are two operations, and the reaper runs beside this
	// deliberately: without the lock a renewal could read a record as live,
	// stall while a sweep reverted it, and then write back a fresh expiry.
	if settle, err := lock.Acquire(s.log.Path() + settleSuffix); err == nil {
		defer func() { _ = settle.Release() }()
	}

	live, err := journal.Outstanding(s.log.Path())
	if err != nil {
		return err
	}

	stillOutstanding := make(map[string]bool, len(live))
	for _, record := range live {
		stillOutstanding[record.MutationID] = true
	}

	expiry := s.lease.Renew()

	records, dropped := s.renewable(expiry, stillOutstanding)
	for _, record := range records {
		if err := s.log.Append(record); err != nil {
			return err
		}
	}

	if dropped > 0 && len(records) == 0 {
		return ErrFaultsTakenAway
	}

	return nil
}

func (s *Session) RevertAll(ctx context.Context, progress Progress) error {
	var firstErr error

	for _, record := range s.outstanding() {
		err := revertWith(ctx, s.env, s.log, record, s.lookup)
		s.settle(record.MutationID, err)

		if progress != nil {
			progress(record, err)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if firstErr != nil {
		// ErrRevertFailed is what callers branch on, and khaos's exit policy
		// ranks it above every other outcome. The first underlying failure is
		// diagnostic text for the operator, not a second identity to match.
		//nolint:errorlint // %v is deliberate
		return fmt.Errorf("%w: %v", ErrRevertFailed, firstErr)
	}

	return nil
}

func (s *Session) settle(mutationID string, failure error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.mutations {
		if s.mutations[i].MutationID != mutationID {
			continue
		}
		if failure != nil {
			s.mutations[i].Phase = journal.PhaseFailed
			s.mutations[i].Detail = failure.Error()
			continue
		}
		s.mutations[i].Phase = journal.PhaseReverted
		s.mutations[i].Detail = ""
	}
}

func (s *Session) remember(record journal.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutations = append(s.mutations, record)
}

func (s *Session) renewable(
	expiry time.Time,
	stillOutstanding map[string]bool,
) ([]journal.Record, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]journal.Record, 0, len(s.mutations))
	now := time.Now().UTC()
	dropped := 0

	for i := range s.mutations {
		if s.mutations[i].Phase != journal.PhaseApplied {
			continue
		}

		if !stillOutstanding[s.mutations[i].MutationID] {
			s.mutations[i].Phase = journal.PhaseReverted
			s.mutations[i].Detail = detailTakenAway
			dropped++
			continue
		}

		s.mutations[i].ExpiresAt = expiry
		s.mutations[i].At = now
		out = append(out, s.mutations[i])
	}

	return out, dropped
}

func (s *Session) outstanding() []journal.Record {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]journal.Record, 0, len(s.mutations))
	for i := len(s.mutations) - 1; i >= 0; i-- {
		if s.mutations[i].Outstanding() {
			out = append(out, s.mutations[i])
		}
	}

	return out
}

func Revert(
	ctx context.Context,
	env inject.Env,
	log *journal.Journal,
	record journal.Record,
) error {
	return revertWith(ctx, env, log, record, inject.Lookup)
}

func revertWith(
	ctx context.Context,
	env inject.Env,
	log *journal.Journal,
	record journal.Record,
	lookup Registry,
) error {
	mutator, err := lookup(record.Kind)
	if err != nil {
		return err
	}

	record.At = time.Now().UTC()

	switch err := mutator.Revert(ctx, env, record); {
	case err == nil:
		record.Phase = journal.PhaseReverted
		record.Detail = ""
	case errors.Is(err, dockerx.ErrContainerGone):
		record.Phase = journal.PhaseReverted
		record.Detail = detailTargetGone
	default:
		record.Phase = journal.PhaseFailed
		record.Detail = err.Error()
		_ = log.Append(record)
		return fmt.Errorf(errRevert, record.Kind, record.TargetName, err)
	}

	return log.Append(record)
}

func (s *Session) Confirm(
	ctx context.Context,
	kind string,
	target dockerx.Target,
) (string, error) {
	mutator, err := s.lookup(kind)
	if err != nil {
		return "", err
	}

	method, confirmed, err := mutator.Confirm(ctx, s.env, target)
	if err != nil {
		return "", err
	}

	if !confirmed {
		return "", nil
	}

	return method, nil
}
