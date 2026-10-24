// ©AngelaMos | 2026
// session_test.go

package run

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const (
	fakeKind  = "fake-fault"
	otherKind = "other-fault"
	ttl       = time.Minute
)

type fake struct {
	planned  int
	applied  int
	reverted int

	payload  json.RawMessage
	planErr  error
	applyErr error
	revertRe error

	journalAtApply []journal.Record
	path           string
	unconfirmable  bool

	// entered is closed when Apply begins and blocks until release is
	// closed, so a test can act on the journal with a mutation held INSIDE
	// its application.
	entered chan struct{}
	release chan struct{}
}

func (f *fake) Describe(
	inject.Env,
	dockerx.Target,
) string {
	return "a fake fault"
}

func (f *fake) Plan(
	context.Context,
	inject.Env,
	dockerx.Target,
) (json.RawMessage, error) {
	f.planned++
	return f.payload, f.planErr
}

func (f *fake) Apply(
	context.Context,
	inject.Env,
	dockerx.Target,
	json.RawMessage,
) error {
	f.applied++
	if f.path != "" {
		f.journalAtApply, _ = journal.Outstanding(f.path)
	}

	if f.entered != nil {
		close(f.entered)
		<-f.release
	}

	return f.applyErr
}

func (f *fake) Confirm(
	context.Context,
	inject.Env,
	dockerx.Target,
) (string, bool, error) {
	if f.unconfirmable {
		return "", false, nil
	}
	return "a fake confirmation", true, nil
}

func (f *fake) Revert(context.Context, inject.Env, journal.Record) error {
	f.reverted++
	return f.revertRe
}

func registryOf(mutators map[string]inject.Mutator) Registry {
	return func(kind string) (inject.Mutator, error) {
		mutator, ok := mutators[kind]
		if !ok {
			return nil, inject.ErrUnknownKind
		}
		return mutator, nil
	}
}

func tempJournal(t *testing.T) *journal.Journal {
	t.Helper()

	j, err := journal.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })

	return j
}

func target() dockerx.Target {
	return dockerx.Target{ID: "abc123", Name: "shop-api-1", Inspected: true}
}

func TestTheJournalIsWrittenBeforeTheFaultIsApplied(t *testing.T) {
	log := tempJournal(t)

	payload, err := journal.EncodePayload(
		map[string]string{"networks": "shop_default"},
	)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	mutator := &fake{payload: payload, path: log.Path()}
	session := newSessionWith(
		inject.Env{},
		log,
		ttl,
		registryOf(map[string]inject.Mutator{fakeKind: mutator}),
	)

	if err := session.Inject(
		context.Background(),
		fakeKind,
		target(),
	); err != nil {
		t.Fatalf("inject: %v", err)
	}

	if len(mutator.journalAtApply) != 1 {
		t.Fatalf(
			"the journal held %d outstanding records when Apply ran; it must already describe "+
				"the mutation, or a kill between the write and the apply is unrecoverable",
			len(mutator.journalAtApply),
		)
	}

	if mutator.journalAtApply[0].Phase != journal.PhasePending {
		t.Fatalf("the pre-apply record was phase %q, want %q",
			mutator.journalAtApply[0].Phase, journal.PhasePending)
	}

	var decoded map[string]string
	if err := mutator.journalAtApply[0].DecodePayload(&decoded); err != nil {
		t.Fatalf(
			"the pre-apply record carried no payload, so a revert from a cold start "+
				"would have nothing to restore: %v",
			err,
		)
	}

	if decoded["networks"] != "shop_default" {
		t.Fatalf("payload came back as %+v", decoded)
	}
}

func TestPlanRunsBeforeAnythingIsJournaledOrApplied(t *testing.T) {
	log := tempJournal(t)
	mutator := &fake{planErr: errors.New("cannot read the target")}

	session := newSessionWith(
		inject.Env{},
		log,
		ttl,
		registryOf(map[string]inject.Mutator{fakeKind: mutator}),
	)

	if err := session.Inject(
		context.Background(),
		fakeKind,
		target(),
	); err == nil {
		t.Fatal("a failing plan was treated as success")
	}

	if mutator.applied != 0 {
		t.Fatal("Apply ran after Plan failed")
	}

	outstanding, err := journal.Outstanding(log.Path())
	if err != nil {
		t.Fatalf("outstanding: %v", err)
	}

	if len(outstanding) != 0 {
		t.Fatalf("a failed plan left %d records behind", len(outstanding))
	}
}

func TestAFailedApplyStaysOutstandingAndIsReverted(t *testing.T) {
	log := tempJournal(t)
	mutator := &fake{applyErr: errors.New("daemon said no")}

	session := newSessionWith(
		inject.Env{},
		log,
		ttl,
		registryOf(map[string]inject.Mutator{fakeKind: mutator}),
	)

	if err := session.Inject(
		context.Background(),
		fakeKind,
		target(),
	); err == nil {
		t.Fatal("a failing apply was treated as success")
	}

	if err := session.RevertAll(context.Background(), nil); err != nil {
		t.Fatalf("revert: %v", err)
	}

	if mutator.reverted != 1 {
		t.Fatalf(
			"a mutation whose apply failed was reverted %d times; it may have partially "+
				"landed and must always be undone",
			mutator.reverted,
		)
	}
}

func TestRevertAllUndoesMostRecentFirst(t *testing.T) {
	log := tempJournal(t)

	first := &fake{}
	second := &fake{}
	session := newSessionWith(
		inject.Env{},
		log,
		ttl,
		registryOf(map[string]inject.Mutator{
			fakeKind:  first,
			otherKind: second,
		}),
	)

	ctx := context.Background()
	if err := session.Inject(ctx, fakeKind, target()); err != nil {
		t.Fatalf("inject first: %v", err)
	}
	if err := session.Inject(ctx, otherKind, target()); err != nil {
		t.Fatalf("inject second: %v", err)
	}

	var order []string
	if err := session.RevertAll(ctx, func(record journal.Record, _ error) {
		order = append(order, record.Kind)
	}); err != nil {
		t.Fatalf("revert: %v", err)
	}

	if len(order) != 2 || order[0] != otherKind || order[1] != fakeKind {
		t.Fatalf("reverted in order %v, want most recent first", order)
	}
}

func TestRevertAllContinuesPastAFailureAndReportsIt(t *testing.T) {
	log := tempJournal(t)

	broken := &fake{revertRe: errors.New("stuck")}
	working := &fake{}

	session := newSessionWith(
		inject.Env{},
		log,
		ttl,
		registryOf(map[string]inject.Mutator{
			fakeKind:  working,
			otherKind: broken,
		}),
	)

	ctx := context.Background()
	_ = session.Inject(ctx, fakeKind, target())
	_ = session.Inject(ctx, otherKind, target())

	err := session.RevertAll(ctx, nil)

	if !errors.Is(err, ErrRevertFailed) {
		t.Fatalf(
			"got %v, want an error wrapping ErrRevertFailed for the rollback exit code",
			err,
		)
	}

	if working.reverted != 1 {
		t.Fatal(
			"a failure on one mutation stopped the others from being reverted",
		)
	}
}

func TestAnAlreadyRevertedMutationIsNotRevertedTwice(t *testing.T) {
	log := tempJournal(t)
	mutator := &fake{}

	session := newSessionWith(
		inject.Env{},
		log,
		ttl,
		registryOf(map[string]inject.Mutator{fakeKind: mutator}),
	)

	ctx := context.Background()
	if err := session.Inject(ctx, fakeKind, target()); err != nil {
		t.Fatalf("inject: %v", err)
	}

	if err := session.RevertAll(ctx, nil); err != nil {
		t.Fatalf("first revert: %v", err)
	}
	if err := session.RevertAll(ctx, nil); err != nil {
		t.Fatalf("second revert: %v", err)
	}

	if mutator.reverted != 1 {
		t.Fatalf(
			"reverted %d times across two RevertAll calls, want 1",
			mutator.reverted,
		)
	}
}

func TestReclaimHonoursTheLease(t *testing.T) {
	log := tempJournal(t)
	mutator := &fake{}
	registry := registryOf(map[string]inject.Mutator{fakeKind: mutator})

	session := newSessionWith(inject.Env{}, log, time.Hour, registry)
	if err := session.Inject(
		context.Background(),
		fakeKind,
		target(),
	); err != nil {
		t.Fatalf("inject: %v", err)
	}

	live := reclaimWith(
		context.Background(),
		inject.Env{},
		log,
		time.Now().UTC(),
		true,
		registry,
	)
	if len(live.Results) != 0 {
		t.Fatal(
			"a fault with a live lease was reclaimed out from under the run holding it",
		)
	}

	expired := reclaimWith(context.Background(), inject.Env{}, log,
		time.Now().UTC().Add(2*time.Hour), true, registry)

	if len(expired.Results) != 1 {
		t.Fatalf(
			"an expired lease produced %d reclaims, want 1",
			len(expired.Results),
		)
	}
}

func TestReclaimIsIdempotent(t *testing.T) {
	log := tempJournal(t)
	mutator := &fake{}
	registry := registryOf(map[string]inject.Mutator{fakeKind: mutator})

	session := newSessionWith(inject.Env{}, log, ttl, registry)
	if err := session.Inject(
		context.Background(),
		fakeKind,
		target(),
	); err != nil {
		t.Fatalf("inject: %v", err)
	}

	for i := range 3 {
		sweep := reclaimWith(
			context.Background(),
			inject.Env{},
			log,
			time.Now().UTC(),
			false,
			registry,
		)
		if sweep.Failed() {
			t.Fatalf("sweep %d failed", i)
		}
	}

	if mutator.reverted != 1 {
		t.Fatalf("three reclaims reverted %d times, want 1", mutator.reverted)
	}
}

func TestRenewDoesNotResurrectAFaultSomethingElseReverted(t *testing.T) {
	log := tempJournal(t)
	mutator := &fake{}
	registry := registryOf(map[string]inject.Mutator{fakeKind: mutator})

	session := newSessionWith(inject.Env{}, log, ttl, registry)
	if err := session.Inject(
		context.Background(),
		fakeKind,
		target(),
	); err != nil {
		t.Fatalf("inject: %v", err)
	}

	sweep := reclaimWith(
		context.Background(),
		inject.Env{},
		log,
		time.Now().UTC(),
		false,
		registry,
	)
	if sweep.Failed() {
		t.Fatal("the simulated reaper failed")
	}

	if err := session.Renew(); !errors.Is(err, ErrFaultsTakenAway) {
		t.Fatalf(
			"got %v; a session whose faults were reverted elsewhere must stop renewing "+
				"and say so, not re-append applied records and make the mutation outstanding again",
			err,
		)
	}

	outstanding, err := journal.Outstanding(log.Path())
	if err != nil {
		t.Fatalf("outstanding: %v", err)
	}

	if len(outstanding) != 0 {
		t.Fatalf(
			"renewal resurrected %d reverted mutation(s)",
			len(outstanding),
		)
	}
}

func TestAnUnknownKindIsRefused(t *testing.T) {
	log := tempJournal(t)
	session := newSessionWith(inject.Env{}, log, ttl, registryOf(nil))

	if err := session.Inject(
		context.Background(),
		"nope",
		target(),
	); !errors.Is(
		err,
		inject.ErrUnknownKind,
	) {
		t.Fatalf("got %v, want ErrUnknownKind", err)
	}
}

// A mutation settled by the reaper while its own Apply is still running
// leaves a live fault that no later recovery can see, because Outstanding
// treats the reversion as terminal.
//
// The window is held open by a channel rather than a sleep, so this fails for
// the reason it names rather than on a slow machine.
func TestAMutationBeingAppliedIsNotSettledByTheReaper(t *testing.T) {
	log := tempJournal(t)

	mutator := &fake{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	registry := registryOf(map[string]inject.Mutator{fakeKind: mutator})

	// A lease far shorter than the application takes.
	session := newSessionWith(inject.Env{}, log, time.Millisecond, registry)

	done := make(chan error, 1)
	go func() {
		done <- session.Inject(context.Background(), fakeKind, target())
	}()

	<-mutator.entered

	// The reaper runs while Apply is still inside the mutator, with a clock
	// well past the lease.
	sweep := reclaimWith(
		context.Background(),
		inject.Env{},
		log,
		time.Now().UTC().Add(time.Hour),
		true,
		registry,
	)

	close(mutator.release)

	if err := <-done; err != nil {
		t.Fatalf("inject: %v", err)
	}

	if len(sweep.Results) == 0 {
		// The reaper left it alone, which is the outcome this test wants.
		// Nothing further to check.
		return
	}

	// It was reverted mid-apply. Then the fault MUST still be accounted for,
	// because Apply completed and the target is carrying it.
	live, err := journal.Outstanding(log.Path())
	if err != nil {
		t.Fatalf("outstanding: %v", err)
	}

	if len(live) == 0 {
		t.Fatalf(
			"the reaper reverted a mutation while it was still being applied, and the applied fault is now outstanding to nobody: %d record(s) reclaimed, 0 outstanding",
			len(sweep.Results),
		)
	}
}

// A mutation INSIDE its own Apply has to be renewable, or its durable expiry
// lapses while the work is in flight.
func TestAMutationIsRenewableWhileItIsStillBeingApplied(t *testing.T) {
	log := tempJournal(t)

	mutator := &fake{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	registry := registryOf(map[string]inject.Mutator{fakeKind: mutator})

	session := newSessionWith(inject.Env{}, log, time.Hour, registry)

	done := make(chan error, 1)
	go func() {
		done <- session.Inject(context.Background(), fakeKind, target())
	}()

	<-mutator.entered

	before := expiryOf(t, log.Path())

	if err := session.Renew(); err != nil {
		t.Fatalf("renew: %v", err)
	}

	after := expiryOf(t, log.Path())

	close(mutator.release)

	if err := <-done; err != nil {
		t.Fatalf("inject: %v", err)
	}

	if !after.After(before) {
		t.Fatalf(
			"the expiry of a mutation still inside its Apply did not move (%s -> %s), so the reaper is free to revert it mid-application",
			before,
			after,
		)
	}
}

// And a renewal has to SAY it is a renewal: while it is indistinguishable
// from an application, a reversion can never be safely re-opened by a real
// one.
func TestARenewalIsJournaledAsARenewalNotAnApplication(t *testing.T) {
	log := tempJournal(t)
	registry := registryOf(map[string]inject.Mutator{fakeKind: &fake{}})

	session := newSessionWith(inject.Env{}, log, time.Hour, registry)

	if err := session.Inject(
		context.Background(),
		fakeKind,
		target(),
	); err != nil {
		t.Fatalf("inject: %v", err)
	}

	if err := session.Renew(); err != nil {
		t.Fatalf("renew: %v", err)
	}

	records, _ := journal.Replay(log.Path())
	if len(records) == 0 {
		t.Fatal("the journal is empty")
	}

	last := records[len(records)-1]

	if last.Phase != journal.PhaseRenewed {
		t.Fatalf(
			"a renewal was journaled as %q, want %q: while a renewal is indistinguishable from an application, a reversion can never be safely re-opened by a real one",
			last.Phase,
			journal.PhaseRenewed,
		)
	}
}

// expiryOf reads the latest expiry the journal carries for any outstanding
// mutation.
func expiryOf(t *testing.T, path string) time.Time {
	t.Helper()

	records, _ := journal.Replay(path)

	var latest time.Time
	for _, record := range records {
		if record.ExpiresAt.After(latest) {
			latest = record.ExpiresAt
		}
	}

	return latest
}
