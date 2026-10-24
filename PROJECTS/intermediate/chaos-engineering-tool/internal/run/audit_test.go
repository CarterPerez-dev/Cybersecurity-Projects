// ©AngelaMos | 2026
// audit_test.go

package run

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

func TestMissingContainerDoesNotSettlePersistentResources(t *testing.T) {
	for _, kind := range []string{inject.KindPause, inject.KindCredentialTier, "secret-unreadable"} {
		t.Run(kind, func(t *testing.T) {
			log := tempJournal(t)
			mutator := &fake{revertRe: dockerx.ErrContainerGone}
			registry := registryOf(map[string]inject.Mutator{kind: mutator})
			session := newSessionWith(inject.Env{}, log, time.Minute, registry)
			if err := session.Inject(t.Context(), kind, target()); err != nil {
				t.Fatal(err)
			}
			err := session.RevertAll(t.Context(), nil)
			if (err == nil) != (kind == inject.KindPause) {
				t.Fatalf("revert %s: %v", kind, err)
			}
			live, err := journal.Outstanding(log.Path())
			if err != nil || (len(live) == 0) != (kind == inject.KindPause) {
				t.Fatalf("outstanding %s: %v, %v", kind, live, err)
			}
		})
	}
}

func TestCompletedApplyKeepsRenewedExpiry(t *testing.T) {
	for _, fails := range []bool{false, true} {
		name := map[bool]string{false: "success", true: "partial failure"}[fails]
		t.Run(name, func(t *testing.T) {
			log := tempJournal(t)
			mutator := &fake{
				entered: make(chan struct{}), release: make(chan struct{}),
			}
			if fails {
				mutator.applyErr = errors.New("partial application")
			}
			registry := registryOf(map[string]inject.Mutator{fakeKind: mutator})
			session := newSessionWith(inject.Env{}, log, time.Hour, registry)
			done := make(chan error, 1)
			go func() {
				done <- session.Inject(context.Background(), fakeKind, target())
			}()
			<-mutator.entered
			if err := session.Renew(); err != nil {
				t.Fatal(err)
			}
			renewed := session.Lease().ExpiresAt()
			close(mutator.release)
			if err := <-done; (err != nil) != fails {
				t.Fatalf("apply: %v", err)
			}
			live, err := journal.Outstanding(log.Path())
			if err != nil || len(live) != 1 {
				t.Fatalf("outstanding: %v, %v", live, err)
			}
			if live[0].ExpiresAt.Before(renewed) {
				t.Fatalf(
					"application lost renewal: %s < %s",
					live[0].ExpiresAt,
					renewed,
				)
			}
		})
	}
}

func TestReaperCannotSettleAnInFlightPartialApplication(t *testing.T) {
	log := tempJournal(t)
	mutator := &fake{
		entered: make(chan struct{}), release: make(chan struct{}),
		applyErr: errors.New("changed state before failing"),
	}
	registry := registryOf(map[string]inject.Mutator{fakeKind: mutator})
	session := newSessionWith(inject.Env{}, log, time.Minute, registry)
	done := make(chan error, 1)
	go func() {
		done <- session.Inject(context.Background(), fakeKind, target())
	}()
	<-mutator.entered
	sweep := reclaimWith(context.Background(), inject.Env{}, log,
		time.Now().Add(time.Hour), true, registry)
	close(mutator.release)
	if err := <-done; err == nil {
		t.Fatal("partial application unexpectedly succeeded")
	}
	if len(sweep.Results) != 0 || mutator.reverted != 0 {
		t.Fatal("recovery entered the mutator while its application was active")
	}
	live, err := journal.Outstanding(log.Path())
	if err != nil || len(live) != 1 {
		t.Fatalf("partial application disappeared: %v, %v", live, err)
	}
	if err := session.RevertAll(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if mutator.reverted != 1 {
		t.Fatal("completed application was not recoverable")
	}
}

func TestCredentialLifetimeRemainsJournaledThroughRecovery(t *testing.T) {
	log := tempJournal(t)
	resource, fault := &fake{}, &fake{}
	registry := registryOf(map[string]inject.Mutator{
		inject.KindCredentialTier: resource,
		fakeKind:                  fault,
	})
	session := newSessionWith(inject.Env{}, log, time.Hour, registry)
	for _, kind := range []string{inject.KindCredentialTier, fakeKind} {
		if err := session.Inject(t.Context(), kind, target()); err != nil {
			t.Fatal(err)
		}
	}
	if err := session.RevertFaults(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	live, err := journal.Outstanding(log.Path())
	if err != nil || len(live) != 1 ||
		live[0].Kind != inject.KindCredentialTier || resource.reverted != 0 {
		t.Fatalf(
			"credential lifetime settled before recovery: %v, %v", live, err,
		)
	}
	if err := session.Renew(); err != nil {
		t.Fatal(err)
	}
	resource.revertRe = errors.New("role removal failed")
	revertErr := session.RevertAll(t.Context(), nil)
	if !errors.Is(revertErr, ErrRevertFailed) {
		t.Fatalf("cleanup failure suppressed: %v", revertErr)
	}
	live, err = journal.Outstanding(log.Path())
	if err != nil || len(live) != 1 {
		t.Fatalf("failed role cleanup lost its obligation: %v, %v", live, err)
	}
	resource.revertRe = nil
	if err := session.RevertAll(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	live, err = journal.Outstanding(log.Path())
	if err != nil || len(live) != 0 {
		t.Fatalf("finished cleanup remains outstanding: %v, %v", live, err)
	}
}
