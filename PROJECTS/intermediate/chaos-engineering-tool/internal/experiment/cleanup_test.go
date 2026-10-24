// ©AngelaMos | 2026
// cleanup_test.go

package experiment

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

func TestEngineRevertsAfterPanicInFaultLifecycle(t *testing.T) {
	for _, stage := range []Stage{StageConfirm, StageObserve, StageRevert} {
		t.Run(string(stage), func(t *testing.T) {
			faulted, calls := false, 0
			injector := &scriptedInjector{faulted: &faulted}
			engine := Engine{Injector: injector, Report: func(event Event) {
				if event.Stage == stage {
					panic("fault lifecycle failed")
				}
			}}
			defer func() {
				if recover() == nil {
					t.Error("panic was swallowed")
				}
				if faulted || injector.reverts != 1 {
					t.Errorf(
						"faulted=%v, reverts=%d", faulted, injector.reverts,
					)
				}
			}()
			_, _ = engine.Run(context.Background(), spec(
				scriptedProbe{
					probe.Valid,
					probe.Accepted,
					probe.Accepted,
					&faulted,
					&calls,
				},
				scriptedProbe{
					probe.Invalid,
					probe.Rejected,
					probe.Rejected,
					&faulted,
					&calls,
				},
			))
		})
	}
}

type blockedRollback struct {
	scriptedInjector
}

func (b *blockedRollback) Revert(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestRollbackDetachesCancellationButRetainsADeadline(t *testing.T) {
	engine := Engine{
		Injector: &blockedRollback{}, RollbackTimeout: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	started := time.Now()
	err := engine.rollback(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("rollback error = %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("rollback exceeded its bound")
	}
}

type canceledConfirmation struct {
	scriptedInjector
	cancel context.CancelFunc
}

func (c *canceledConfirmation) Confirm(context.Context) (string, error) {
	c.cancel()
	return "", context.Canceled
}

func TestConfirmationCancellationRecordsInterruptedAndReverts(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	faulted, calls := false, 0
	injector := &canceledConfirmation{
		scriptedInjector: scriptedInjector{faulted: &faulted}, cancel: cancel,
	}
	experiment := spec(
		scriptedProbe{
			probe.Valid, probe.Accepted, probe.Accepted, &faulted, &calls,
		},
		scriptedProbe{
			probe.Invalid, probe.Rejected, probe.Rejected, &faulted, &calls,
		},
	)
	result, err := (Engine{Injector: injector}).Run(ctx, experiment)
	if !errors.Is(err, context.Canceled) ||
		result.Verdict.Epistemic != Interrupted || faulted {
		t.Fatalf("canceled confirmation: %v, %+v", err, result.Verdict)
	}
}
