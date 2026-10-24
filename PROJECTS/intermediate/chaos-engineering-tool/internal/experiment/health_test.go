// ©AngelaMos | 2026
// health_test.go

package experiment

import (
	"context"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

func TestHealthStopRevertsAndPreservesMeasuredBypass(t *testing.T) {
	faulted, calls, shifted := false, 0, false
	injector := &scriptedInjector{faulted: &faulted}
	experiment := spec(
		scriptedProbe{
			probe.Valid, probe.Accepted, probe.Accepted, &faulted, &calls,
		},
		scriptedProbe{
			probe.Invalid, probe.Rejected, probe.Accepted, &faulted, &calls,
		},
	)
	experiment.AbortAfter = 2
	experiment.Timing.FaultFor = time.Second
	experiment.IdleFor = time.Second
	experiment.Shift = func(context.Context) error { shifted = true; return nil }
	result, err := (Engine{Injector: injector}).Run(t.Context(), experiment)
	if err != nil {
		t.Fatal(err)
	}
	if faulted || injector.reverts != 1 || shifted {
		t.Fatalf(
			"faulted=%v reverts=%d shifted=%v",
			faulted,
			injector.reverts,
			shifted,
		)
	}
	if result.Observation.HaltReason == "" ||
		result.Observation.Fault.Paired() != 2 {
		t.Fatalf("stop not recorded: %+v", result.Observation)
	}
	observed := result.Observation.FaultFor
	if observed <= 0 || observed >= experiment.Timing.FaultFor {
		t.Fatalf("early stop recorded %s of %s", observed,
			experiment.Timing.FaultFor)
	}
	if !result.Verdict.Defect || result.Verdict.Direction != Permitted {
		t.Fatalf("measured bypass was lost: %+v", result.Verdict)
	}
	if result.Observation.Resumed.Requests() != 0 ||
		result.Observation.Recovery.Requests() == 0 {
		t.Fatal("stop must skip later fault phases and measure recovery")
	}
}

func TestHealthStopRequiresConsecutiveFailures(t *testing.T) {
	stop := healthStop{limit: 2}
	for _, failed := range []bool{true, false, true} {
		if stop.reached(failed) {
			t.Fatal("nonconsecutive failures stopped the run")
		}
	}
	if !stop.reached(true) {
		t.Fatal("consecutive failures did not stop the run")
	}
	disabled := healthStop{}
	for range 10 {
		if disabled.reached(true) {
			t.Fatal("default health policy stopped the run")
		}
	}
}

type shiftedHealthInjector struct {
	scriptedInjector
	shifted *bool
}

func (i *shiftedHealthInjector) Revert(ctx context.Context) error {
	*i.shifted = false
	return i.scriptedInjector.Revert(ctx)
}

func TestStoppingALaterWindowPreservesThePrimaryDuration(t *testing.T) {
	faulted, shifted, calls := false, false, 0
	injector := &shiftedHealthInjector{
		scriptedInjector: scriptedInjector{
			faulted: &faulted,
		},
		shifted: &shifted,
	}
	experiment := spec(
		scriptedProbe{
			probe.Valid, probe.Accepted, probe.Accepted, &faulted, &calls,
		},
		scriptedProbe{
			probe.Invalid, probe.Rejected, probe.Accepted, &shifted, &calls,
		},
	)
	experiment.AbortAfter = 2
	experiment.Timing.FaultFor = 50 * time.Millisecond
	experiment.Shift = func(context.Context) error { shifted = true; return nil }
	result, err := (Engine{Injector: injector}).Run(t.Context(), experiment)
	if err != nil {
		t.Fatal(err)
	}
	if result.Observation.HaltReason == "" ||
		result.Observation.Shift.Paired() != 2 || faulted || shifted ||
		injector.reverts != 1 {
		t.Fatalf("second-phase health stop: %+v", result.Observation)
	}
	if result.Observation.FaultFor < experiment.Timing.FaultFor {
		t.Fatalf("later window replaced the primary duration: %s",
			result.Observation.FaultFor)
	}
}
