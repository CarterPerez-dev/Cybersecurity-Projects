// ©AngelaMos | 2026
// throttled_test.go

package experiment

import (
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

// A rate limiter never inspects the credential it is asked about, so its
// negative control is the request over the budget and its refusal is a 429.
// Three guards read the invalid stream, and each test below pins one of them
// against both a declared and an undeclared experiment: without the
// declaration the old behaviour must still hold, or this is a blanket
// loosening rather than a declared one.

var throttles = []probe.Disposition{probe.Throttled}

// limiterBaseline is a limiter enforcing its budget.
func limiterBaseline() probe.Window {
	return probe.Window{
		Valid: stream(probe.Valid, repeat(probe.Accepted, MinimumPaired)...),
		Invalid: stream(
			probe.Invalid,
			repeat(probe.Throttled, MinimumPaired)...),
	}
}

func TestABaselineRefusedWithAThrottleCountsAsEnforcement(t *testing.T) {
	reason, unmet := baselineUnmet(
		limiterBaseline(),
		"",
		false,
		closedWhen(Observation{ClosedWhen: throttles}),
	)
	if unmet {
		t.Fatalf(
			"a limiter that throttled every over-budget request was read as never enforcing: %s",
			reason,
		)
	}
}

func TestAThrottledBaselineIsStillUnmetWhenNothingDeclaresIt(t *testing.T) {
	if _, unmet := baselineUnmet(
		limiterBaseline(),
		"",
		false,
		closedWhen(Observation{}),
	); !unmet {
		t.Fatal(
			"an experiment that declared no refusal beyond Rejected accepted a throttle as enforcement, so the set is not being read at all",
		)
	}
}

// The declared set extends Rejected rather than replacing it.
func TestADeclaredSetStillAcceptsAnOrdinaryRejection(t *testing.T) {
	if _, unmet := baselineUnmet(
		healthyBaseline(),
		"",
		false,
		closedWhen(Observation{ClosedWhen: throttles}),
	); unmet {
		t.Fatal(
			"declaring Throttled stopped a plain 403 baseline from counting as enforcement",
		)
	}
}

// leakObservation is the limiter's defect: the over-budget request was
// throttled while the datastore was reachable and served once it was severed.
func leakObservation(closed []probe.Disposition) Observation {
	return Observation{
		ClosedWhen: closed,
		Baseline:   limiterBaseline(),
		Fault: probe.Window{
			Valid: stream(
				probe.Valid,
				repeat(probe.Accepted, MinimumPaired)...),
			Invalid: stream(
				probe.Invalid,
				repeat(probe.Accepted, MinimumPaired)...),
		},
	}
}

func TestAnOverBudgetRequestServedDuringTheFaultIsCounted(t *testing.T) {
	leaked := leakedMonotonic(leakObservation(throttles))
	if leaked != MinimumPaired {
		t.Fatalf(
			"the limiter served %d over-budget requests during the fault and khaos counted %d",
			MinimumPaired,
			leaked,
		)
	}
}

func TestAnUndeclaredThrottleLeaksNothing(t *testing.T) {
	if leaked := leakedMonotonic(leakObservation(nil)); leaked != 0 {
		t.Fatalf(
			"an experiment declaring nothing counted %d leaks from a throttled baseline, so the guard is no longer reading the declaration",
			leaked,
		)
	}
}

// A limiter has recovered when the over-budget request is throttled again.
func TestRecoveryReadsTheDeclaredRefusal(t *testing.T) {
	recovered := recoveryOf(limiterBaseline(), throttles)
	if recovered != Recovered {
		t.Fatalf(
			"a limiter throttling every over-budget request again was read as %q rather than recovered",
			recovered,
		)
	}
}

// Through closedWhen rather than a bare nil: the bare nil skips the
// defaulting the other two guards go through, and cannot see a change that
// makes Throttled closed for every experiment.
func TestRecoveryIsStillDegradedWhenNothingDeclaresTheThrottle(t *testing.T) {
	if recovered := recoveryOf(
		limiterBaseline(),
		closedWhen(Observation{}),
	); recovered == Recovered {
		t.Fatal(
			"an experiment declaring nothing read a throttle as a recovered refusal",
		)
	}
}

func TestRecoveryStillReadsAPlainRejection(t *testing.T) {
	if recovered := recoveryOf(
		healthyBaseline(),
		closedWhen(Observation{ClosedWhen: throttles}),
	); recovered != Recovered {
		t.Fatalf(
			"declaring Throttled stopped a plain 403 recovery from being read as recovered, got %q",
			recovered,
		)
	}
}

// The three guards above are EPISTEMIC: they ask whether khaos observed this
// control decide at all, and whether the steady state came back. A declared
// refusal only answers that when the disposition is the target DECIDING.
//
// `Throttled` is a decision, so the limiter needs it. `Unavailable` is not --
// probe.go says a 503 "is never Rejected" and Answered() is false for it --
// and four shipped families declare it. Letting it through these three turns
// a target that 500s its negative control into one khaos reports as enforcing.
var unavailable = []probe.Disposition{probe.Unavailable}

// deadNegativeControl is a target whose auth path throws instead of refusing:
// the valid credential is served and the bogus one gets a 500. It was never
// observed enforcing anything, so the run has to be voided.
func deadNegativeControl() probe.Window {
	return probe.Window{
		Valid: stream(probe.Valid, repeat(probe.Accepted, MinimumPaired)...),
		Invalid: stream(
			probe.Invalid,
			repeat(probe.Unavailable, MinimumPaired)...),
	}
}

func TestA503OnTheNegativeControlIsNotEnforcement(t *testing.T) {
	reason, unmet := baselineUnmet(
		deadNegativeControl(),
		"",
		false,
		closedWhen(Observation{ClosedWhen: unavailable}),
	)
	if !unmet {
		t.Fatal(
			"a baseline whose negative control only ever 500'd was read as a control that was enforcing; khaos would then print that the invalid credential kept being rejected",
		)
	}

	_ = reason
}

func TestA503InTheBaselineCannotSeedTheLeakLatch(t *testing.T) {
	leaked := leakedMonotonic(Observation{
		ClosedWhen: unavailable,
		Baseline:   deadNegativeControl(),
		Fault: probe.Window{
			Valid: stream(
				probe.Valid,
				repeat(probe.Accepted, MinimumPaired)...),
			Invalid: stream(
				probe.Invalid,
				repeat(probe.Accepted, MinimumPaired)...),
		},
	})

	if leaked != 0 {
		t.Fatalf(
			"khaos counted %d inputs as 'already refused and then accepted' when the baseline only ever 500'd them; it never saw a refusal to contradict",
			leaked,
		)
	}
}

func TestA503InRecoveryIsNotASteadyState(t *testing.T) {
	recovered := recoveryOf(
		deadNegativeControl(),
		closedWhen(Observation{ClosedWhen: unavailable}),
	)

	if recovered == Recovered {
		t.Fatal(
			"a recovery window still 500ing the negative control was read as the steady state returning",
		)
	}
}
