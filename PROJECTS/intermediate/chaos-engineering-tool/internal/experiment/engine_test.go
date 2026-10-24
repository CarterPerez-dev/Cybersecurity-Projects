// ©AngelaMos | 2026
// engine_test.go

package experiment

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

type scriptedProbe struct {
	credential probe.Credential
	before     probe.Disposition
	during     probe.Disposition
	faulted    *bool
	calls      *int
}

func (p scriptedProbe) Name() string { return "scripted" }

func (p scriptedProbe) Describe() string             { return "a scripted probe" }
func (p scriptedProbe) Credential() probe.Credential { return p.credential }

func (p scriptedProbe) Run(context.Context) probe.Outcome {
	*p.calls++

	disposition := p.before
	if *p.faulted {
		disposition = p.during
	}

	return probe.Outcome{
		At:          time.Now().UTC(),
		Credential:  p.credential,
		Disposition: disposition,
	}
}

type scriptedInjector struct {
	faulted       *bool
	injectErr     error
	revertErr     error
	confirmErr    error
	restartErr    error
	unconfirmable bool
	injects       int
	reverts       int
	restarts      int

	// restarted lets a probe see that the target went away, so a test can
	// model a container that does not come back.
	restarted *bool
}

func (i *scriptedInjector) Inject(context.Context, string, string) error {
	i.injects++
	if i.injectErr != nil {
		return i.injectErr
	}
	*i.faulted = true
	return nil
}

func (i *scriptedInjector) Confirm(context.Context) (string, error) {
	if i.confirmErr != nil {
		return "", i.confirmErr
	}
	if i.unconfirmable {
		return "", nil
	}
	return "a scripted confirmation", nil
}

func (i *scriptedInjector) Revert(context.Context) error {
	i.reverts++
	*i.faulted = false
	return i.revertErr
}

func (i *scriptedInjector) Restart(context.Context) error {
	i.restarts++

	if i.restartErr != nil {
		return i.restartErr
	}

	if i.restarted != nil {
		*i.restarted = true
	}

	return nil
}

func quickTiming() Timing {
	return Timing{
		SampleInterval: time.Millisecond,
		BaselineFor:    10 * time.Millisecond,
		FaultFor:       10 * time.Millisecond,
		RecoveryFor:    5 * time.Millisecond,
	}
}

func spec(valid, invalid probe.Probe) Experiment {
	return Experiment{
		Name: "test.experiment",
		Hypothesis: Hypothesis{
			Condition: "a dependency outage",
			Response:  "a refusal",
		},
		Fault:    Fault{Kind: "container-pause", Target: "dep"},
		Polarity: Polarity{Defects: []Direction{Permitted}},
		Probes:   probe.Pair{Valid: valid, Invalid: invalid},
		Timing:   quickTiming(),
	}
}

func TestTheEngineRunsEveryStageInOrder(t *testing.T) {
	faulted := false
	calls := 0

	injector := &scriptedInjector{faulted: &faulted}
	engine := Engine{Injector: injector}

	var stages []Stage
	engine.Report = func(e Event) { stages = append(stages, e.Stage) }

	result, err := engine.Run(context.Background(), spec(
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
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	want := []Stage{
		StageBaseline,
		StageInject,
		StageConfirm,
		StageObserve,
		StageRevert,
		StageRecover,
		StageVerdict,
	}
	if len(stages) != len(want) {
		t.Fatalf("stages = %v, want %v", stages, want)
	}
	for i := range want {
		if stages[i] != want[i] {
			t.Fatalf("stage %d = %s, want %s", i, stages[i], want[i])
		}
	}

	if injector.injects != 1 || injector.reverts != 1 {
		t.Fatalf(
			"injects=%d reverts=%d, want 1 and 1",
			injector.injects,
			injector.reverts,
		)
	}

	if result.Verdict.Direction != Held {
		t.Fatalf("direction = %s, want %s", result.Verdict.Direction, Held)
	}
}

func TestTheEngineRefusesAnExperimentWithoutANegativeControl(t *testing.T) {
	faulted := false
	calls := 0

	engine := Engine{Injector: &scriptedInjector{faulted: &faulted}}

	incomplete := spec(
		scriptedProbe{
			probe.Valid,
			probe.Accepted,
			probe.Accepted,
			&faulted,
			&calls,
		},
		nil,
	)

	if _, err := engine.Run(
		context.Background(),
		incomplete,
	); !errors.Is(
		err,
		ErrNoProbePair,
	) {
		t.Fatalf(
			"got %v; an experiment without an invalid-credential probe has no negative "+
				"control, so its verdict would mean nothing",
			err,
		)
	}
}

func TestAFailingInjectionRevertsAndNeverProducesADirection(t *testing.T) {
	faulted := false
	calls := 0

	injector := &scriptedInjector{
		faulted:   &faulted,
		injectErr: errors.New("daemon said no"),
	}
	engine := Engine{Injector: injector}

	result, err := engine.Run(context.Background(), spec(
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

	if err == nil {
		t.Fatal("a failing injection was reported as success")
	}

	if injector.reverts != 1 {
		t.Fatalf(
			"reverts = %d; a failed injection may have partially landed and must always "+
				"be followed by a revert",
			injector.reverts,
		)
	}

	if result.Verdict.Epistemic != Errored ||
		result.Verdict.Direction != Undetermined {
		t.Fatalf(
			"verdict = %s/%s, want %s/%s",
			result.Verdict.Epistemic,
			result.Verdict.Direction,
			Errored,
			Undetermined,
		)
	}
}

func TestTheEngineNeverInjectsIntoATargetThatWasNotEnforcing(t *testing.T) {
	faulted := false
	calls := 0

	injector := &scriptedInjector{faulted: &faulted}
	engine := Engine{Injector: injector}

	result, err := engine.Run(context.Background(), spec(
		scriptedProbe{
			probe.Valid,
			probe.Accepted,
			probe.Accepted,
			&faulted,
			&calls,
		},
		scriptedProbe{
			probe.Invalid,
			probe.Accepted,
			probe.Accepted,
			&faulted,
			&calls,
		},
	))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if injector.injects != 0 {
		t.Fatal(
			"khaos injected a fault into a target that was not enforcing before the run; " +
				"there is nothing to learn and the operator paid the blast radius for it",
		)
	}

	if result.Verdict.Epistemic != BaselineNotMet {
		t.Fatalf(
			"epistemic = %s, want %s",
			result.Verdict.Epistemic,
			BaselineNotMet,
		)
	}
	if result.Observation.FaultFor != 0 {
		t.Fatal("a refused run claimed time observing an uninjected fault")
	}
}

func TestTheEngineDetectsAControlThatGaveWayUnderFault(t *testing.T) {
	faulted := false
	calls := 0

	engine := Engine{Injector: &scriptedInjector{faulted: &faulted}}

	result, err := engine.Run(context.Background(), spec(
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
			probe.Accepted,
			&faulted,
			&calls,
		},
	))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if result.Verdict.Direction != Permitted {
		t.Fatalf(
			"direction = %s, want %s; the invalid credential was rejected before the fault "+
				"and accepted during it",
			result.Verdict.Direction,
			Permitted,
		)
	}

	if !result.Verdict.Defect {
		t.Fatal(
			"failing open was not flagged as a defect for a control that declares it one",
		)
	}

	if result.Verdict.Epistemic != Deviated {
		t.Fatalf("epistemic = %s, want %s", result.Verdict.Epistemic, Deviated)
	}
}

func TestAnInterruptedRunIsNotConclusive(t *testing.T) {
	faulted := false
	calls := 0

	engine := Engine{Injector: &scriptedInjector{faulted: &faulted}}

	ctx, cancel := context.WithCancel(context.Background())

	slow := spec(
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
	)
	slow.Timing.FaultFor = time.Second

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	result, err := engine.Run(ctx, slow)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if result.Verdict.Epistemic != Interrupted {
		t.Fatalf(
			"epistemic = %s, want %s",
			result.Verdict.Epistemic,
			Interrupted,
		)
	}

	if result.Verdict.Conclusive {
		t.Fatal("an interrupted run was marked conclusive")
	}
}

func TestTheHypothesisUsesTheCanonicalTemplate(t *testing.T) {
	h := Hypothesis{
		Condition: "the identity provider being unreachable",
		Response:  "a refusal",
	}

	want := "In the event of the identity provider being unreachable, we are confident that our system will respond with a refusal."
	if got := h.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// goneAfterRestart answers normally until the target is restarted and never
// again, which is what a container that does not come back looks like. The
// baseline has to be measurable or the run is voided before the restart and
// the test passes for the wrong reason.
type goneAfterRestart struct {
	credential probe.Credential
	restarted  *bool
}

func (p goneAfterRestart) Name() string { return "gone-after-restart" }

func (p goneAfterRestart) Describe() string { return "a probe that stops answering" }

func (p goneAfterRestart) Credential() probe.Credential { return p.credential }

func (p goneAfterRestart) Run(context.Context) probe.Outcome {
	disposition := probe.Accepted
	if *p.restarted {
		disposition = probe.Unreachable
	}

	return probe.Outcome{
		At:          time.Now().UTC(),
		Credential:  p.credential,
		Disposition: disposition,
	}
}

// coldSpec is a run whose fault is the target INITIALISING without a
// dependency it had a moment ago.
func coldSpec(valid, invalid probe.Probe) Experiment {
	out := spec(valid, invalid)
	out.ColdStart = true

	return out
}

// The restart is the injection for this experiment, so a coldStart that
// silently did nothing would leave the verdict, the exit code and the stage
// line unchanged: the stage is emitted BEFORE the restart is attempted.
func TestAColdStartRunActuallyRestartsTheTarget(t *testing.T) {
	faulted := false
	calls := 0

	injector := &scriptedInjector{faulted: &faulted}
	engine := Engine{Injector: injector}

	if _, err := engine.Run(context.Background(), coldSpec(
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
	)); err != nil {
		t.Fatalf("run: %v", err)
	}

	if injector.restarts != 1 {
		t.Fatalf(
			"a cold-start run restarted the target %d time(s), want exactly 1",
			injector.restarts,
		)
	}
}

// And an experiment that does NOT declare it must not restart anything, or
// every other family pays for this one.
func TestAnOrdinaryRunNeverRestartsTheTarget(t *testing.T) {
	faulted := false
	calls := 0

	injector := &scriptedInjector{faulted: &faulted}
	engine := Engine{Injector: injector}

	if _, err := engine.Run(context.Background(), spec(
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
	)); err != nil {
		t.Fatalf("run: %v", err)
	}

	if injector.restarts != 0 {
		t.Fatalf(
			"an experiment that declares no cold start restarted the target %d time(s)",
			injector.restarts,
		)
	}
}

// A restart khaos could not perform means the fault window would measure a
// target in the wrong state, so the run is abandoned and the fault reverted
// rather than reported.
func TestAFailedRestartAbandonsTheRunAndRevertsTheFault(t *testing.T) {
	faulted := false
	calls := 0

	wanted := errors.New("the daemon refused the restart")

	injector := &scriptedInjector{faulted: &faulted, restartErr: wanted}
	engine := Engine{Injector: injector}

	_, err := engine.Run(context.Background(), coldSpec(
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

	if !errors.Is(err, wanted) {
		t.Fatalf("the restart failure was not surfaced: %v", err)
	}

	if injector.reverts == 0 {
		t.Fatal("the fault was left applied after the restart failed")
	}

	if faulted {
		t.Fatal("the fault is still armed after the run abandoned")
	}
}

// A target that never answers again produces a NAMED refusal rather than a
// measured window: there is nothing to measure, and reporting HELD would
// claim a survival khaos never saw.
func TestATargetThatNeverComesBackIsNamedRatherThanMeasured(t *testing.T) {
	faulted := false
	calls := 0

	injector := &scriptedInjector{faulted: &faulted}
	engine := Engine{Injector: injector, SettleFor: 20 * time.Millisecond}

	restarted := false
	injector.restarted = &restarted

	run := coldSpec(
		goneAfterRestart{probe.Valid, &restarted},
		scriptedProbe{
			probe.Invalid,
			probe.Rejected,
			probe.Rejected,
			&faulted,
			&calls,
		},
	)

	_, err := engine.Run(context.Background(), run)

	if !errors.Is(err, ErrNeverCameBack) {
		t.Fatalf(
			"a target that never answered after the restart did not produce ErrNeverCameBack: %v",
			err,
		)
	}
}
