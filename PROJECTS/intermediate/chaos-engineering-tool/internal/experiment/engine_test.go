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
	unconfirmable bool
	injects       int
	reverts       int
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
