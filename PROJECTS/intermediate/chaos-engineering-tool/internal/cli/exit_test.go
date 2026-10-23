// ©AngelaMos | 2026
// exit_test.go

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/run"
)

// held is a finished run with nothing wrong with it, which every case below
// mutates one field of. Building it here rather than per case is what keeps a
// case honest: a case that passes because it forgot to set Conclusive is
// testing the fixture, not the mapping.
func held() experiment.Result {
	return experiment.Result{
		Verdict: experiment.Verdict{
			Epistemic:  experiment.Passed,
			Direction:  experiment.Held,
			Recovery:   experiment.Recovered,
			Conclusive: true,
		},
	}
}

func codeOf(t *testing.T, result experiment.Result) int {
	t.Helper()

	err := exitFor(result, nil)
	if err == nil {
		return CodeOK
	}

	var exit *Exit
	if !errors.As(err, &exit) {
		t.Fatalf("exitFor returned an error carrying no code: %v", err)
	}

	return exit.Code
}

// Every epistemic value is reachable and assigned at a real site in the
// verdict engine, so every one needs its own code. A single non-zero exit
// would collapse "a control failed open", "the experiment was invalid" and
// "khaos could not measure" into one signal, and those are three different
// human responses.
func TestEveryReachableOutcomeHasItsOwnExitCode(t *testing.T) {
	for _, row := range []struct {
		name  string
		shape func(*experiment.Result)
		want  int
	}{
		{
			"a clean held run",
			func(*experiment.Result) {},
			CodeOK,
		},
		{
			"the direction this experiment calls a defect",
			func(r *experiment.Result) {
				r.Verdict.Epistemic = experiment.Deviated
				r.Verdict.Direction = experiment.Permitted
				r.Verdict.Defect = true
			},
			CodeDefect,
		},
		{
			"deviated in a direction it does NOT call a defect",
			func(r *experiment.Result) {
				r.Verdict.Epistemic = experiment.Deviated
				r.Verdict.Direction = experiment.Denied
			},
			CodeDeviated,
		},
		{
			"held on evidence khaos declined to call conclusive",
			func(r *experiment.Result) {
				r.Verdict.Conclusive = false
			},
			CodeInconclusive,
		},
		{
			"khaos's own measurement failed",
			func(r *experiment.Result) {
				r.Verdict.Epistemic = experiment.ProbeError
			},
			CodeProbe,
		},
		{
			"the fault was never confirmed",
			func(r *experiment.Result) {
				r.Verdict.Epistemic = experiment.Aborted
			},
			CodeVoid,
		},
		{
			"the target was broken before khaos injected",
			func(r *experiment.Result) {
				r.Verdict.Epistemic = experiment.BaselineNotMet
			},
			CodeBaseline,
		},
		{
			"the question does not apply to this target",
			func(r *experiment.Result) {
				r.Verdict.Epistemic = experiment.Unsupported
			},
			CodeUnsupported,
		},
		{
			"the run was interrupted",
			func(r *experiment.Result) {
				r.Verdict.Epistemic = experiment.Interrupted
			},
			CodeInterrupted,
		},
		{
			"the fault could not be reverted",
			func(r *experiment.Result) {
				r.Observation.RollbackFailed = true
			},
			CodeRollback,
		},
		{
			"the target never came back",
			func(r *experiment.Result) {
				r.Verdict.Recovery = experiment.Degraded
			},
			CodeRollback,
		},
		{
			"recovery was never observed",
			func(r *experiment.Result) {
				r.Verdict.Recovery = experiment.Unobserved
			},
			CodeInconclusive,
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			result := held()
			row.shape(&result)

			if got := codeOf(t, result); got != row.want {
				t.Fatalf("exit code %d, want %d", got, row.want)
			}
		})
	}
}

// No two outcomes may share a code, or CI cannot tell them apart, which is
// the entire reason the taxonomy exists. Interrupted and inconclusive were
// both literally 4 in the shipped binary.
func TestNoTwoOutcomesShareACode(t *testing.T) {
	codes := map[int]Outcome{}

	for _, outcome := range append(suppressible(), outcomeRollback) {
		code := codeFor(t, outcome)

		if other, clash := codes[code]; clash {
			t.Fatalf(
				"%s and %s both exit %d, so nothing downstream can tell them apart",
				outcome,
				other,
				code,
			)
		}

		codes[code] = outcome
	}
}

// codeFor walks the mapping the other way, through the states that produce
// each outcome, so this census reads the real function rather than a table
// written beside it.
func codeFor(t *testing.T, outcome Outcome) int {
	t.Helper()

	result := held()

	switch outcome {
	case OutcomeDefect:
		result.Verdict.Epistemic = experiment.Deviated
		result.Verdict.Defect = true
	case OutcomeDeviated:
		result.Verdict.Epistemic = experiment.Deviated
	case OutcomeInconclusive:
		result.Verdict.Conclusive = false
	case OutcomeProbe:
		result.Verdict.Epistemic = experiment.ProbeError
	case OutcomeVoid:
		result.Verdict.Epistemic = experiment.Aborted
	case OutcomeBaseline:
		result.Verdict.Epistemic = experiment.BaselineNotMet
	case OutcomeUnsupported:
		result.Verdict.Epistemic = experiment.Unsupported
	case OutcomeInterrupted:
		result.Verdict.Epistemic = experiment.Interrupted
	case outcomeRollback:
		result.Observation.RollbackFailed = true
	default:
		t.Fatalf("no state produces the outcome %q", outcome)
	}

	return codeOf(t, result)
}

// A defect outranks the epistemic axis, because one leaked request is a proof
// and khaos reports a proven bypass even on thin evidence.
func TestADefectOutranksThinEvidence(t *testing.T) {
	result := held()
	result.Verdict.Epistemic = experiment.Deviated
	result.Verdict.Defect = true
	result.Verdict.Conclusive = false

	if got := codeOf(t, result); got != CodeDefect {
		t.Fatalf("exit code %d, want the defect code %d", got, CodeDefect)
	}
}

// And the state khaos left the target in outranks the defect.
func TestRollbackOutranksTheDefect(t *testing.T) {
	result := held()
	result.Verdict.Defect = true
	result.Observation.RollbackFailed = true

	if got := codeOf(t, result); got != CodeRollback {
		t.Fatalf("exit code %d, want the rollback code %d", got, CodeRollback)
	}
}

func TestTheDefaultGateNarrowsNothing(t *testing.T) {
	gate, err := ParseGate("")
	if err != nil {
		t.Fatalf("the empty default was refused: %v", err)
	}

	for _, outcome := range suppressible() {
		exit := &Exit{Code: codeFor(t, outcome), Outcome: outcome}

		if got := gate.Apply(exit); got == CodeOK {
			t.Fatalf(
				"the default gate silenced %s; a run khaos declined to conclude from exiting 0 is a green build on no evidence",
				outcome,
			)
		}
	}
}

func TestGatingOnTheDefectAloneSilencesTheRest(t *testing.T) {
	gate, err := ParseGate(string(OutcomeDefect))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	for _, outcome := range suppressible() {
		exit := &Exit{Code: codeFor(t, outcome), Outcome: outcome}
		got := gate.Apply(exit)

		if outcome == OutcomeDefect {
			if got != CodeDefect {
				t.Fatalf("the gated outcome was silenced: %d", got)
			}

			continue
		}

		if got != CodeOK {
			t.Fatalf(
				"%s survived a gate that does not name it: %d",
				outcome,
				got,
			)
		}
	}
}

// The two codes no gate may touch, asserted against EVERY gate value rather
// than against the default: a --fail-on that could suppress an unreverted
// fault would leave the environment dirty for every later job on the runner.
func TestNoGateCanSuppressARollbackFailure(t *testing.T) {
	for _, value := range []string{
		FailOnAny,
		FailOnNever,
		string(OutcomeDefect),
		string(OutcomeInconclusive) + "," + string(OutcomeVoid),
	} {
		t.Run(value, func(t *testing.T) {
			gate, err := ParseGate(value)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			exit := &Exit{
				Code:    CodeRollback,
				Outcome: outcomeRollback,
				Err:     run.ErrRevertFailed,
			}

			if got := gate.Apply(exit); got != CodeRollback {
				t.Fatalf(
					"--fail-on %s silenced an unreverted fault, which leaves the environment dirty",
					value,
				)
			}
		})
	}
}

// `never` is the one value that reports every measurable outcome as 0, and it
// still cannot reach the rollback code above.
func TestNeverSilencesEveryMeasurableOutcome(t *testing.T) {
	gate, err := ParseGate(FailOnNever)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	for _, outcome := range suppressible() {
		exit := &Exit{Code: codeFor(t, outcome), Outcome: outcome}

		if got := gate.Apply(exit); got != CodeOK {
			t.Fatalf("--fail-on never left %s at %d", outcome, got)
		}
	}
}

// A typo that silenced the defect code would turn every run green, so an
// unknown name is refused rather than gating on nothing.
func TestAnUnknownOutcomeIsRefusedByName(t *testing.T) {
	for _, value := range []string{
		"open",
		"defect,typo",
		"rollback-failed",
		"DEFECT",
	} {
		t.Run(value, func(t *testing.T) {
			_, err := ParseGate(value)
			if !errors.Is(err, ErrUnknownOutcome) {
				t.Fatalf("ParseGate(%q) did not refuse by name: %v", value, err)
			}
		})
	}
}

// The gate's vocabulary is the verdict's own vocabulary, so an operator reads
// an outcome in the report and can type it into the flag.
func TestTheGateNamesMatchTheVerdictsOwnWords(t *testing.T) {
	for _, row := range []struct {
		outcome   Outcome
		epistemic experiment.Epistemic
	}{
		{OutcomeProbe, experiment.ProbeError},
		{OutcomeVoid, experiment.Aborted},
		{OutcomeBaseline, experiment.BaselineNotMet},
		{OutcomeUnsupported, experiment.Unsupported},
		{OutcomeInterrupted, experiment.Interrupted},
	} {
		// `void` is deliberately not `aborted`: the epistemic word describes
		// what khaos did and the gate word describes what the operator got.
		if row.outcome == OutcomeVoid {
			continue
		}

		if string(row.outcome) != string(row.epistemic) {
			t.Errorf(
				"the gate calls it %q and the verdict prints %q",
				row.outcome,
				row.epistemic,
			)
		}
	}
}

// gated is what turns a narrowed code into a nil error, so a suppressed
// outcome genuinely exits 0 rather than printing a failure with code 0.
func TestASuppressedOutcomeReturnsNoError(t *testing.T) {
	gate, err := ParseGate(FailOnNever)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	suppressed := gated(gate, &Exit{
		Code:    CodeInconclusive,
		Outcome: OutcomeInconclusive,
		Err:     ErrInconclusive,
	})

	if suppressed != nil {
		t.Fatalf("a suppressed outcome still returned an error: %v", suppressed)
	}

	// And an error the gate has no opinion about passes through untouched.
	foreign := errors.New("the daemon refused the connection")
	if got := gated(gate, foreign); !errors.Is(got, foreign) {
		t.Fatalf("a non-verdict error was swallowed by the gate: %v", got)
	}
}

// Nothing may quietly drop out of the gate's vocabulary: a code with no name
// is a code no operator can gate on.
func TestEverySuppressibleOutcomeIsParseable(t *testing.T) {
	for _, outcome := range suppressible() {
		gate, err := ParseGate(string(outcome))
		if err != nil {
			t.Fatalf("ParseGate(%q): %v", outcome, err)
		}

		if !slices.Contains(gate.allowed, outcome) {
			t.Fatalf("%q parsed into a gate that does not contain it", outcome)
		}
	}
}

// The LITERAL numbers, because they are a published contract: a CI pipeline
// keys off the integer, not off the name of the constant. Every other test
// here compares a state against a named code, so all of them would survive a
// wholesale renumbering together. This one would not.
func TestTheExitCodesAreTheirPublishedNumbers(t *testing.T) {
	for name, want := range map[string]struct {
		got  int
		want int
	}{
		"OK":           {CodeOK, 0},
		"USAGE":        {CodeUsage, 1},
		"DEFECT":       {CodeDefect, 2},
		"DEVIATED":     {CodeDeviated, 3},
		"INCONCLUSIVE": {CodeInconclusive, 4},
		"PROBE":        {CodeProbe, 5},
		"ROLLBACK":     {CodeRollback, 6},
		"VOID":         {CodeVoid, 7},
		"BASELINE":     {CodeBaseline, 8},
		"UNSUPPORTED":  {CodeUnsupported, 9},
		"INTERRUPTED":  {CodeInterrupted, 10},
		"INTERNAL":     {CodeInternal, 70},
	} {
		if want.got != want.want {
			t.Errorf("%s is %d, want %d", name, want.got, want.want)
		}
	}
}

// The code in the record and the code the process returns are the SAME
// contract. Computed by two lists, they disagreed: a rollback failure wrote
// exit.code 1 into run.json while the process exited 6, about the one
// outcome no --fail-on value may suppress.
func TestTheRecordedCodeIsTheCodeTheProcessReturns(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"a fault that could not be reverted": {
			err:  run.ErrRevertFailed,
			want: CodeRollback,
		},
		"a target that never recovered": {
			err:  ErrNotRecovered,
			want: CodeRollback,
		},
		"an interrupted run": {
			err:  context.Canceled,
			want: CodeInterrupted,
		},
		"an ordinary execution error": {
			err:  errors.New("the daemon refused"),
			want: CodeUsage,
		},
		"a wrapped rollback failure": {
			err:  fmt.Errorf("reverting: %w", run.ErrRevertFailed),
			want: CodeRollback,
		},

		// errors.Join is where the precedence actually bites: the state khaos
		// left the target in outranks the verdict about it, and the RECORD has
		// to agree with that, not just the status.
		"a rollback failure joined with a defect": {
			err:  errors.Join(ErrDefectFound, run.ErrRevertFailed),
			want: CodeRollback,
		},
		"a rollback failure joined with cancellation": {
			err:  errors.Join(context.Canceled, run.ErrRevertFailed),
			want: CodeRollback,
		},
		"a carried defect code joined with a rollback failure": {
			err: errors.Join(
				&Exit{Code: CodeDefect, Err: ErrDefectFound},
				run.ErrRevertFailed,
			),
			want: CodeRollback,
		},
	} {
		t.Run(name, func(t *testing.T) {
			outcome := exitFor(held(), tc.err)

			if got := ExitCode(outcome); got != tc.want {
				t.Errorf(
					"the process would exit %d",
					got,
				)
			}

			if got, _ := exitDetail(outcome); got != tc.want {
				t.Errorf(
					"the record would say exit.code %d, want %d: an artifact that disagrees with the status is worse than no artifact",
					got,
					tc.want,
				)
			}
		})
	}
}

// A non-positive reap interval reaches time.NewTicker, which panics, and it
// got there after the workspace lock was taken. Refused before anything
// opens.
func TestANonPositiveReapIntervalIsRefusedBeforeAnythingOpens(t *testing.T) {
	for _, interval := range []time.Duration{
		0,
		-time.Second,
	} {
		err := runReap(context.Background(), io.Discard, interval)

		if !errors.Is(err, ErrIntervalNotPositive) {
			t.Fatalf(
				"reap --interval %s returned %v, want a refusal naming the interval",
				interval,
				err,
			)
		}
	}
}
