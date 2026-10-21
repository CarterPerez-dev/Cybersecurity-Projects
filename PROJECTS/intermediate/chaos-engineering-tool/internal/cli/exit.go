// ©AngelaMos | 2026
// exit.go

package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/CarterPerez-dev/khaos/internal/experiment"
)

// The exit contract. A single non-zero code would collapse "a control failed
// open", "the experiment was invalid" and "khaos crashed" into one signal, and
// those need three different human responses.
const (
	CodeOK           = 0
	CodeUsage        = 1
	CodeDefect       = 2
	CodeDeviated     = 3
	CodeInconclusive = 4
	CodeProbe        = 5
	CodeRollback     = 6
	CodeVoid         = 7
	CodeBaseline     = 8
	CodeUnsupported  = 9
	CodeInterrupted  = 10
	CodeInternal     = 70
)

// Outcome names an exit code for --fail-on. The names are the operator's
// vocabulary, so they are the same words the verdict prints.
type Outcome string

const (
	OutcomeDefect       Outcome = "defect"
	OutcomeDeviated     Outcome = "deviated"
	OutcomeInconclusive Outcome = "inconclusive"
	OutcomeProbe        Outcome = "probe-error"
	OutcomeVoid         Outcome = "void"
	OutcomeBaseline     Outcome = "baseline-not-met"
	OutcomeUnsupported  Outcome = "unsupported"
	OutcomeInterrupted  Outcome = "interrupted"

	// outcomeRollback is deliberately unexported and absent from
	// suppressible(): it names a code no gate may silence, so an operator
	// must not be able to type it into --fail-on and believe it did
	// something.
	outcomeRollback Outcome = "rollback-failed"

	// FailOnAny is the default: every outcome khaos declines to call a clean
	// pass keeps its own non-zero code. FailOnNever reports every measurable
	// outcome as 0 and leaves the detail to the run record.
	FailOnAny   = "any"
	FailOnNever = "never"
)

// Exit carries the code beside the error, so the precedence is decided once
// where the run finishes rather than re-derived by a growing chain of
// errors.Is checks at the process boundary.
type Exit struct {
	Code    int
	Outcome Outcome
	Err     error
}

func (e *Exit) Error() string { return e.Err.Error() }
func (e *Exit) Unwrap() error { return e.Err }

// suppressible is every outcome --fail-on may silence. Rollback failure,
// usage and internal errors are deliberately absent: an unreverted fault
// leaves the environment dirty for every later job on that runner, and a tool
// that crashed or could not read its own flags is not reporting a
// measurement at all.
func suppressible() []Outcome {
	return []Outcome{
		OutcomeDefect,
		OutcomeDeviated,
		OutcomeInconclusive,
		OutcomeProbe,
		OutcomeVoid,
		OutcomeBaseline,
		OutcomeUnsupported,
		OutcomeInterrupted,
	}
}

var ErrUnknownOutcome = errors.New(
	"that is not an outcome khaos can gate on",
)

// Gate is the parsed --fail-on set.
type Gate struct {
	all     bool
	none    bool
	allowed []Outcome
}

// ParseGate refuses an unknown name rather than quietly gating on nothing,
// because a typo that silenced the defect code would turn every run green.
func ParseGate(value string) (Gate, error) {
	trimmed := strings.TrimSpace(value)

	switch trimmed {
	case "", FailOnAny:
		return Gate{all: true}, nil
	case FailOnNever:
		return Gate{none: true}, nil
	}

	gate := Gate{}
	known := suppressible()

	for _, name := range strings.Split(trimmed, ",") {
		outcome := Outcome(strings.TrimSpace(name))

		if !slices.Contains(known, outcome) {
			return Gate{}, fmt.Errorf(
				errUnknownOutcome,
				ErrUnknownOutcome,
				outcome,
				joinOutcomes(known),
			)
		}

		gate.allowed = append(gate.allowed, outcome)
	}

	return gate, nil
}

// Apply narrows a code to 0 when its outcome is outside the gate. An outcome
// this gate cannot suppress passes through whatever the gate says.
func (g Gate) Apply(exit *Exit) int {
	if exit == nil {
		return CodeOK
	}

	if !slices.Contains(suppressible(), exit.Outcome) {
		return exit.Code
	}

	if g.all {
		return exit.Code
	}

	if g.none {
		return CodeOK
	}

	if slices.Contains(g.allowed, exit.Outcome) {
		return exit.Code
	}

	return CodeOK
}

func joinOutcomes(outcomes []Outcome) string {
	names := make([]string, 0, len(outcomes))
	for _, outcome := range outcomes {
		names = append(names, string(outcome))
	}

	return strings.Join(names, listSep)
}

// epistemicExit maps the one axis that is not about the target's direction.
// Every value is reachable and assigned at a real site in the verdict engine,
// so none of these is an inert code.
func epistemicExit(epistemic experiment.Epistemic) (int, Outcome, bool) {
	switch epistemic {
	case experiment.ProbeError:
		return CodeProbe, OutcomeProbe, true
	case experiment.Aborted:
		return CodeVoid, OutcomeVoid, true
	case experiment.BaselineNotMet:
		return CodeBaseline, OutcomeBaseline, true
	case experiment.Unsupported:
		return CodeUnsupported, OutcomeUnsupported, true
	case experiment.Interrupted:
		return CodeInterrupted, OutcomeInterrupted, true
	default:
		return 0, "", false
	}
}

// gated narrows a run's own exit to what --fail-on allows. A nil result is a
// clean pass; an error that is not an Exit came from somewhere the gate has
// no opinion about and passes through untouched.
func gated(gate Gate, err error) error {
	if err == nil {
		return nil
	}

	var exit *Exit
	if !errors.As(err, &exit) {
		return err
	}

	if gate.Apply(exit) == CodeOK {
		return nil
	}

	return err
}
