// ©AngelaMos | 2026
// polarity_test.go

package experiment

import (
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

// Polarity is declared per experiment and khaos assumes NOTHING about which
// direction is the defect. The design document says so about failing open:
// authentication failing open is catastrophic, a rate-limit counter failing
// open is a defensible trade, and khaos reports against the declaration.
//
// The same rule applies to HOLDING, and it did not. finish() skipped the
// polarity check whenever the direction was Held, on the assumption that a
// control which held is never a defect. That is the identical mistake inverted,
// hard-coded one layer below the mechanism built to prevent it, and it made
// every such declaration inert.
//
// The `tls.` family is where it matters. khaos serves a certificate it
// deliberately broke, and a target that carries on unchanged has ACCEPTED it.
// "Nothing looks wrong" IS the finding, and the run used to exit 0.

// heldIsTheDefect is the shape a certificate experiment declares.
var heldIsTheDefect = Polarity{
	Defects:   []Direction{Held, Permitted},
	Rationale: "a target that carries on unchanged accepted a certificate khaos deliberately broke",
}

// holdingObservation is a clean run in which the target behaved perfectly:
// valid accepted throughout, invalid refused throughout. For most families that
// is a pass. For a certificate fault it means the bad certificate was used.
func holdingObservation() Observation {
	return Observation{
		FaultConfirmed: true,
		Baseline:       healthyBaseline(),
		Fault: probe.Window{
			Valid: stream(
				probe.Valid,
				repeat(probe.Accepted, MinimumToClaimClosed)...),
			Invalid: stream(
				probe.Invalid,
				repeat(probe.Rejected, MinimumToClaimClosed)...),
		},
		Recovery: healthyRecovery(),
	}
}

func TestAnExperimentCanDeclareHoldingToBeTheDefect(t *testing.T) {
	verdict := Judge(holdingObservation(), heldIsTheDefect)

	if verdict.Direction != Held {
		t.Fatalf(
			"direction = %s, want %s; the target served valid traffic and refused invalid traffic throughout",
			verdict.Direction,
			Held,
		)
	}

	if !verdict.Defect {
		t.Fatal(
			"the experiment declared HELD a defect and khaos reported none, so a target that used a certificate khaos deliberately broke would exit 0 and be cleared",
		)
	}

	if !verdict.Conclusive {
		t.Fatal(
			"a run with enough paired samples to claim closed was marked inconclusive",
		)
	}
}

// The other direction, so the fix is not just "always a defect". An experiment
// that does NOT declare holding a defect must still get a clean pass out of the
// same observation.
func TestHoldingIsStillAPassWhenTheExperimentSaysSo(t *testing.T) {
	verdict := Judge(holdingObservation(), authPolarity)

	if verdict.Direction != Held {
		t.Fatalf("direction = %s, want %s", verdict.Direction, Held)
	}

	if verdict.Defect {
		t.Fatal(
			"holding was reported as a defect for an experiment that declares PERMITTED to be the defect, so the polarity is being ignored in the other direction now",
		)
	}

	if verdict.Epistemic != Passed {
		t.Fatalf("epistemic = %s, want %s", verdict.Epistemic, Passed)
	}
}

// UNDETERMINED must never be a defect, whatever the polarity says, because it
// is the absence of a direction rather than one. No polarity lists it, and this
// pins that: removing the direction guard must not have made "khaos could not
// tell" into a finding.
func TestAnUndeterminedDirectionIsNeverADefect(t *testing.T) {
	observation := holdingObservation()
	observation.FaultConfirmed = false

	verdict := Judge(observation, heldIsTheDefect)

	if verdict.Direction != Undetermined {
		t.Fatalf("direction = %s, want %s", verdict.Direction, Undetermined)
	}

	if verdict.Defect {
		t.Fatal(
			"a run khaos could not draw a direction from was reported as a defect",
		)
	}
}
