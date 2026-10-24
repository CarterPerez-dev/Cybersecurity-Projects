// ©AngelaMos | 2026
// rotation_test.go

package experiment

import (
	"strings"
	"testing"
)

const movedWhat = "moved dependency.khaos.test. to 10.244.244.20 in the zone"

func rotated(queriesDuringFault int64) Observation {
	return Observation{
		Baseline:       healthyBaseline(),
		Fault:          heldFaultWindow(),
		Recovery:       healthyRecovery(),
		FaultConfirmed: true,
		RotatedWhat:    movedWhat,
		ConsultedWhat:  ConsultsResolver,
		Consulted:      2,
		Delivered:      queriesDuringFault,
	}
}

// The whole question for the one fault that MOVES the zone: did the change
// reach the target at all. khaos states it in BOTH directions, so a clean run
// is an answer rather than silence.
func TestTheRotationIsReportedInBothDirections(t *testing.T) {
	followed := Judge(rotated(74), dnsPolarity)

	if !hasReason(followed, "so the rotation reached it") {
		t.Fatalf(
			"a target that asked again was not told the rotation reached it: %v",
			followed.Reasons,
		)
	}

	unseen := Judge(rotated(0), dnsPolarity)

	if !hasReason(unseen, "ZERO during the fault window") {
		t.Fatalf(
			"a target that never asked again was not told the rotation missed it: %v",
			unseen.Reasons,
		)
	}

	// Both carry the counts and the act, or an operator cannot audit either.
	for _, verdict := range []Verdict{followed, unseen} {
		if !hasReason(verdict, movedWhat) {
			t.Fatalf(
				"the reason does not name what khaos moved: %v",
				verdict.Reasons,
			)
		}
	}
}

// AND IT IS NOT A BYPASS. No credential got through that would not have before:
// the target is still reaching the endpoint it reached during the baseline.
// Reporting PERMITTED here would be khaos claiming a bypass it did not observe,
// which is the overstatement this family's polarity exists to prevent.
func TestARotationThatMissedTheTargetIsNotCalledABypass(t *testing.T) {
	verdict := Judge(rotated(0), dnsPolarity)

	if verdict.Direction != Held {
		t.Fatalf(
			"a target that never saw the rotation was judged %s: %v",
			verdict.Direction,
			verdict.Reasons,
		)
	}

	if verdict.Defect {
		t.Fatalf("it was reported as a defect: %v", verdict.Reasons)
	}

	if !hasReason(verdict, "NOT a credential bypass") {
		t.Fatalf(
			"khaos did not say it was reporting no bypass, so a reader has to infer it: %v",
			verdict.Reasons,
		)
	}
}

// And an experiment that performed no rotation must be told nothing about one,
// or every other fault in every family gains a sentence about a zone it never
// touched.
func TestAnExperimentThatRotatedNothingSaysNothingAboutIt(t *testing.T) {
	observation := Observation{
		Baseline:       healthyBaseline(),
		Fault:          heldFaultWindow(),
		Recovery:       healthyRecovery(),
		FaultConfirmed: true,
	}

	for _, reason := range Judge(observation, dnsPolarity).Reasons {
		if strings.Contains(reason, "in the zone") ||
			strings.Contains(reason, "rotation") {
			t.Fatalf(
				"an experiment that rotated nothing was told about one: %q",
				reason,
			)
		}
	}
}

// The rotation is EXEMPT from the delivery guard, and that exemption is the
// whole design: window one's guard reads "the target never met the fault" as a
// void run, and here not asking again IS the measurement.
func TestTheRotationIsExemptFromTheDeliveryGuard(t *testing.T) {
	// The BUILT experiment, not a hand-made observation: the exemption lives in
	// the builder, so an observation written by hand proves nothing about it.
	// Measured by gutting, which stayed green against the hand-made version.
	definition, err := Lookup(NameDNSTTLRotate)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	spec, err := Build(definition.Name, fill(definition.Params), fastTiming)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if spec.DeliveredWhat != "" {
		t.Fatalf(
			"the rotation declares the delivery guard (%q), which aborts the run on the very observation this experiment exists to measure",
			spec.DeliveredWhat,
		)
	}

	if spec.RotatedWhat == "" {
		t.Fatal(
			"the rotation declares no observable of its own, so a run that measured it would say nothing",
		)
	}

	// And the rest of the family still DOES declare it, or the exemption was
	// applied to the whole family rather than to the one fault that earns it.
	guarded := 0

	for _, other := range Catalog() {
		if other.Family != FamilyDNS || other.Name == NameDNSTTLRotate {
			continue
		}

		built, err := Build(other.Name, fill(other.Params), fastTiming)
		if err != nil {
			t.Fatalf("build %s: %v", other.Name, err)
		}

		if built.DeliveredWhat != "" {
			guarded++
		}
	}

	if guarded == 0 {
		t.Fatal(
			"no other DNS fault carries the delivery guard, so the exemption was applied to the whole family",
		)
	}

	if Judge(rotated(0), dnsPolarity).Epistemic != Passed {
		t.Fatalf(
			"a target that never asked again produced %s rather than a readable verdict",
			Judge(rotated(0), dnsPolarity).Epistemic,
		)
	}
}
