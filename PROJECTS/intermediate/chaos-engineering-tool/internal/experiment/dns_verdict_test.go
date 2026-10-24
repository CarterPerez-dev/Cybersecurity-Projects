// ©AngelaMos | 2026
// dns_verdict_test.go

package experiment

import (
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const deliveredResolveWhat = "re-resolve its dependency's name"

// faultWindows are the two shapes every test below starts from: one where the
// invalid credential starts being accepted under the fault, and one where
// nothing changes.
func permittedFaultWindow() probe.Window {
	return probe.Window{
		Valid: stream(probe.Valid, repeat(probe.Accepted, MinimumPaired*3)...),
		Invalid: stream(
			probe.Invalid,
			append(
				repeat(probe.Rejected, 1),
				repeat(probe.Accepted, MinimumPaired*3)...,
			)...,
		),
	}
}

func heldFaultWindow() probe.Window {
	return probe.Window{
		Valid: stream(probe.Valid, repeat(probe.Accepted, MinimumPaired*3)...),
		Invalid: stream(
			probe.Invalid,
			repeat(probe.Rejected, MinimumPaired*3)...,
		),
	}
}

// TestAnExperimentWithoutThePauseSaysNothingAboutIt is the control for the guard
// in diagnose.
//
// Without it every PERMITTED verdict in the three families that do not use the
// idleness pause reported on a resumed window khaos never collected, which reads
// as khaos having tried the pause and learned nothing from it.
func TestAnExperimentWithoutThePauseSaysNothingAboutIt(t *testing.T) {
	observation := Observation{
		Baseline:       healthyBaseline(),
		Fault:          permittedFaultWindow(),
		Recovery:       healthyRecovery(),
		FaultConfirmed: true,
		ConfirmMethod:  "measured",
		Delivered:      3,
		DeliveredWhat:  deliveredResolveWhat,
	}

	verdict := Judge(observation, dnsPolarity)

	if verdict.Direction != Permitted {
		t.Fatalf("direction %s, want %s", verdict.Direction, Permitted)
	}

	if verdict.Cause != Undiagnosed {
		t.Errorf("cause %s, want %s", verdict.Cause, Undiagnosed)
	}

	for _, reason := range verdict.Reasons {
		if strings.Contains(reason, "resumed window") {
			t.Errorf(
				"an experiment that never paused traffic reported on the pause: %q",
				reason,
			)
		}
	}
}

// TestAFaultTheTargetNeverMetIsAbortedNotHeld is the control for the delivery
// guard, and the live run of this tier is what made it necessary.
//
// A DNS fault can be armed, confirmed at khaos's own resolver, and reach nothing
// at all: Go's HTTP transport resolves a name once per kept-alive connection, so
// a target holding a live connection never asks again. Measured on the range's
// own gateway at two lookups across forty-six requests. Reporting that as HELD
// is a clean survival khaos never earned.
func TestAFaultTheTargetNeverMetIsAbortedNotHeld(t *testing.T) {
	observation := Observation{
		Baseline:       healthyBaseline(),
		Fault:          heldFaultWindow(),
		Recovery:       healthyRecovery(),
		FaultConfirmed: true,
		ConfirmMethod:  "measured",
		Consulted:      2,
		ConsultedWhat:  ConsultsResolver,

		Delivered:     0,
		DeliveredWhat: deliveredResolveWhat,
	}

	verdict := Judge(observation, dnsPolarity)

	if verdict.Epistemic != Aborted {
		t.Fatalf(
			"epistemic %s, want %s: a fault the target never met is not a survival",
			verdict.Epistemic,
			Aborted,
		)
	}

	if verdict.Conclusive {
		t.Error("a fault the target never met produced a conclusive verdict")
	}

	// The SAME observation with delivery has to reach the ordinary reading, or
	// the guard is not reading the count it claims to and would abort every run.
	observation.Delivered = MinimumPaired

	delivered := Judge(observation, dnsPolarity)

	if delivered.Epistemic == Aborted {
		t.Errorf(
			"a delivered fault was also reported as never met (%s), so the guard "+
				"is not reading the delivery count",
			strings.Join(delivered.Reasons, "; "),
		)
	}
}

// TestTheDeliveryGuardIsOptional keeps the new field from changing every other
// family's verdict. An experiment that does not declare DeliveredWhat has no
// delivery question, and a zero count must mean nothing there.
func TestTheDeliveryGuardIsOptional(t *testing.T) {
	observation := Observation{
		Baseline:       healthyBaseline(),
		Fault:          heldFaultWindow(),
		Recovery:       healthyRecovery(),
		FaultConfirmed: true,
		ConfirmMethod:  "measured",
		Delivered:      0,
	}

	verdict := Judge(observation, outagePolarity)

	if verdict.Epistemic == Aborted {
		t.Fatalf(
			"an experiment that declares no delivery question was aborted for "+
				"not answering it: %s",
			strings.Join(verdict.Reasons, "; "),
		)
	}
}

// TestNoCacheIsUnsupportedNotSurvived is the control for CacheRequired. A target
// that re-resolves on every request has no cache lifetime to honour or ignore,
// so the two TTL faults have nothing to measure in it, and reporting that as a
// survival claims the target withstood something it never experienced.
func TestNoCacheIsUnsupportedNotSurvived(t *testing.T) {
	baseline := healthyBaseline()

	observation := Observation{
		Baseline:       baseline,
		Fault:          heldFaultWindow(),
		Recovery:       healthyRecovery(),
		FaultConfirmed: true,
		ConfirmMethod:  "measured",
		ConsultedWhat:  ConsultsResolver,
		CacheRequired:  cacheRequiredTTL,

		// Two whole lookups inside a baseline measured in seconds, against the
		// ten-minute lifetime khaos serves. A target honouring that resolves
		// once for the entire window.
		Consulted: queriesPerLookup * cacheLookupGrace,

		Delivered:     1,
		DeliveredWhat: deliveredResolveWhat,
	}

	verdict := Judge(observation, dnsPolarity)

	if verdict.Epistemic != Unsupported {
		t.Fatalf("epistemic %s, want %s", verdict.Epistemic, Unsupported)
	}

	// A target that DID cache has to reach the ordinary reading, or the
	// threshold is rejecting every run rather than the uncached ones.
	observation.Consulted = 1

	cached := Judge(observation, dnsPolarity)

	if cached.Epistemic == Unsupported {
		t.Errorf(
			"a target that resolved once across the whole baseline was reported "+
				"as having no cache: %s",
			strings.Join(cached.Reasons, "; "),
		)
	}

	// The BOUNDARY, both sides, because the whole defect was an off-by-four in
	// this comparison and a threshold with no control at its edge is a number
	// nobody checked.
	threshold := int64(queriesPerLookup * cacheLookupGrace)

	observation.Consulted = threshold - 1
	if Judge(observation, dnsPolarity).Epistemic == Unsupported {
		t.Errorf(
			"one query below the threshold was reported as no cache at all (%d of %d)",
			threshold-1,
			threshold,
		)
	}

	observation.Consulted = threshold
	if Judge(observation, dnsPolarity).Epistemic != Unsupported {
		t.Errorf(
			"exactly at the threshold was not reported as uncached (%d)",
			threshold,
		)
	}
}
