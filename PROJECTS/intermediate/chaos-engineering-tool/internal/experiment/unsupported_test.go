// ©AngelaMos | 2026
// unsupported_test.go

package experiment

import (
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

// Go's crypto/x509 performs no revocation checking of any kind and has no
// option to turn it on, so a Go target handed a certificate revoked in a valid,
// in-date, correctly signed CRL from its own issuer accepts it with a nil
// error. Three readings of that are available and two of them are lies:
//
//   - PASSED is the worst. The certificate really was revoked and really was
//     used, and khaos would be reporting a clean survival.
//   - PERMITTED accuses the target of skipping a check it never had.
//   - UNSUPPORTED says what happened: there was no revocation check to fail,
//     so khaos makes no security claim.
//
// The distinction is MEASURED. khaos counts what the target fetched from the
// authority, so a target that never asked is an observation, and a target that
// asked and used the certificate anyway is still the defect it is.

// revocationObservation is a run where the fault landed, the baseline was
// healthy, and the target accepted the revoked credential throughout. Only
// `consulted` varies, which is the whole point: everything else about these two
// runs is identical and the verdict has to differ.
func revocationObservation(consulted int64) Observation {
	return Observation{
		FaultConfirmed: true,
		Baseline:       healthyBaseline(),
		Fault: probe.Window{
			Valid: stream(
				probe.Valid,
				repeat(probe.Accepted, MinimumPaired)...),
			Invalid: stream(
				probe.Invalid,
				repeat(probe.Rejected, MinimumPaired)...),
		},
		Recovery: healthyRecovery(),

		Unsupportable: "revocation checking",
		ConsultedWhat: "khaos's CRL distribution point",
		Consulted:     consulted,
	}
}

func TestATargetThatNeverCheckedRevocationIsUnsupportedNotPassed(t *testing.T) {
	verdict := Judge(revocationObservation(0), authPolarity)

	if verdict.Epistemic != Unsupported {
		t.Fatalf(
			"epistemic = %s, want %s; the target accepted a certificate khaos revoked at its own CA, and reporting that as anything else is either an accusation about a check the platform does not have or a clean bill of health for a revoked certificate in use",
			verdict.Epistemic,
			Unsupported,
		)
	}

	if verdict.Epistemic == Passed {
		t.Fatal("a revoked certificate in active use was reported as a pass")
	}

	if verdict.Direction == Permitted {
		t.Fatal(
			"the verdict accused the target of permitting a bypass, which requires a check to have been bypassed",
		)
	}

	if verdict.Conclusive {
		t.Fatal(
			"an unsupported run was marked conclusive, so the exit code would claim khaos had established something",
		)
	}

	if len(verdict.Reasons) == 0 {
		t.Fatal(
			"the verdict carries no reason, so an operator reading `unsupported` cannot tell whether khaos declined to claim or simply broke",
		)
	}
}

// The other direction, and the one that makes the verdict honest rather than an
// excuse. A target that DID fetch the CRL and then used the certificate anyway
// has a revocation check, and that check failed.
func TestATargetThatCheckedAndAcceptedAnywayIsStillADefect(t *testing.T) {
	verdict := Judge(revocationObservation(12), authPolarity)

	if verdict.Epistemic == Unsupported {
		t.Fatal(
			"a target that fetched khaos's CRL twelve times during the baseline and then accepted a certificate listed in it was excused as unsupported; the check exists and it failed",
		)
	}

	if verdict.Epistemic != Passed && verdict.Epistemic != Deviated {
		t.Fatalf(
			"epistemic = %s; a run with a healthy baseline, a confirmed fault and a consulted endpoint is measurable and has to reach a directional reading",
			verdict.Epistemic,
		)
	}
}

// The guard only applies to experiments that DECLARE the check optional.
// Without that, a never-consulted endpoint would be excused everywhere,
// including for the three introspection experiments whose whole liveness
// problem is that a target doing purely local validation never calls them.
func TestANeverConsultedEndpointIsStillVoidWhenTheCheckIsNotOptional(
	t *testing.T,
) {
	observation := revocationObservation(0)
	observation.Unsupportable = ""

	verdict := Judge(observation, authPolarity)

	if verdict.Epistemic == Unsupported {
		t.Fatal(
			"an experiment that did not declare its check optional got the unsupported reading anyway, which would excuse every fault aimed at an endpoint the target happens not to use",
		)
	}

	if verdict.Epistemic != BaselineNotMet {
		t.Fatalf(
			"epistemic = %s, want %s; a fault aimed at an endpoint the target never touched is a void run",
			verdict.Epistemic,
			BaselineNotMet,
		)
	}
}
