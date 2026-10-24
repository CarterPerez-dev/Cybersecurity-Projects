// ©AngelaMos | 2026
// decision_evidence_test.go

package experiment

import (
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

func TestNonDecisionsCannotEstablishAHold(t *testing.T) {
	for _, disposition := range []probe.Disposition{
		probe.Redirected, probe.Throttled, probe.TimedOut, probe.ProbeFailed,
	} {
		for _, required := range []probe.Credential{probe.Forged, probe.Revoked} {
			t.Run(string(required)+"/"+string(disposition), func(t *testing.T) {
				observation := Observation{
					Baseline: healthyBaseline(), Recovery: healthyRecovery(),
					Fault: window(
						probe.Accepted,
						probe.Rejected,
						"",
						"",
						MinimumToClaimClosed,
					),
					FaultConfirmed: true,
				}
				if required == probe.Forged {
					observation.ForgedBaseline = probe.ExpectAccepted
				}
				for range MinimumToClaimClosed {
					observation.Baseline.Record(probe.Outcome{
						Credential: required, Disposition: probe.Accepted,
					})
					observation.Fault.Record(probe.Outcome{
						Credential: required, Disposition: disposition,
					})
				}
				verdict := Judge(observation, idpPolarity)
				if verdict.Conclusive || verdict.Defect {
					t.Fatalf("non-decisions concluded: %+v", verdict)
				}
			})
		}
	}
}

func TestRedirectedPrimaryStreamsCannotEstablishAHold(t *testing.T) {
	for _, fault := range []probe.Window{
		window(probe.Accepted, probe.Redirected, "", "", MinimumToClaimClosed),
		window(probe.Redirected, probe.Rejected, "", "", MinimumToClaimClosed),
	} {
		verdict := Judge(Observation{
			Baseline: healthyBaseline(), Fault: fault,
			Recovery: healthyRecovery(), FaultConfirmed: true,
		}, idpPolarity)
		if verdict.Conclusive || verdict.Direction == Held {
			t.Fatalf("redirects concluded a hold: %+v", verdict)
		}
	}
}

func TestFixedExpiryCanLapseDuringAPauseAfterALongerSteadyWindow(t *testing.T) {
	const steady = 30 * time.Second
	const idle = 10 * time.Second
	const expires = 35 * time.Second
	var resumed probe.Stream
	for sample := steady + idle; sample < steady+idle+5*time.Second; sample += time.Second {
		disposition := probe.Accepted
		if sample >= expires {
			disposition = probe.Rejected
		}
		resumed.Outcomes = append(
			resumed.Outcomes, probe.Outcome{Disposition: disposition},
		)
	}
	cause, _ := resolveCause(resumed, steady, idle, nil)
	if cause != LapsedOnPause {
		t.Fatalf("a fixed 35s expiry was diagnosed as %s", cause)
	}
}
