// ©AngelaMos | 2026
// forgery_verdict_test.go

package experiment

import (
	"strings"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const forgedDefectPhrase = "no signature at all and a header saying so"

// window builds an observation window from a disposition per stream, repeated
// enough times to clear every sample floor. Streams given no disposition are
// left absent, which is how an experiment that declares no forged or revoked
// stream looks.
func window(
	valid, invalid, forged, revoked probe.Disposition,
	n int,
) probe.Window {
	out := probe.Window{}

	for range n {
		at := time.Now().UTC()

		out.Record(
			probe.Outcome{At: at, Credential: probe.Valid, Disposition: valid},
		)
		out.Record(
			probe.Outcome{
				At:          at,
				Credential:  probe.Invalid,
				Disposition: invalid,
			},
		)

		if forged != "" {
			out.Record(
				probe.Outcome{
					At:          at,
					Credential:  probe.Forged,
					Disposition: forged,
				},
			)
		}

		if revoked != "" {
			out.Record(
				probe.Outcome{
					At:          at,
					Credential:  probe.Revoked,
					Disposition: revoked,
				},
			)
		}
	}

	return out
}

func forgeryObservation(
	baseline, fault probe.Window,
	expect probe.Expectation,
) Observation {
	return Observation{
		Baseline: baseline,
		Fault:    fault,
		Recovery: window(
			probe.Accepted,
			probe.Rejected,
			probe.Rejected,
			"",
			MinimumPaired,
		),
		FaultConfirmed: true,
		ConfirmMethod:  "khaos read its own forged token back off the provider",
		ForgedBaseline: expect,
		Defect:         forgedDefectPhrase,
	}
}

// One acceptance of a credential khaos PROVED defective is a proof, so the
// finding does not wait for the sample floor. The engine refuses to measure a
// fault it could not confirm, so by the time this is judged khaos has already
// read the malformed token back off its own provider.
func TestOneAcceptedForgedCredentialIsAConclusiveFinding(t *testing.T) {
	observation := forgeryObservation(
		window(
			probe.Accepted,
			probe.Rejected,
			probe.Accepted,
			"",
			MinimumPaired,
		),
		window(probe.Accepted, probe.Rejected, probe.Accepted, "", 1),
		probe.ExpectAccepted,
	)

	verdict := Judge(observation, idpPolarity)

	if verdict.Epistemic != Deviated || verdict.Direction != Permitted {
		t.Fatalf("verdict = %s / %s, want %s / %s (%s)",
			verdict.Epistemic, verdict.Direction, Deviated, Permitted,
			strings.Join(verdict.Reasons, "; "))
	}

	if !verdict.Conclusive {
		t.Fatal("a proven bypass was reported as inconclusive")
	}

	if !verdict.Defect {
		t.Fatal(
			"the identity tier declares PERMITTED a defect and this verdict did not",
		)
	}

	joined := strings.Join(verdict.Reasons, "; ")

	if !strings.Contains(joined, forgedDefectPhrase) {
		t.Fatalf(
			"the verdict does not name what was wrong with the credential: %s",
			joined,
		)
	}

	// The evidence claim lives in the per-trap CONFIRM line, not in this reason.
	// The shared reason used to assert that khaos had read the credential back
	// off the provider, which is true of the ten forgery traps and false of
	// `identity.jwks_unreachable`, whose confirmed observable is the key set
	// answering non-200 and which never inspects the credential at all.
	if observation.ConfirmMethod == "" {
		t.Fatal(
			"the run records no confirmation method, so nothing says how khaos established " +
				"the credential was defective before presenting it",
		)
	}
}

// The forged stream being refused throughout is the target behaving correctly,
// and it must not read as a finding.
func TestAForgedCredentialRefusedThroughoutIsAPass(t *testing.T) {
	observation := forgeryObservation(
		window(
			probe.Accepted,
			probe.Rejected,
			probe.Accepted,
			"",
			MinimumToClaimClosed,
		),
		window(
			probe.Accepted,
			probe.Rejected,
			probe.Rejected,
			"",
			MinimumToClaimClosed,
		),
		probe.ExpectAccepted,
	)

	verdict := Judge(observation, idpPolarity)

	if verdict.Epistemic != Passed || verdict.Direction != Held {
		t.Fatalf("verdict = %s / %s, want %s / %s (%s)",
			verdict.Epistemic, verdict.Direction, Passed, Held,
			strings.Join(verdict.Reasons, "; "))
	}

	if verdict.Defect {
		t.Fatal(
			"a target that refused every forged credential was reported as defective",
		)
	}
}

// The liveness guard that matters most in the whole family. A target not pointed
// at khaos's identity provider refuses every credential khaos mints, for reasons
// that have nothing to do with any trap. Without this guard every one of the ten
// forgery experiments reports a clean survival against a target it never tested.
func TestATargetThatNeverTrustedKhaosProviderVoidsTheRun(t *testing.T) {
	observation := forgeryObservation(
		// Note the valid stream IS accepted: the target is serving, enforcing,
		// and simply refusing khaos's issuer. That is exactly the case a naive
		// baseline check passes.
		window(
			probe.Accepted,
			probe.Rejected,
			probe.Rejected,
			"",
			MinimumToClaimClosed,
		),
		window(
			probe.Accepted,
			probe.Rejected,
			probe.Rejected,
			"",
			MinimumToClaimClosed,
		),
		probe.ExpectAccepted,
	)

	verdict := Judge(observation, idpPolarity)

	if verdict.Epistemic != BaselineNotMet {
		t.Fatalf(
			"epistemic = %s, want %s (%s)",
			verdict.Epistemic,
			BaselineNotMet,
			strings.Join(verdict.Reasons, "; "),
		)
	}

	if verdict.Conclusive {
		t.Fatal(
			"a run that never established the target trusts khaos's provider was conclusive",
		)
	}

	if !strings.Contains(
		strings.Join(verdict.Reasons, "; "),
		"resolves keys from the issuer",
	) {
		t.Fatalf("the refusal does not tell the operator what to check: %s",
			strings.Join(verdict.Reasons, "; "))
	}
}

// The mirror guard, for the one experiment whose forged credential is malformed
// from the start. A target that never refused it was not checking signatures, so
// its acceptance during the fault proves nothing changed.
func TestATargetThatNeverCheckedTheForgedCredentialVoidsTheRun(t *testing.T) {
	observation := forgeryObservation(
		window(
			probe.Accepted,
			probe.Rejected,
			probe.Accepted,
			"",
			MinimumToClaimClosed,
		),
		window(
			probe.Accepted,
			probe.Rejected,
			probe.Accepted,
			"",
			MinimumToClaimClosed,
		),
		probe.ExpectRejected,
	)

	verdict := Judge(observation, idpPolarity)

	if verdict.Epistemic != BaselineNotMet {
		t.Fatalf(
			"epistemic = %s, want %s (%s)",
			verdict.Epistemic,
			BaselineNotMet,
			strings.Join(verdict.Reasons, "; "),
		)
	}

	if !strings.Contains(
		strings.Join(verdict.Reasons, "; "),
		"not checking the property",
	) {
		t.Fatalf("the refusal does not say what was never established: %s",
			strings.Join(verdict.Reasons, "; "))
	}
}

// The two guards point in OPPOSITE directions, so each one has to be inert for
// the other's expectation. A guard that fired on both would void every run in
// the family.
func TestTheTwoForgedGuardsDoNotFireOnEachOthersExpectation(t *testing.T) {
	acceptedThroughout := window(
		probe.Accepted,
		probe.Rejected,
		probe.Accepted,
		"",
		MinimumToClaimClosed,
	)
	rejectedThroughout := window(
		probe.Accepted,
		probe.Rejected,
		probe.Rejected,
		"",
		MinimumToClaimClosed,
	)

	if _, unmet := baselineUnmet(
		acceptedThroughout,
		probe.ExpectAccepted,
		true,
		nil,
	); unmet {
		t.Error(
			"ExpectAccepted voided a baseline where the forged stream WAS accepted",
		)
	}

	if _, unmet := baselineUnmet(
		rejectedThroughout,
		probe.ExpectRejected,
		true,
		nil,
	); unmet {
		t.Error(
			"ExpectRejected voided a baseline where the forged stream WAS rejected",
		)
	}
}

func TestAnAbsentForgedStreamIsAllowedOnlyWhenNotRequired(t *testing.T) {
	bare := window(probe.Accepted, probe.Rejected, "", "", MinimumToClaimClosed)

	for _, expect := range []probe.Expectation{"", probe.ExpectAccepted, probe.ExpectRejected} {
		if _, unmet := baselineUnmet(
			bare, expect, true, nil,
		); unmet != (expect != "") {
			t.Errorf(
				"missing forged stream handled incorrectly under expectation %q",
				expect,
			)
		}
	}
}

// A forged acceptance and a monotonic leak in the same run are two different
// observations, and both get stated. Returning on the first one dropped the
// other from a run where both were true.
func TestEveryStreamThatLeakedIsStated(t *testing.T) {
	observation := forgeryObservation(
		window(
			probe.Accepted,
			probe.Rejected,
			probe.Accepted,
			"",
			MinimumPaired,
		),
		window(
			probe.Accepted,
			probe.Accepted,
			probe.Accepted,
			"",
			MinimumPaired,
		),
		probe.ExpectAccepted,
	)

	verdict := Judge(observation, idpPolarity)

	joined := strings.Join(verdict.Reasons, "; ")

	if !strings.Contains(joined, "khaos minted with") {
		t.Errorf("the forged stream's finding is missing: %s", joined)
	}

	if !strings.Contains(joined, "had already refused") {
		t.Errorf("the monotonic finding is missing: %s", joined)
	}
}

// The idleness discriminator is for CACHING causes. A forged credential getting
// through is not a caching bug, so a forgery experiment must not spend a minute
// of the operator's run pausing traffic to diagnose one.
func TestAForgedFindingAloneDoesNotAskForTheIdlenessDiscriminator(
	t *testing.T,
) {
	observation := forgeryObservation(
		window(
			probe.Accepted,
			probe.Rejected,
			probe.Accepted,
			"",
			MinimumPaired,
		),
		window(
			probe.Accepted,
			probe.Rejected,
			probe.Accepted,
			"",
			MinimumPaired,
		),
		probe.ExpectAccepted,
	)

	if !Leaking(observation) {
		t.Fatal(
			"a proven forged bypass did not register as a leak, so no cause would ever be diagnosed",
		)
	}

	verdict := Judge(observation, idpPolarity)

	// Nothing resumed, because no forgery experiment sets IdleFor, so the cause
	// stays honestly UNDIAGNOSED rather than being guessed.
	if verdict.Cause != Undiagnosed {
		t.Fatalf(
			"cause = %s, want %s on a run with no idleness phase",
			verdict.Cause,
			Undiagnosed,
		)
	}
}

// A target whose key cache never expires is serving perfectly well and simply
// does not know khaos's keys, which khaos regenerates every run. The generic
// refusal says the target was not serving, which sends an operator to look at a
// service that is fine.
//
// Measured against the range's forever-cache gateway: a second consecutive run
// could not establish a baseline, and nothing in the output said why.
func TestTheIdentityTierSaysWhyItsOwnCredentialWasRefused(t *testing.T) {
	refused := window(
		probe.Rejected,
		probe.Rejected,
		"",
		"",
		MinimumToClaimClosed,
	)

	minted, unmet := baselineUnmet(refused, "", true, nil)
	if !unmet {
		t.Fatal(
			"a baseline where khaos's own credential was never accepted was not voided",
		)
	}

	operator, unmet := baselineUnmet(refused, "", false, nil)
	if !unmet {
		t.Fatal(
			"a baseline where the operator's credential was never accepted was not voided",
		)
	}

	if minted == operator {
		t.Fatal(
			"the identity tier and the operator-supplied tier give the same refusal, so the " +
				"one case where the generic wording is misleading reads identically",
		)
	}

	for _, want := range []string{"key set", "fresh key set every run", "Restart the target"} {
		if !strings.Contains(minted, want) {
			t.Errorf(
				"the identity tier's refusal does not mention %q: %s",
				want,
				minted,
			)
		}
	}

	if strings.Contains(minted, "was not serving") {
		t.Errorf(
			"the identity tier's refusal still claims the target was not serving: %s",
			minted,
		)
	}
}

// Recovery is three-valued, and "not observed" is the state that used to lie.
func TestRecoveryDistinguishesUnobservedFromRecovered(t *testing.T) {
	healthy := window(
		probe.Accepted,
		probe.Rejected,
		"",
		"",
		MinimumToClaimClosed,
	)

	cases := []struct {
		name     string
		recovery probe.Window
		want     Recovery
	}{
		{"healthy run of pairs", healthy, Recovered},
		{"no evidence at all", probe.Window{}, Unobserved},
		{
			"measured and still broken",
			window(probe.Rejected, probe.Rejected, "", "", MinimumPaired),
			Degraded,
		},
	}

	for _, each := range cases {
		t.Run(each.name, func(t *testing.T) {
			observation := Observation{
				Baseline:       healthy,
				Fault:          healthy,
				Recovery:       each.recovery,
				FaultConfirmed: true,
			}

			verdict := Judge(observation, idpPolarity)

			if verdict.Recovery != each.want {
				t.Fatalf(
					"recovery = %q, want %q (%s)",
					verdict.Recovery,
					each.want,
					strings.Join(verdict.Reasons, "; "),
				)
			}
		})
	}
}

// An unobserved recovery must say so rather than pass silently.
func TestAnUnobservedRecoveryIsWarnedAboutRatherThanAssumed(t *testing.T) {
	healthy := window(
		probe.Accepted,
		probe.Rejected,
		"",
		"",
		MinimumToClaimClosed,
	)

	verdict := Judge(Observation{
		Baseline:       healthy,
		Fault:          healthy,
		FaultConfirmed: true,
	}, idpPolarity)

	joined := strings.Join(verdict.Reasons, "; ")

	if !strings.Contains(joined, "not the same as it having come back") {
		t.Fatalf("khaos assumed a recovery it never measured: %s", joined)
	}

	found := false
	for _, warning := range verdict.Warnings {
		if warning == WarningRecoveryUnobserved {
			found = true
		}
	}

	if !found {
		t.Fatalf("no recovery-unobserved warning: %v", verdict.Warnings)
	}
}

// A required stream with no usable decisions cannot support a clean result.
// Thirty valid acceptances and thirty invalid refusals used to clear the floor
// while every forged probe failed, and the run reported that the target refused
// a credential it was never successfully shown.
func TestARequiredForgedStreamWithNoDecisionsCannotReportHeld(t *testing.T) {
	baseline := window(
		probe.Accepted,
		probe.Rejected,
		probe.Accepted,
		"",
		MinimumToClaimClosed,
	)

	fault := probe.Window{}
	for range MinimumToClaimClosed {
		fault.Record(
			probe.Outcome{Credential: probe.Valid, Disposition: probe.Accepted},
		)
		fault.Record(
			probe.Outcome{
				Credential:  probe.Invalid,
				Disposition: probe.Rejected,
			},
		)
		fault.Record(
			probe.Outcome{
				Credential:  probe.Forged,
				Disposition: probe.ProbeFailed,
			},
		)
	}

	observation := Observation{
		Baseline: baseline,
		Fault:    fault,
		Recovery: window(
			probe.Accepted,
			probe.Rejected,
			"",
			"",
			MinimumToClaimClosed,
		),
		FaultConfirmed: true,
		ForgedBaseline: probe.ExpectAccepted,
	}

	verdict := Judge(observation, idpPolarity)

	if verdict.Epistemic == Passed {
		t.Fatalf(
			"a run where every forged probe failed reported a clean survival (%s)",
			strings.Join(verdict.Reasons, "; "),
		)
	}

	if verdict.Epistemic != ProbeError {
		t.Fatalf("epistemic = %s, want %s", verdict.Epistemic, ProbeError)
	}

	// The control: the same run with real decisions on that stream judges
	// normally, or this guard would have deleted the clean-result path.
	decided := window(
		probe.Accepted,
		probe.Rejected,
		probe.Rejected,
		"",
		MinimumToClaimClosed,
	)
	observation.Fault = decided

	if verdict := Judge(observation, idpPolarity); verdict.Epistemic != Passed {
		t.Fatalf("a run WITH forged decisions was judged %s, want %s (%s)",
			verdict.Epistemic, Passed, strings.Join(verdict.Reasons, "; "))
	}
}

// The guard requiring this experiment's own stream to have been MEASURED
// must count DECISIONS, not transport: Countable() excludes only khaos's own
// failures, so a stream of timeouts would clear the floor and produce a hold
// about a credential the target was never observed to judge.
func TestATimedOutForgedStreamIsNotEvidenceTheTargetDecided(t *testing.T) {
	for _, disposition := range []probe.Disposition{
		probe.Unreachable,
		probe.Unavailable,
	} {
		t.Run(string(disposition), func(t *testing.T) {
			observation := forgeryObservation(
				window(
					probe.Accepted,
					probe.Rejected,
					probe.Accepted,
					"",
					MinimumPaired,
				),
				window(
					probe.Accepted,
					probe.Rejected,
					disposition,
					"",
					MinimumPaired,
				),
				probe.ExpectAccepted,
			)

			verdict := Judge(observation, idpPolarity)

			if verdict.Epistemic != ProbeError {
				t.Fatalf(
					"verdict = %s / %s conclusive=%v, want %s: every forged probe was a %s, so the target was never seen to decide about the credential this experiment is about (%s)",
					verdict.Epistemic,
					verdict.Direction,
					verdict.Conclusive,
					ProbeError,
					disposition,
					strings.Join(verdict.Reasons, "; "),
				)
			}
		})
	}
}

// The other half, because a guard that rejects everything is not a guard: a
// forged stream the target actually DECIDED about still clears the floor.
func TestADecidedForgedStreamStillClearsTheFloor(t *testing.T) {
	observation := forgeryObservation(
		window(
			probe.Accepted,
			probe.Rejected,
			probe.Accepted,
			"",
			MinimumPaired,
		),
		window(
			probe.Accepted,
			probe.Rejected,
			probe.Rejected,
			"",
			MinimumPaired,
		),
		probe.ExpectAccepted,
	)

	verdict := Judge(observation, idpPolarity)

	if verdict.Epistemic == ProbeError {
		t.Fatalf(
			"a forged stream the target refused every time was reported unmeasurable: %s",
			strings.Join(verdict.Reasons, "; "),
		)
	}
}
