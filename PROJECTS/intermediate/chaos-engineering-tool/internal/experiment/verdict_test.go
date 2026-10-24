// ©AngelaMos | 2026
// verdict_test.go

package experiment

import (
	"strings"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

func stream(
	credential probe.Credential,
	dispositions ...probe.Disposition,
) probe.Stream {
	s := probe.Stream{Credential: credential}
	base := time.Now().UTC()

	for i, d := range dispositions {
		s.Outcomes = append(s.Outcomes, probe.Outcome{
			At:          base.Add(time.Duration(i) * time.Second),
			Credential:  credential,
			Disposition: d,
		})
	}

	return s
}

func repeat(d probe.Disposition, n int) []probe.Disposition {
	out := make([]probe.Disposition, n)
	for i := range out {
		out[i] = d
	}
	return out
}

func healthyBaseline() probe.Window {
	return probe.Window{
		Valid: stream(probe.Valid, repeat(probe.Accepted, MinimumPaired)...),
		Invalid: stream(
			probe.Invalid,
			repeat(probe.Rejected, MinimumPaired)...),
	}
}

func healthyRecovery() probe.Window {
	return probe.Window{
		Valid:   stream(probe.Valid, repeat(probe.Accepted, 2)...),
		Invalid: stream(probe.Invalid, repeat(probe.Rejected, 2)...),
	}
}

var authPolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "an authentication check that stops enforcing is catastrophic",
}

func TestTheVerdictTruthTable(t *testing.T) {
	cases := []struct {
		name          string
		fault         probe.Window
		wantEpistemic Epistemic
		wantDirection Direction
		wantDefect    bool
	}{
		{
			name: "survived with enforcement intact",
			fault: probe.Window{
				Valid: stream(
					probe.Valid,
					repeat(probe.Accepted, MinimumPaired)...),
				Invalid: stream(
					probe.Invalid,
					repeat(probe.Rejected, MinimumPaired)...),
			},
			wantEpistemic: Passed,
			wantDirection: Held,
		},
		{
			name: "failed closed, legitimate traffic refused",
			fault: probe.Window{
				Valid: stream(
					probe.Valid,
					repeat(probe.Rejected, MinimumPaired)...),
				Invalid: stream(
					probe.Invalid,
					repeat(probe.Rejected, MinimumPaired)...),
			},
			wantEpistemic: Deviated,
			wantDirection: Denied,
		},
		{
			name: "failed open, a rejected credential was later accepted",
			fault: probe.Window{
				Valid: stream(
					probe.Valid,
					repeat(probe.Accepted, MinimumPaired)...),
				Invalid: stream(
					probe.Invalid,
					repeat(probe.Accepted, MinimumPaired)...),
			},
			wantEpistemic: Deviated,
			wantDirection: Permitted,
			wantDefect:    true,
		},
		{
			name: "stopped answering entirely",
			fault: probe.Window{
				Valid: stream(
					probe.Valid,
					repeat(probe.Unavailable, MinimumPaired)...),
				Invalid: stream(
					probe.Invalid,
					repeat(probe.Unavailable, MinimumPaired)...),
			},
			wantEpistemic: Deviated,
			wantDirection: Crashed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict := Judge(Observation{
				FaultConfirmed: true,
				Baseline:       healthyBaseline(),
				Fault:          tc.fault,
				Recovery:       healthyRecovery(),
			}, authPolarity)

			if verdict.Epistemic != tc.wantEpistemic {
				t.Fatalf(
					"epistemic = %s, want %s (%s)",
					verdict.Epistemic,
					tc.wantEpistemic,
					strings.Join(verdict.Reasons, "; "),
				)
			}

			if verdict.Direction != tc.wantDirection {
				t.Fatalf(
					"direction = %s, want %s (%s)",
					verdict.Direction,
					tc.wantDirection,
					strings.Join(verdict.Reasons, "; "),
				)
			}

			if verdict.Defect != tc.wantDefect {
				t.Fatalf("defect = %v, want %v", verdict.Defect, tc.wantDefect)
			}
		})
	}
}

func TestATargetThatWasNeverEnforcingIsNotAPass(t *testing.T) {
	baseline := healthyBaseline()
	baseline.Invalid = stream(
		probe.Invalid,
		repeat(probe.Accepted, MinimumPaired)...)

	verdict := Judge(Observation{
		FaultConfirmed: true,
		Baseline:       baseline,
		Fault: probe.Window{
			Valid: stream(
				probe.Valid,
				repeat(probe.Accepted, MinimumPaired)...),
			Invalid: stream(
				probe.Invalid,
				repeat(probe.Accepted, MinimumPaired)...),
		},
		Recovery: healthyRecovery(),
	}, authPolarity)

	if verdict.Epistemic != BaselineNotMet {
		t.Fatalf(
			"epistemic = %s, want %s; a target that accepted an invalid credential BEFORE "+
				"the fault was never enforcing, and a two-valued verdict would report this as a clean pass "+
				"while teaching the operator nothing",
			verdict.Epistemic,
			BaselineNotMet,
		)
	}

	if verdict.Conclusive {
		t.Fatal(
			"a run against a target that was not enforcing was marked conclusive",
		)
	}

	if verdict.Direction != Undetermined {
		t.Fatalf("direction = %s, want %s", verdict.Direction, Undetermined)
	}
}

func TestAServiceStillServingAValidCredentialIsNotPermitted(t *testing.T) {
	// A service that keeps honouring a credential that was valid when the
	// outage began is behaving CORRECTLY. Only a credential it had already
	// rejected, later accepted, is a control that stopped enforcing.
	verdict := Judge(Observation{
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
	}, authPolarity)

	if verdict.Direction == Permitted {
		t.Fatal(
			"a service that kept serving a still-valid credential was reported as failing open",
		)
	}

	if verdict.Direction != Held {
		t.Fatalf("direction = %s, want %s", verdict.Direction, Held)
	}
}

func TestAnEarlyAcceptanceFollowedByEnforcementIsNotPermitted(t *testing.T) {
	// A target that accepted once while warming up and then enforced
	// consistently has not stopped enforcing. Counting acceptances instead of
	// ordering them calls this a failure to enforce.
	baseline := healthyBaseline()
	baseline.Invalid = stream(
		probe.Invalid,
		probe.Accepted,
		probe.Rejected,
		probe.Rejected,
		probe.Rejected,
		probe.Rejected,
	)

	verdict := Judge(Observation{
		FaultConfirmed: true,
		Baseline:       baseline,
		Fault: probe.Window{
			Valid: stream(
				probe.Valid,
				repeat(probe.Accepted, MinimumPaired)...),
			Invalid: stream(
				probe.Invalid,
				repeat(probe.Rejected, MinimumPaired)...),
		},
		Recovery: healthyRecovery(),
	}, authPolarity)

	if verdict.Direction == Permitted {
		t.Fatal(
			"an acceptance that happened BEFORE the target ever enforced was counted as the " +
				"control giving way; the test is 'a credential it had already refused was later " +
				"honoured', not 'something was accepted at some point'",
		)
	}

	if verdict.Direction != Held {
		t.Fatalf("direction = %s, want %s", verdict.Direction, Held)
	}
}

func TestPermittedRequiresAPriorRejection(t *testing.T) {
	baseline := healthyBaseline()
	baseline.Invalid = stream(
		probe.Invalid,
		repeat(probe.Unavailable, MinimumPaired)...)

	verdict := Judge(Observation{
		FaultConfirmed: true,
		Baseline:       baseline,
		Fault: probe.Window{
			Valid: stream(
				probe.Valid,
				repeat(probe.Accepted, MinimumPaired)...),
			Invalid: stream(
				probe.Invalid,
				repeat(probe.Accepted, MinimumPaired)...),
		},
		Recovery: healthyRecovery(),
	}, authPolarity)

	if verdict.Epistemic != BaselineNotMet {
		t.Fatalf(
			"epistemic = %s; with no rejection ever observed there is no enforcement to lose, "+
				"so there is nothing to conclude",
			verdict.Epistemic,
		)
	}
}

func TestAThinSampleIsNotConclusive(t *testing.T) {
	thin := probe.Window{
		Valid:   stream(probe.Valid, probe.Accepted),
		Invalid: stream(probe.Invalid, probe.Rejected),
	}

	for _, tc := range []struct {
		name        string
		observation Observation
	}{
		{"thin fault window after a healthy baseline", Observation{FaultConfirmed: true, Baseline: healthyBaseline(), Fault: thin}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict := Judge(tc.observation, authPolarity)

			if verdict.Conclusive {
				t.Fatal("a run with too few samples was marked conclusive")
			}

			if verdict.Epistemic != ProbeError {
				t.Fatalf(
					"epistemic = %s, want %s",
					verdict.Epistemic,
					ProbeError,
				)
			}
		})
	}
}

func TestAFaultThatNeverLandedCannotProduceAVerdict(t *testing.T) {
	verdict := Judge(Observation{
		FaultConfirmed: false,
		Baseline:       healthyBaseline(),
		Fault:          healthyBaseline(),
		Recovery:       healthyRecovery(),
	}, authPolarity)

	if verdict.Epistemic != Aborted {
		t.Fatalf(
			"epistemic = %s, want %s; nothing measured can be attributed to a fault "+
				"that was never confirmed applied",
			verdict.Epistemic,
			Aborted,
		)
	}

	if verdict.Conclusive {
		t.Fatal("a run whose fault never landed was marked conclusive")
	}
}

func TestPolarityDecidesWhetherADeviationIsADefect(t *testing.T) {
	failedOpen := Observation{
		FaultConfirmed: true,
		Baseline:       healthyBaseline(),
		Fault: probe.Window{
			Valid: stream(
				probe.Valid,
				repeat(probe.Accepted, MinimumPaired)...),
			Invalid: stream(
				probe.Invalid,
				repeat(probe.Accepted, MinimumPaired)...),
		},
		Recovery: healthyRecovery(),
	}

	strict := Judge(failedOpen, Polarity{Defects: []Direction{Permitted}})
	if !strict.Defect {
		t.Fatal(
			"failing open was not a defect for a control that declares it one",
		)
	}

	lenient := Judge(failedOpen, Polarity{Defects: []Direction{Denied}})
	if lenient.Defect {
		t.Fatal(
			"failing open was called a defect for a control that deliberately tolerates it; " +
				"a rate-limit counter that stops counting when its datastore is unreachable is a " +
				"trade, not a bug",
		)
	}

	if lenient.Direction != Permitted {
		t.Fatalf(
			"direction = %s; polarity changes whether a deviation is a defect, never which "+
				"direction it went",
			lenient.Direction,
		)
	}
}

func TestAFailureToRecoverIsRecorded(t *testing.T) {
	verdict := Judge(Observation{
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
		Recovery: probe.Window{
			Valid:   stream(probe.Valid, repeat(probe.Unavailable, 2)...),
			Invalid: stream(probe.Invalid, repeat(probe.Unavailable, 2)...),
		},
	}, authPolarity)

	if verdict.Epistemic != Deviated {
		t.Fatalf(
			"epistemic = %s; a target that never came back after the revert did not pass",
			verdict.Epistemic,
		)
	}
}

func TestEveryVerdictCarriesAReason(t *testing.T) {
	observations := map[string]Observation{
		"not applied": {FaultConfirmed: false},
		"thin":        {FaultConfirmed: true, Baseline: healthyBaseline()},
		"no baseline": {
			FaultConfirmed: true,
			Baseline: probe.Window{
				Valid: stream(
					probe.Valid,
					repeat(probe.Accepted, MinimumPaired)...),
				Invalid: stream(
					probe.Invalid,
					repeat(probe.Accepted, MinimumPaired)...),
			},
			Fault: healthyBaseline(),
		},
		"held": {
			FaultConfirmed: true,
			Baseline:       healthyBaseline(),
			Fault:          healthyBaseline(),
			Recovery:       healthyRecovery(),
		},
	}

	for name, observation := range observations {
		t.Run(name, func(t *testing.T) {
			verdict := Judge(observation, authPolarity)
			if len(verdict.Reasons) == 0 {
				t.Fatal("a verdict was produced with no stated reason")
			}
			for _, reason := range verdict.Reasons {
				if strings.TrimSpace(reason) == "" {
					t.Fatal("a verdict reason was empty")
				}
			}
		})
	}
}

// TestFailingClosedIsDeclaredPerControl is the control for ClosedWhen, and it
// is a control at BOTH ends: the same window reads HELD when nothing is
// declared and DENIED when unavailability is, so neither the default nor the
// declaration can be deleted without turning something red.
//
// It exists because a 503 is deliberately not a statement about a credential,
// and the pooled-credential experiments measure a service whose fail-closed
// outcome is exactly that. Measured against the range before this existed:
// `--pool-mode bounded` lost its database access, answered 503 for 35 of 76
// probes, and khaos reported `passed / HELD` - the correct behaviour read as
// the defect.
func TestFailingClosedIsDeclaredPerControl(t *testing.T) {
	// Accepted first, so the latch the ordering rule needs is armed, then the
	// service stops being able to answer at all.
	faulted := probe.Window{
		Valid: stream(
			probe.Valid,
			append(
				repeat(probe.Accepted, 4),
				repeat(probe.Unavailable, MinimumPaired)...,
			)...),
		Invalid: stream(
			probe.Invalid,
			repeat(probe.Rejected, MinimumPaired+4)...),
	}

	cases := []struct {
		name       string
		closedWhen []probe.Disposition
		want       Direction
	}{
		{
			name: "nothing declared, so only a refusal counts",
			want: Undetermined,
		},
		{
			name:       "unavailability declared, so losing access counts",
			closedWhen: []probe.Disposition{probe.Unavailable},
			want:       Denied,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			verdict := Judge(Observation{
				FaultConfirmed: true,
				Baseline:       healthyBaseline(),
				Fault:          faulted,
				Recovery:       healthyRecovery(),
				ClosedWhen:     test.closedWhen,
			}, authPolarity)

			if verdict.Direction != test.want {
				t.Fatalf(
					"direction = %q, want %q (reasons: %v)",
					verdict.Direction,
					test.want,
					verdict.Reasons,
				)
			}
		})
	}
}

// TestADeclaredClosureNeverHidesARefusal pins the other half of the rule: the
// declared set EXTENDS what counts as closed and never replaces it, so an
// experiment that declares unavailability still reports a plain refusal.
func TestADeclaredClosureNeverHidesARefusal(t *testing.T) {
	verdict := Judge(Observation{
		FaultConfirmed: true,
		Baseline:       healthyBaseline(),
		Fault: probe.Window{
			Valid: stream(
				probe.Valid,
				append(
					repeat(probe.Accepted, 4),
					repeat(probe.Rejected, MinimumPaired)...,
				)...),
			Invalid: stream(
				probe.Invalid,
				repeat(probe.Rejected, MinimumPaired+4)...),
		},
		Recovery:   healthyRecovery(),
		ClosedWhen: []probe.Disposition{probe.Unavailable},
	}, authPolarity)

	if verdict.Direction != Denied {
		t.Fatalf(
			"direction = %q, want %q; declaring one closure must not stop a refusal counting",
			verdict.Direction,
			Denied,
		)
	}
}

// Recovery is judged over the WHOLE window: a run that collapses after two
// good pairs is not recovered, and a late recovery still counts.
func TestRecoveryIsJudgedAtTheEndOfTheWindowNotTheFirstGoodRun(t *testing.T) {
	healthy := func(n int) []probe.Disposition {
		out := make([]probe.Disposition, n)
		for i := range out {
			out[i] = probe.Accepted
		}
		return out
	}

	for name, tc := range map[string]struct {
		valid []probe.Disposition
		want  Recovery
	}{
		"healthy throughout": {
			valid: healthy(6),
			want:  Recovered,
		},
		"two good pairs then collapse": {
			valid: []probe.Disposition{
				probe.Accepted,
				probe.Accepted,
				probe.Unreachable,
				probe.Unreachable,
				probe.Unreachable,
				probe.Unreachable,
			},
			want: Degraded,
		},
		"broken first then a full healthy run": {
			valid: []probe.Disposition{
				probe.Unreachable,
				probe.Unreachable,
				probe.Accepted,
				probe.Accepted,
				probe.Accepted,
			},
			want: Recovered,
		},
		"alternating never settles": {
			valid: []probe.Disposition{
				probe.Accepted,
				probe.Unreachable,
				probe.Accepted,
				probe.Unreachable,
				probe.Accepted,
			},
			want: Degraded,
		},
		"recovers only on the very last pair": {
			valid: []probe.Disposition{
				probe.Unreachable,
				probe.Unreachable,
				probe.Unreachable,
				probe.Accepted,
			},
			want: Degraded,
		},
		// A single trailing blip must NOT withdraw a recovery: this verdict
		// maps to the one exit code no --fail-on value can suppress.
		"one trailing blip after a long healthy run": {
			valid: append(healthy(12), probe.Unreachable),
			want:  Recovered,
		},
		"two trailing blips are a sustained collapse": {
			valid: append(
				healthy(12),
				probe.Unreachable,
				probe.Unreachable,
			),
			want: Degraded,
		},
	} {
		t.Run(name, func(t *testing.T) {
			recovery := probe.Window{}

			for _, disposition := range tc.valid {
				at := time.Now().UTC()
				recovery.Record(probe.Outcome{
					At:          at,
					Credential:  probe.Valid,
					Disposition: disposition,
				})
				recovery.Record(probe.Outcome{
					At:          at,
					Credential:  probe.Invalid,
					Disposition: probe.Rejected,
				})
			}

			got := recoveryOf(recovery, nil)
			if got != tc.want {
				t.Fatalf("recovery = %s, want %s", got, tc.want)
			}
		})
	}
}
