// ©AngelaMos | 2026
// shift_test.go

package experiment

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	whatShifted = "khaos's dependency answered 503 to everything"

	deniedCredentialRefused = "the credential the dependency denied"
)

// deniedWindow is the FIRST fault phase: the dependency answered a definitive
// 403 for one credential and kept allowing the other.
func deniedWindow(revoked probe.Disposition) probe.Window {
	return probe.Window{
		Valid: stream(probe.Valid, repeat(probe.Accepted, MinimumPaired)...),
		Invalid: stream(
			probe.Invalid,
			repeat(probe.Rejected, MinimumPaired)...),
		Revoked: stream(probe.Revoked, repeat(revoked, MinimumPaired)...),
	}
}

// unknownWindow is the SECOND phase: the dependency answered nothing at all,
// so what the valid stream does here is a different branch of the caller.
func unknownWindow(valid probe.Disposition) probe.Window {
	return probe.Window{
		Valid: stream(probe.Valid, repeat(valid, MinimumPaired)...),
		Invalid: stream(
			probe.Invalid,
			repeat(probe.Rejected, MinimumPaired)...),
		Revoked: stream(probe.Revoked, repeat(valid, MinimumPaired)...),
	}
}

func shifted(revoked, validUnderOutage probe.Disposition) Observation {
	return Observation{
		Baseline: probe.Window{
			Valid: stream(
				probe.Valid,
				repeat(probe.Accepted, MinimumPaired)...),
			Invalid: stream(
				probe.Invalid,
				repeat(probe.Rejected, MinimumPaired)...),
			Revoked: stream(
				probe.Revoked,
				repeat(probe.Accepted, MinimumPaired)...),
		},
		Fault:          deniedWindow(revoked),
		Shift:          unknownWindow(validUnderOutage),
		Shifted:        true,
		ShiftWhat:      whatShifted,
		Recovery:       healthyRecovery(),
		FaultConfirmed: true,
		Defect:         deniedCredentialRefused,
		DeliveredWhat:  "ask its authorization dependency",
		Delivered:      int64(MinimumPaired * 2),

		// The SECOND window's counter, and leaving it out is not neutral: a
		// declared delivery guard plus a zero count is a window the target
		// never met, which the verdict voids rather than reads. Every row
		// below is about a target that did consult its dependency.
		ShiftAsked: int64(MinimumPaired * 2),
	}
}

func TestTheTwoPhasesReadFourDifferentCallers(t *testing.T) {
	for _, row := range []struct {
		name          string
		revoked       probe.Disposition
		validUnderOut probe.Disposition
		wantDirection Direction
		wantDefect    bool
		wantReason    string
	}{
		{
			name:          "three branches, which is the correct caller",
			revoked:       probe.Rejected,
			validUnderOut: probe.Rejected,
			wantDirection: Held,
			wantDefect:    false,
			wantReason:    "acted on what the dependency SAID",
		},
		{
			name:          "honours the deny and treats silence as permission",
			revoked:       probe.Rejected,
			validUnderOut: probe.Accepted,
			wantDirection: Permitted,
			wantDefect:    true,
			wantReason:    "this target's fallback is to allow",
		},
		{
			name:          "honours silence and ignores the deny",
			revoked:       probe.Accepted,
			validUnderOut: probe.Rejected,
			wantDirection: Permitted,
			wantDefect:    true,
			wantReason:    "the collapse inverted",
		},
		{
			name:          "two branches where it needs three",
			revoked:       probe.Accepted,
			validUnderOut: probe.Accepted,
			wantDirection: Permitted,
			wantDefect:    true,
			wantReason:    "permitted access during both",
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			verdict := Judge(
				shifted(row.revoked, row.validUnderOut),
				authzPolarity,
			)

			if verdict.Direction != row.wantDirection {
				t.Fatalf(
					"direction %s, want %s (reasons: %v)",
					verdict.Direction,
					row.wantDirection,
					verdict.Reasons,
				)
			}

			if verdict.Defect != row.wantDefect {
				t.Fatalf("defect %v, want %v", verdict.Defect, row.wantDefect)
			}

			if !hasReason(verdict, row.wantReason) {
				t.Fatalf(
					"no reason mentions %q, so khaos reached the right verdict without saying which caller it saw: %v",
					row.wantReason,
					verdict.Reasons,
				)
			}

			if !strings.Contains(
				strings.Join(verdict.Reasons, " "),
				whatShifted,
			) {
				t.Fatalf(
					"the reasons never name what the second phase did: %v",
					verdict.Reasons,
				)
			}
		})
	}
}

// A refusal in the second phase is the CORRECT outcome, so it must never be
// read as a direction of its own: the valid credential is refused there by a
// caller that is behaving properly, and reading that window the way the first
// one is read would report the correct caller as having failed closed.
func TestTheSecondPhaseIsNeverReadAsADenial(t *testing.T) {
	verdict := Judge(shifted(probe.Rejected, probe.Rejected), authzPolarity)

	if verdict.Direction != Held {
		t.Fatalf(
			"a caller that refused in both phases was judged %s: the second window is a comparison, not a direction",
			verdict.Direction,
		)
	}

	if verdict.Epistemic != Passed {
		t.Fatalf("epistemic %s, want %s", verdict.Epistemic, Passed)
	}
}

// An acceptance at the START of the second window is what a decision cache
// produces: the caller was correctly serving that credential a moment earlier.
// Only the trailing run counts, or khaos would report a correct caller with a
// two-second cache as failing open.
func TestACacheLapsingIntoRefusalIsNotAFinding(t *testing.T) {
	observation := shifted(probe.Rejected, probe.Rejected)

	observation.Shift.Valid = stream(
		probe.Valid,
		probe.Accepted,
		probe.Accepted,
		probe.Rejected,
		probe.Rejected,
		probe.Rejected,
	)

	verdict := Judge(observation, authzPolarity)

	if verdict.Direction != Held {
		t.Fatalf(
			"a cache that lapsed into refusal was judged %s: the acceptances came before the last refusal, which is what a bounded cache looks like (%v)",
			verdict.Direction,
			verdict.Reasons,
		)
	}
}

// And the mirror: a refusal followed by acceptances is a cache that lapsed and
// a caller that then decided to allow anyway, which IS the finding.
func TestServingAfterTheLastRefusalIsAFinding(t *testing.T) {
	observation := shifted(probe.Rejected, probe.Rejected)

	observation.Shift.Valid = stream(
		probe.Valid,
		probe.Rejected,
		probe.Rejected,
		probe.Accepted,
		probe.Accepted,
		probe.Accepted,
	)

	verdict := Judge(observation, authzPolarity)

	if verdict.Direction != Permitted {
		t.Fatalf(
			"a caller that started serving again while the dependency could not answer was judged %s (%v)",
			verdict.Direction,
			verdict.Reasons,
		)
	}
}

func TestA503RefusalEndsTheRunOfAcceptances(t *testing.T) {
	observation := shifted(probe.Rejected, probe.Rejected)
	observation.ClosedWhen = []probe.Disposition{probe.Unavailable}

	observation.Shift.Valid = stream(
		probe.Valid,
		append(
			[]probe.Disposition{probe.Accepted},
			repeat(probe.Unavailable, MinimumPaired*2)...,
		)...,
	)

	verdict := Judge(observation, authzPolarity)

	if verdict.Direction == Permitted {
		t.Fatalf(
			"a caller that served one cached request and then refused %d with the disposition this experiment DECLARES as closed was judged PERMITTED: %v",
			MinimumPaired*2,
			verdict.Reasons,
		)
	}

	if hasReason(verdict, "this target's fallback is to allow") {
		t.Fatalf(
			"khaos told an operator their fail-closed caller allows by default: %v",
			verdict.Reasons,
		)
	}

	// And the mirror, on the FIRST window's revoked stream: the same hardcoded
	// Rejected made every cached acceptance count when the target then 503'd.
	window := shifted(probe.Rejected, probe.Rejected)
	window.ClosedWhen = []probe.Disposition{probe.Unavailable}
	window.Fault.Revoked = stream(
		probe.Revoked,
		append(
			[]probe.Disposition{probe.Accepted},
			repeat(probe.Unavailable, MinimumPaired*2)...,
		)...,
	)

	if revokedHonoured(window) != 0 {
		t.Fatalf(
			"a bounded cache that lapsed into 503s counted %d unexplained acceptances; a correct bounded cache explains all of them",
			revokedHonoured(window),
		)
	}
}

// A target that DIED under the fault is not a target that failed closed, and
// the two were one disposition. This experiment declares a 503 as its refusal,
// so a crashed target was reported `deviated / DENIED` with "the valid
// credential stopped being accepted" -- when it stopped ANSWERING, and this
// fault takes nothing away from the target that could explain a crash.
func TestACrashedTargetIsNotReadAsFailingClosed(t *testing.T) {
	observation := shifted(probe.Rejected, probe.Rejected)
	observation.ClosedWhen = []probe.Disposition{probe.Unavailable}

	// Every probe dies on the connection, in both streams, which is what
	// `unanswered` reads across.
	observation.Fault = probe.Window{
		Valid: stream(
			probe.Valid,
			repeat(probe.Unreachable, MinimumPaired*2)...),
		Invalid: stream(
			probe.Invalid,
			repeat(probe.Unreachable, MinimumPaired*2)...),
		Revoked: stream(
			probe.Revoked,
			repeat(probe.Unreachable, MinimumPaired*2)...),
	}

	verdict := Judge(observation, authzPolarity)

	if verdict.Direction != Crashed {
		t.Fatalf(
			"a target that answered nothing at all was judged %s: %v",
			verdict.Direction,
			verdict.Reasons,
		)
	}

	// And the contrast, on the same declared set: a target ANSWERING 503 has
	// refused, and that still has to read as this control failing closed.
	answering := shifted(probe.Rejected, probe.Rejected)
	answering.ClosedWhen = []probe.Disposition{probe.Unavailable}
	answering.Fault = probe.Window{
		Valid: stream(
			probe.Valid,
			repeat(probe.Unavailable, MinimumPaired*2)...),
		Invalid: stream(
			probe.Invalid,
			repeat(probe.Rejected, MinimumPaired*2)...),
		Revoked: stream(
			probe.Revoked,
			repeat(probe.Unavailable, MinimumPaired*2)...),
	}

	if direction := Judge(
		answering,
		authzPolarity,
	).Direction; direction != Denied {
		t.Fatalf(
			"a target answering 503 to everything was judged %s, want %s: it answered, and this control declares that its refusal",
			direction,
			Denied,
		)
	}
}

// The exposure figure has to describe the SAME set as the count beside it. The
// count is the trailing run; a first-to-last span over the whole window
// includes the period the target spent refusing, and quoting the two in one
// sentence states an exposure khaos did not measure.
func TestTheExposureSpanDescribesTheRunItCounts(t *testing.T) {
	observation := shifted(probe.Rejected, probe.Rejected)

	observation.Shift.Valid = stream(
		probe.Valid,
		probe.Accepted,
		probe.Accepted,
		probe.Rejected,
		probe.Rejected,
		probe.Accepted,
		probe.Accepted,
	)

	// stream() spaces its outcomes one second apart, so the whole window spans
	// 5s and the trailing run of two acceptances spans 1s.
	if span := observation.Shift.Valid.AcceptedSpanSinceLastRefusal(
		probe.Rejected,
	); span != time.Second {
		t.Fatalf(
			"the trailing run spans %s, want 1s: a first-to-last span over this window is 5s, 4s of which the target was refusing",
			span,
		)
	}

	if !hasReason(
		Judge(observation, authzPolarity),
		"1s is a lower bound on the exposure",
	) {
		t.Fatalf(
			"the reason quotes a span that is not the run it counted: %v",
			Judge(observation, authzPolarity).Reasons,
		)
	}
}

// Window one aborts the run when the target never met the fault. Window two had
// no such guard, so a target that answered the whole second window from a
// cached allow -- without asking its dependency once -- was reported as a
// conclusive defect for serving "requests whose authorization it could not have
// checked". It checked nothing, because it asked nothing.
func TestASecondWindowTheTargetNeverMetIsNotAFinding(t *testing.T) {
	observation := shifted(probe.Rejected, probe.Accepted)
	observation.DeliveredWhat = "ask its authorization dependency"
	observation.ShiftAsked = 0

	verdict := Judge(observation, authzPolarity)

	if verdict.Direction == Permitted {
		t.Fatalf(
			"a second window the target never met was reported as a bypass: %v",
			verdict.Reasons,
		)
	}

	if !hasReason(verdict, "did not observe the target meeting it") {
		t.Fatalf(
			"khaos did not say the second window never reached the target: %v",
			verdict.Reasons,
		)
	}

	// With the counter moving, the same window IS the finding.
	delivered := shifted(probe.Rejected, probe.Accepted)
	delivered.DeliveredWhat = "ask its authorization dependency"
	delivered.ShiftAsked = int64(MinimumPaired)

	if Judge(delivered, authzPolarity).Direction != Permitted {
		t.Fatal(
			"with the dependency actually consulted, serving the valid credential while it could not answer is the finding and must still be reported",
		)
	}
}

// A stream that was only ever redirected or throttled decided nothing, and
// every four-cell sentence reads an absence of acceptances as an observed
// refusal. baselineUnmet already guards redirect-as-refusal; the fault
// window's revoked stream needed the same.
func TestAnUndecidedFirstWindowIsNotReadAsARefusal(t *testing.T) {
	observation := shifted(probe.Rejected, probe.Rejected)
	observation.Fault.Revoked = stream(
		probe.Revoked,
		repeat(probe.Redirected, MinimumPaired)...,
	)

	verdict := Judge(observation, authzPolarity)

	if hasReason(verdict, "That is the third branch") {
		t.Fatalf(
			"a stream that only ever redirected was credited with refusing the denied credential: %v",
			verdict.Reasons,
		)
	}

	if !hasReason(verdict, "no decision to compare") {
		t.Fatalf(
			"the undecided first window was not reported: %v",
			verdict.Reasons,
		)
	}
}

// Each phase is guarded by whether it was MEASURABLE. The absence of an
// acceptance is only evidence of a refusal when the target answered at all, and
// a caller that fell over in the second phase must not read as one that
// correctly stopped serving.
func TestAnUnmeasurablePhaseIsSaidRatherThanRead(t *testing.T) {
	silent := shifted(probe.Rejected, probe.Rejected)
	silent.Shift.Valid = stream(
		probe.Valid,
		repeat(probe.ProbeFailed, MinimumPaired)...)

	if !hasReason(
		Judge(silent, authzPolarity),
		"cannot tell a target that correctly stopped serving from one that fell over",
	) {
		t.Fatalf(
			"a second phase the target never answered was read as a correct refusal: %v",
			Judge(silent, authzPolarity).Reasons,
		)
	}

	unanswered := shifted(probe.Rejected, probe.Rejected)
	unanswered.Fault.Revoked = stream(
		probe.Revoked,
		repeat(probe.ProbeFailed, MinimumPaired)...)

	if !hasReason(
		Judge(unanswered, authzPolarity),
		"produced no answer at all during the first window",
	) {
		t.Fatalf(
			"the two phases were compared with nothing measured in the first: %v",
			Judge(unanswered, authzPolarity).Reasons,
		)
	}
}

// A failed shift leaves khaos with one window where it needs two. The first
// one's finding stands on its own, and the missing comparison is stated rather
// than passed over in silence.
func TestAFailedShiftIsStatedAndNotFatal(t *testing.T) {
	observation := shifted(probe.Rejected, probe.Rejected)
	observation.Shifted = false
	observation.Shift = probe.Window{}
	observation.ShiftFailed = true

	verdict := Judge(observation, authzPolarity)

	if verdict.Direction != Held {
		t.Fatalf(
			"a failed second phase changed the first phase's verdict to %s",
			verdict.Direction,
		)
	}

	if !hasReason(verdict, "could not establish the second phase") {
		t.Fatalf("the missing comparison was not reported: %v", verdict.Reasons)
	}
}

// An experiment with no second phase must read exactly as it did before the
// mechanism existed, or every other family's verdicts move.
func TestAnExperimentWithoutASecondPhaseSaysNothingAboutOne(t *testing.T) {
	observation := Observation{
		Baseline:       healthyBaseline(),
		Fault:          deniedWindow(probe.Rejected),
		Recovery:       healthyRecovery(),
		FaultConfirmed: true,
	}

	for _, reason := range Judge(observation, authPolarity).Reasons {
		if strings.Contains(reason, "second phase") ||
			strings.Contains(reason, "dependency SAID") {
			t.Fatalf(
				"an experiment with no second phase was told about one: %q",
				reason,
			)
		}
	}
}

// The retry storm, which is a REASON rather than a direction: no credential got
// through, and what it tells an operator is that their caller will hammer a
// dependency with a key it has already been told is dead.
func TestTheRetryStormIsCountedAgainstTheRequests(t *testing.T) {
	quiet := shifted(probe.Rejected, probe.Rejected)
	quiet.Refusals = int64(MinimumPaired)

	if hasReason(
		Judge(quiet, authzPolarity),
		"asked again about a credential",
	) {
		t.Fatalf(
			"a caller that asked exactly once per request was reported as retrying: %v",
			Judge(quiet, authzPolarity).Reasons,
		)
	}

	storm := shifted(probe.Rejected, probe.Rejected)
	storm.Refusals = int64(MinimumPaired * 3)

	if !hasReason(
		Judge(storm, authzPolarity),
		"asked again about a credential",
	) {
		t.Fatalf(
			"three refusals per request was not reported as a retry: %v",
			Judge(storm, authzPolarity).Reasons,
		)
	}
}

// The census. A tier whose whole value is the comparison between two windows
// must not ship an experiment that measures one of them: the first window's
// finding is real on its own, so the omission would be invisible in every
// verdict. And a second phase khaos cannot NAME produces evidence an operator
// cannot act on, in both the plan line and the reason text.
func TestEveryAuthorizationExperimentMeasuresBothWindows(t *testing.T) {
	covered := 0

	for _, definition := range Catalog() {
		if !inject.NeedsAuthz(definition.FaultKind) {
			continue
		}

		t.Run(definition.Name, func(t *testing.T) {
			covered++

			spec, err := Build(
				definition.Name,
				fill(definition.Params),
				fastTiming,
			)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			if spec.Shift == nil {
				t.Fatal(
					"this experiment arms a definitive deny and never makes the dependency unable to answer, so it measures one branch of the caller and claims to measure the discriminator",
				)
			}

			if spec.ShiftDetail == "" {
				t.Fatal(
					"the second phase has no plan line, so a run shows an operator a stage with no reason for it",
				)
			}

			if spec.ShiftWhat == "" {
				t.Fatal(
					"the second phase is unnamed, so every reason quoting it reads as a placeholder",
				)
			}

			if spec.Refusals == nil {
				t.Fatal(
					"this experiment has no refusal counter, so repeated attempts with a refused credential cannot be measured",
				)
			}

			if spec.Consulted == nil {
				t.Fatal(
					"this experiment has no consultation counter, so a target that never asks its authorization dependency reads as one that survived the fault",
				)
			}
		})
	}

	if covered == 0 {
		t.Fatal(
			"no catalogued experiment needs the authorization dependency, so this census cannot fail for the right reason",
		)
	}
}

// phasedProbe answers differently in all THREE phases, which is what a shift
// test needs and what the two-phase scripted probe cannot express.
type phasedProbe struct {
	credential probe.Credential
	before     probe.Disposition
	during     probe.Disposition
	after      probe.Disposition
	faulted    *bool
	shifted    *bool
}

func (p phasedProbe) Name() string                 { return "phased" }
func (p phasedProbe) Describe() string             { return "a phased probe" }
func (p phasedProbe) Credential() probe.Credential { return p.credential }

func (p phasedProbe) Run(context.Context) probe.Outcome {
	disposition := p.before

	switch {
	case *p.shifted:
		disposition = p.after
	case *p.faulted:
		disposition = p.during
	}

	return probe.Outcome{
		At:          time.Now().UTC(),
		Credential:  p.credential,
		Disposition: disposition,
	}
}

// The verdict tests above hand-build their observations, which proves nothing
// about the code that FEEDS them: a control on a pure function says nothing
// about its caller. This is the other end -- the engine really arming the
// second phase, really sampling a second window, and really recording it where
// the verdict reads it.
func TestTheEngineMeasuresASecondWindowAfterTheShift(t *testing.T) {
	faulted := false
	wasShifted := false
	asked := int64(0)

	injector := &scriptedInjector{faulted: &faulted}
	engine := Engine{Injector: injector}

	var stages []Stage
	engine.Report = func(e Event) { stages = append(stages, e.Stage) }

	run := spec(
		phasedProbe{
			credential: probe.Valid,
			before:     probe.Accepted,
			during:     probe.Accepted,
			after:      probe.Rejected,
			faulted:    &faulted,
			shifted:    &wasShifted,
		},
		phasedProbe{
			credential: probe.Invalid,
			before:     probe.Rejected,
			during:     probe.Rejected,
			after:      probe.Rejected,
			faulted:    &faulted,
			shifted:    &wasShifted,
		},
	)

	run.Probes.Revoked = phasedProbe{
		credential: probe.Revoked,
		before:     probe.Accepted,
		during:     probe.Rejected,
		after:      probe.Rejected,
		faulted:    &faulted,
		shifted:    &wasShifted,
	}

	run.Consulted = func() (int64, error) {
		asked++
		return asked, nil
	}
	run.ConsultedWhat = "khaos's authorization dependency"
	run.ShiftWhat = whatShifted
	run.ShiftDetail = "making the dependency unable to answer"
	run.Shift = func(context.Context) error {
		wasShifted = true
		return nil
	}

	result, err := engine.Run(context.Background(), run)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if !slicesContains(stages, StageShift) {
		t.Fatalf("the engine never reported a shift stage: %v", stages)
	}

	if !result.Observation.Shifted {
		t.Fatal("the engine armed the second phase and did not record it")
	}

	if result.Observation.Shift.Valid.Len() == 0 {
		t.Fatal(
			"the engine recorded no second window, so every comparison the verdict makes would read a zero-valued one",
		)
	}

	if result.Observation.Fault.Valid.Count(probe.Accepted) == 0 {
		t.Fatal(
			"the first window recorded no acceptance of the valid credential",
		)
	}

	if result.Observation.Shift.Valid.Count(probe.Rejected) == 0 {
		t.Fatalf(
			"the second window recorded no refusal, so the two windows are the same measurement: %v",
			result.Observation.Shift.Valid.Distribution(),
		)
	}

	if result.Observation.ShiftWhat != whatShifted {
		t.Fatalf(
			"the observation does not name the second phase: %q",
			result.Observation.ShiftWhat,
		)
	}

	if result.Observation.ShiftAsked <= 0 {
		t.Fatal(
			"the dependency counter was not read across the second window, so a target that stopped asking would read as one that kept asking",
		)
	}

	if result.Verdict.Direction != Held {
		t.Fatalf(
			"a caller that refused in both phases was judged %s: %v",
			result.Verdict.Direction,
			result.Verdict.Reasons,
		)
	}
}

// A failed shift must not take the first window's finding with it, and must not
// skip the rollback.
func TestAFailedShiftStillRevertsAndStillConcludes(t *testing.T) {
	faulted := false
	wasShifted := false

	injector := &scriptedInjector{faulted: &faulted}
	engine := Engine{Injector: injector}

	run := spec(
		phasedProbe{
			credential: probe.Valid,
			before:     probe.Accepted,
			during:     probe.Accepted,
			after:      probe.Accepted,
			faulted:    &faulted,
			shifted:    &wasShifted,
		},
		phasedProbe{
			credential: probe.Invalid,
			before:     probe.Rejected,
			during:     probe.Rejected,
			after:      probe.Rejected,
			faulted:    &faulted,
			shifted:    &wasShifted,
		},
	)

	run.Shift = func(context.Context) error {
		return errors.New("the dependency would not answer 503")
	}

	result, err := engine.Run(context.Background(), run)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if !result.Observation.ShiftFailed {
		t.Fatal("a failed shift was not recorded")
	}

	if result.Observation.Shifted {
		t.Fatal(
			"a failed shift recorded a second window, so the verdict would compare against one that was never measured",
		)
	}

	if injector.reverts != 1 {
		t.Fatalf(
			"reverts=%d after a failed shift, want 1: the fault is still applied",
			injector.reverts,
		)
	}

	if result.Verdict.Direction != Held {
		t.Fatalf("direction %s, want %s", result.Verdict.Direction, Held)
	}
}

func slicesContains(stages []Stage, want Stage) bool {
	for _, stage := range stages {
		if stage == want {
			return true
		}
	}

	return false
}

func hasReason(verdict Verdict, want string) bool {
	for _, reason := range verdict.Reasons {
		if strings.Contains(reason, want) {
			return true
		}
	}

	return false
}
