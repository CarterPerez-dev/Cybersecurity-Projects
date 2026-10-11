// ©AngelaMos | 2026
// verdict.go

package experiment

import (
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

type Epistemic string

const (
	Passed         Epistemic = "passed"
	Deviated       Epistemic = "deviated"
	BaselineNotMet Epistemic = "baseline-not-met"
	ProbeError     Epistemic = "probe-error"
	Aborted        Epistemic = "aborted"
	Interrupted    Epistemic = "interrupted"
	Errored        Epistemic = "error"
)

type Direction string

const (
	Held         Direction = "HELD"
	Denied       Direction = "DENIED"
	Permitted    Direction = "PERMITTED"
	Crashed      Direction = "CRASHED"
	Undetermined Direction = "UNDETERMINED"
)

// Cause is a THIRD axis, and it is deliberately not a value on the directional
// one. Direction answers which way the target broke; cause answers why it is
// still broken, and the two are orthogonal. `PERMITTED` has two causes that look
// identical from outside under steady traffic and need completely different
// fixes, so collapsing them into the direction would lose the distinction khaos
// exists to draw here.
type Cause string

const (
	// Undiagnosed is the honest default. Nothing ran that could tell the causes
	// apart, so khaos says so rather than guessing one.
	Undiagnosed Cause = "UNDIAGNOSED"

	// TTLExtension is the decision cache being re-armed on every failed check.
	// Research 07 section 3.3 pins it to one line inside an error branch:
	// `cache.Set(tok, stale, ttl)`. The TTL stops bounding staleness and starts
	// bounding IDLENESS, so a cached allow becomes permanent exactly when the
	// authority that could revoke it is unreachable. It survives any amount of
	// steady traffic and dies the moment traffic pauses.
	TTLExtension Cause = "TTL-EXTENSION"

	// LapsedOnPause is enforcement returning after the pause, with khaos unable
	// to say WHY. It is the honest middle between the two diagnoses.
	//
	// TTL-EXTENSION claims the cache was being re-armed by traffic. That only
	// follows if steady traffic kept the credential alive for at least as long
	// as the pause then killed it: otherwise an ordinary fixed expiry explains
	// the same observation, and khaos would prescribe removing a cache write
	// that does not exist.
	LapsedOnPause Cause = "LAPSED-ON-PAUSE"

	// StalePastPause is a cached state the traffic pause did not let lapse.
	//
	// It is NOT called NO-EXPIRY, and the rename is a correctness fix rather than
	// a wording preference. Research 07's open question 5 is explicit: khaos
	// cannot tell a cache with no expiry from one whose lifetime simply exceeds
	// the experiment, "not without running longer than the TTL", and the
	// experiment "should report an observed lower bound on the stale window and
	// label it as a bound, never as 'caches forever'".
	//
	// The old label asserted the unbounded claim in two words while the reason
	// beside it hedged, so a five-minute JWKS cache — the default in most
	// libraries, and bounded, and defensible — was reported as having no expiry
	// at all on the strength of a sixteen-second observation.
	StalePastPause Cause = "STALE-PAST-PAUSE"
)

// Recovery is what khaos saw after it reverted the fault. It is three-valued
// because "not observed" and "observed healthy" are different facts, and
// collapsing them let an empty recovery window read as a clean comeback.
type Recovery string

const (
	// Recovered is a healthy run of consecutive pairs after the revert.
	Recovered Recovery = "recovered"

	// Degraded is measured and NOT healthy: the target did not come back.
	Degraded Recovery = "degraded"

	// Unobserved is no usable evidence either way. It is not a pass.
	Unobserved Recovery = "unobserved"
)

type Warning string

const (
	WarningRollbackFailed     Warning = "rollback-failed"
	WarningThinEvidence       Warning = "thin-evidence"
	WarningPartialOutage      Warning = "partial-outage"
	WarningRecoveryUnobserved Warning = "recovery-unobserved"
)

const (
	// A single accepted credential that the target had already rejected is
	// PROOF of a bypass, so PERMITTED needs n=1. The absence of one is not
	// proof of its absence, so HELD needs a sample-size argument. The
	// asymmetry is deliberate.
	MinimumToProveOpen   = 1
	MinimumToClaimClosed = 30
	MinimumPaired        = 5
	RecoveryRunLength    = 2
	crashFraction        = 0.5
)

const (
	reasonThinBaseline       = "the baseline collected %d paired samples, fewer than the %d khaos needs to describe a steady state"
	reasonThinForged         = "the fault window produced %d usable decisions on the credential this experiment is actually about, fewer than the %d khaos needs; the target was never successfully shown the thing under test, so its not refusing one proves nothing"
	reasonThinFault          = "the fault window collected %d paired samples, fewer than the %d khaos needs to conclude anything from an absence of findings"
	reasonNoEnforcement      = "the invalid credential was never rejected during the baseline, so the target was not enforcing anything before the fault and nothing can be concluded from it failing to enforce during one"
	reasonRedirects          = "the invalid credential was answered with a redirect %d time(s) during the baseline and never with a refusal; point --url at an endpoint that answers with a status rather than a login redirect"
	reasonNoService          = "the valid credential was never accepted during the baseline, so the target was not serving before the fault"
	reasonNoServiceMinted    = "the target never accepted a credential from khaos's own identity provider during the baseline. It may not resolve keys from the issuer khaos is serving; and if it caches its key set, a PREVIOUS khaos run's keys may still be cached, because khaos mints a fresh key set every run. Restart the target or shorten its key cache lifetime"
	reasonPermitted          = "a credential the target had already rejected was accepted %d time(s) during the fault"
	reasonDenied             = "the valid credential stopped being accepted %d time(s) during the fault"
	reasonCrashed            = "the target stopped answering %d of %d probes during the fault"
	reasonHeld               = "the valid credential kept being accepted and the invalid one kept being rejected"
	reasonWeakHeld           = "no bypass was observed, but %d paired samples cannot rule one out; %d would"
	reasonNotRecovered       = "the target did not return to its steady state after the fault was reverted"
	reasonRecoveryUnobserved = "khaos collected no usable recovery evidence, so it cannot say whether the target came back; this is not the same as it having come back"
	reasonPartialOutage      = "the target was unreachable for %d of %d probes during the fault, so the measurement is mixed"
	reasonDefect             = "this experiment declares %s to be the defect for this control"
	reasonNotDefect          = "this experiment declares %s to be acceptable for this control, so the deviation is recorded without calling it a defect"
	reasonInterrupted        = "the run was interrupted before it finished, so nothing it measured is conclusive"
	reasonRollback           = "the fault could not be fully reverted, so the target may still be degraded"
	reasonFaultUnconfirmed   = "khaos could not confirm the fault actually took effect, so nothing measured during the run can be attributed to it"
	reasonNothingToRevoke    = "the credential this experiment intends to revoke was never accepted during the baseline, so the target was not honouring it and revoking it takes nothing away"
	reasonActFailed          = "khaos could not make its change at the authority, so the credential it went on to measure was never revoked and every acceptance of it was correct"
	reasonRevokedHonoured    = "a credential khaos invalidated at the authority, by %s, was still accepted %d time(s)"
	reasonForgedAccepted     = "a credential khaos minted with %s was accepted %d time(s)"
	reasonProviderNotTrusted = "the target never accepted a correct credential from khaos's own identity provider during the baseline, so it was not trusting that provider before the fault and its refusal of a forged one during it means nothing; check that the target resolves keys from the issuer khaos is serving"
	reasonForgedNotChecked   = "the target never refused the defective credential during the baseline, so it was not checking the property this experiment is about to break and nothing can be concluded from it accepting one during the fault"
	reasonTTLExtension       = "the credential survived %s of STEADY traffic and then stopped being accepted after a %s pause, and no fixed lifetime behaves that way: every failed check was re-arming whatever the target had cached, a decision or a key set, so the lifetime was bounding IDLENESS rather than staleness. The fix is to stop writing to the cache in the error branch"
	reasonLapsedOnPause      = "the credential stopped being accepted after the %s pause, but the steady-traffic window before it was only %s, so an ordinary fixed expiry between those two durations produces this exact result and khaos will not call it re-arming. Re-run with --fault-for at least %s to separate them"
	reasonStalePastPause     = "the credential was still accepted after traffic was paused for %s, so whatever the target cached did not lapse across that pause. khaos cannot tell a cache with no expiry from one whose lifetime simply exceeds %s, and it will not claim the first from an observation that only establishes the second; raise --idle-for to raise the bound"
	reasonNeverConsulted     = "the target never used %s during the baseline, so the fault this experiment applies there is one it cannot experience; a target that validates credentials locally never calls it, and khaos would otherwise report a clean survival of a fault that never reached it"
	reasonNoResumedEvidence  = "the resumed window produced %d usable samples in %s and never a refusal, so khaos saw nothing that could tell a cache being re-armed from one that outlasts the pause"
	reasonStaleWindow        = "the credential khaos invalidated was accepted over a span of at least %s, which is the lower bound on the exposure and not a measurement of the cache lifetime"
)

type Verdict struct {
	Epistemic  Epistemic `json:"epistemic"`
	Recovery   Recovery  `json:"recovery"`
	Direction  Direction `json:"direction"`
	Cause      Cause     `json:"cause"`
	Conclusive bool      `json:"conclusive"`
	Defect     bool      `json:"defect"`
	Warnings   []Warning `json:"warnings,omitempty"`
	Reasons    []string  `json:"reasons"`
}

type Observation struct {
	Baseline       probe.Window `json:"baseline"`
	Fault          probe.Window `json:"fault"`
	Recovery       probe.Window `json:"recovery"`
	FaultConfirmed bool         `json:"fault_confirmed"`
	ConfirmMethod  string       `json:"fault_confirm_method,omitempty"`
	RollbackFailed bool         `json:"rollback_failed"`
	Interrupted    bool         `json:"interrupted"`

	// Resumed is the window measured AFTER traffic has been paused for IdleFor,
	// with the fault still applied. It is the idleness discriminator: the two
	// causes of a permitted credential are indistinguishable under steady traffic
	// and separate completely across a pause.
	Resumed probe.Window  `json:"resumed"`
	IdleFor time.Duration `json:"idle_for,omitempty"`

	// FaultFor is how long steady traffic ran before the pause. It is what makes
	// the TTL-extension diagnosis falsifiable rather than asserted.
	FaultFor time.Duration `json:"fault_for,omitempty"`

	// Acted records that khaos made its mid-run change at the authority. A run
	// whose action failed measured a credential nobody revoked, so the finding it
	// exists to produce is unreachable and the run is void rather than clean.
	Acted     bool `json:"acted,omitempty"`
	ActFailed bool `json:"act_failed,omitempty"`

	// ForgedBaseline is what the forged stream was DECLARED to do before the
	// fault, carried into the record so a reader can audit the guard that was
	// applied rather than having to know which experiment produced the run.
	ForgedBaseline probe.Expectation `json:"forged_baseline,omitempty"`

	// Consulted is how many times the target reached the faulted endpoint during
	// the baseline, and ConsultedWhat names it. Zero means the fault khaos is
	// about to apply is one the target cannot experience.
	Consulted     int64  `json:"consulted,omitempty"`
	ConsultedWhat string `json:"consulted_what,omitempty"`

	// MintedByKhaos records that the valid credential came from khaos's own
	// identity provider rather than from the operator. It changes only the
	// wording of one refusal, and that wording is the difference between telling
	// an operator their target is down and telling them what to check.
	MintedByKhaos bool `json:"minted_by_khaos,omitempty"`

	// HeldCaveat qualifies a HELD verdict for the experiments whose absence of a
	// finding covers less than it appears to. An unqualified "no bypass was
	// observed" from a probe that tried one of four key serializations, or a
	// hold the target's timeout may simply have absorbed, is khaos claiming more
	// than it measured.
	HeldCaveat string `json:"held_caveat,omitempty"`

	// Defect names what khaos DID to the credential the finding is about, in
	// words, so the verdict can state the actual observation.
	//
	// It is per experiment rather than a constant because the three experiments
	// with a revoked stream invalidate their credential in three different ways,
	// and one constant said all of them happened "while that authority was
	// unreachable". That is true only of the outage experiment: a key rollover
	// and a plain revocation both leave the provider fully reachable and
	// answering, so the constant had khaos asserting something false about its
	// own run on two of the three.
	Defect string `json:"defect,omitempty"`
}

// Judge resolves two independent axes. The epistemic one answers whether the
// run can be believed; the directional one answers which way the target broke.
// A single-axis verdict cannot tell a target that failed closed from one that
// was never enforcing to begin with.
func Judge(observation Observation, polarity Polarity) Verdict {
	// Every verdict carries an explicit cause. An empty one would read as a field
	// khaos forgot rather than a diagnosis it never attempted.
	verdict := Verdict{Direction: Undetermined, Cause: Undiagnosed}

	if observation.RollbackFailed {
		verdict.Warnings = append(verdict.Warnings, WarningRollbackFailed)
		verdict.Reasons = append(verdict.Reasons, reasonRollback)
	}

	if observation.Interrupted {
		verdict.Epistemic = Interrupted
		verdict.Reasons = append(verdict.Reasons, reasonInterrupted)
		return verdict
	}

	// A baseline that was never a steady state is the more fundamental finding
	// and is knowable whether or not the fault went on to land.
	if reason, unmet := baselineUnmet(observation.Baseline, observation.ForgedBaseline, observation.MintedByKhaos); unmet {
		verdict.Epistemic = BaselineNotMet
		verdict.Reasons = append(verdict.Reasons, reason)
		return verdict
	}

	if reason, never := endpointNeverConsulted(observation); never {
		verdict.Epistemic = BaselineNotMet
		verdict.Reasons = append(verdict.Reasons, reason)
		return verdict
	}

	if !observation.FaultConfirmed {
		verdict.Epistemic = Aborted
		verdict.Reasons = append(verdict.Reasons, reasonFaultUnconfirmed)
		return verdict
	}

	// A failed mid-run action is NOT a clean run. The credential khaos measured
	// was never revoked, so every acceptance of it is correct behaviour and the
	// finding this experiment exists to produce was unreachable.
	if observation.ActFailed {
		verdict.Epistemic = Aborted
		verdict.Reasons = append(verdict.Reasons, reasonActFailed)
		return verdict
	}

	// A proven bypass is reported even on thin evidence, because one leaked
	// request is a proof. Everything else waits for the sample floor.
	//
	// The three streams make three DIFFERENT claims and every one that fired is
	// stated. "A credential khaos revoked at the authority was still accepted"
	// is not "a credential the target had already rejected was accepted", and
	// neither is "a credential khaos minted with a deliberate defect was
	// accepted". Reporting one claim when a different stream carried the finding
	// would be khaos describing an observation it never made, and returning on
	// the first one would drop the others from a run where several are true.
	if leaks := leaked(observation); len(leaks) > 0 {
		verdict.Epistemic = Deviated
		verdict.Direction = Permitted
		verdict.Conclusive = true
		verdict.Reasons = append(verdict.Reasons, leaks...)
		verdict.Cause, verdict.Reasons = diagnose(observation, verdict.Reasons)
		return finish(verdict, observation, polarity)
	}

	if paired := observation.Fault.Paired(); paired < MinimumPaired {
		verdict.Epistemic = ProbeError
		verdict.Warnings = append(verdict.Warnings, WarningThinEvidence)
		verdict.Reasons = append(verdict.Reasons, sprintf(reasonThinFault, paired, MinimumPaired))
		return verdict
	}

	// The stream that carries THIS experiment's hypothesis has to have produced
	// usable decisions too. Paired() counts only the valid and invalid streams,
	// so a run where every forged probe failed or timed out still cleared the
	// floor above and fell through to HELD — reporting that the target refused a
	// credential it was never successfully shown.
	//
	// This sits AFTER the leak checks on purpose: one observed acceptance of a
	// credential khaos proved defective is a finding on its own, and must not be
	// discarded for thin evidence.
	if reason, thin := requiredStreamThin(observation); thin {
		verdict.Epistemic = ProbeError
		verdict.Warnings = append(verdict.Warnings, WarningThinEvidence)
		verdict.Reasons = append(verdict.Reasons, reason)
		return verdict
	}

	dir, reasons := direction(observation)
	verdict.Direction = dir
	verdict.Reasons = append(verdict.Reasons, reasons...)
	verdict.Conclusive = true

	if verdict.Direction == Held {
		verdict.Epistemic = Passed
		if paired := observation.Fault.Paired(); paired < MinimumToClaimClosed {
			verdict.Conclusive = false
			verdict.Warnings = append(verdict.Warnings, WarningThinEvidence)
			verdict.Reasons = append(verdict.Reasons, sprintf(reasonWeakHeld, paired, MinimumToClaimClosed))
		}
	} else {
		verdict.Epistemic = Deviated
	}

	return finish(verdict, observation, polarity)
}

func finish(verdict Verdict, observation Observation, polarity Polarity) Verdict {
	if partial, total := unanswered(observation.Fault); partial > 0 && partial < total {
		verdict.Warnings = append(verdict.Warnings, WarningPartialOutage)
		verdict.Reasons = append(verdict.Reasons, sprintf(reasonPartialOutage, partial, total))
	}

	verdict.Recovery = recoveryOf(observation.Recovery)

	switch verdict.Recovery {
	case Degraded:
		verdict.Epistemic = Deviated
		verdict.Reasons = append(verdict.Reasons, reasonNotRecovered)
	case Unobserved:
		verdict.Warnings = append(verdict.Warnings, WarningRecoveryUnobserved)
		verdict.Reasons = append(verdict.Reasons, reasonRecoveryUnobserved)
	}

	if verdict.Direction == Held && observation.HeldCaveat != "" {
		verdict.Reasons = append(verdict.Reasons, observation.HeldCaveat)
	}

	if verdict.Direction != Held {
		verdict.Defect = polarity.IsDefect(verdict.Direction)
		verdict.Reasons = append(verdict.Reasons, polarity.Explain(verdict.Direction))
	}

	return verdict
}

// leaked returns one reason per stream that proved a bypass, in order of how
// specific the claim is. An empty result means nothing leaked.
func leaked(observation Observation) []string {
	reasons := []string{}

	if honoured := revokedHonoured(observation); honoured >= MinimumToProveOpen {
		reasons = append(reasons, sprintf(reasonRevokedHonoured, orUnnamed(observation.Defect), honoured))

		// The exposure as a NUMBER, so the finding is checkable rather than a
		// count whose duration the reader has to infer from the timing flags.
		// Research 07 section 2.2 calls this `stale_accept_window`, "the real
		// exposure window of a leaked key", and it is explicitly a lower bound:
		// khaos stopped looking when the run ended.
		if span := staleWindow(observation); span > 0 {
			reasons = append(reasons, sprintf(reasonStaleWindow, span.Round(time.Second)))
		}
	}

	if accepted := forgedAccepted(observation); accepted >= MinimumToProveOpen {
		reasons = append(reasons, sprintf(reasonForgedAccepted, orUnnamed(observation.Defect), accepted))
	}

	if monotonic := leakedMonotonic(observation); monotonic >= MinimumToProveOpen {
		reasons = append(reasons, sprintf(reasonPermitted, monotonic))
	}

	return reasons
}

// Leaking reports whether ANY mechanism found a bypass. It is exported because
// the ENGINE needs the answer mid-run: the idleness discriminator costs a traffic
// pause and a second measurement window, and there is nothing to diagnose on a
// target that never leaked.
//
// It has to cover every stream. Keyed on the monotonicity count alone, a
// revocation experiment's finding sat entirely in the revoked stream and the
// discriminator never ran, so the cause came back UNDIAGNOSED on a run that had
// just proved a bypass.
func Leaking(observation Observation) bool {
	return len(leaked(observation)) > 0
}

// forgedAccepted counts acceptances of a credential khaos minted with one
// deliberate defect.
//
// There is no monotonicity test here and that is deliberate, but the reason it
// is sound differs by experiment and the shared sentence used to overstate it.
// For the ten forgery traps the oracle reads the minted token back and inspects
// the wrongness, so the credential is PROVED malformed before it is presented.
// For `identity.jwks_unreachable` the confirmed observable is the key set
// answering non-200 and nothing inspects the credential at all; its
// defectiveness comes from CorruptSignature plus the ExpectRejected baseline
// guard, which is adequate evidence but not the evidence the sentence named.
// The reason now states only what is true of both, and the per-trap confirm line
// carries the specific evidence.
// staleWindow is the span from the first acceptance of the invalidated
// credential to the last, across the fault window and the resumed one.
func staleWindow(observation Observation) time.Duration {
	fault := observation.Fault.Revoked.AcceptedSpan()
	resumed := observation.Resumed.Revoked.AcceptedSpan()

	// The idle pause sits between the two windows, so a run that leaked on both
	// sides of it has an exposure spanning the pause as well.
	if resumed > 0 {
		return fault + observation.IdleFor + resumed
	}

	return fault
}

// requiredStreamThin reports whether a stream this experiment NEEDS could not be
// measured. A declared forged stream is required: the experiment's whole
// hypothesis is about that credential, so an absence of findings on it is only
// meaningful if the target actually decided about it.
func requiredStreamThin(observation Observation) (string, bool) {
	if observation.ForgedBaseline == "" {
		return "", false
	}

	if decided := observation.Fault.Forged.Countable(); decided < MinimumPaired {
		return sprintf(reasonThinForged, decided, MinimumPaired), true
	}

	return "", false
}

func forgedAccepted(observation Observation) int {
	return observation.Fault.Forged.Count(probe.Accepted)
}

func orUnnamed(defect string) string {
	if defect == "" {
		return "a deliberate defect"
	}
	return defect
}

// leakedMonotonic counts credentials the target had already rejected and then
// accepted during the fault.
func leakedMonotonic(observation Observation) int {
	rejectedInBaseline := observation.Baseline.Invalid.Any(probe.Rejected)
	return observation.Fault.Invalid.AcceptedAfter(rejectedInBaseline)
}

// revokedHonoured counts acceptances of a credential khaos invalidated at the
// authority that were never followed by a refusal.
//
// Order-sensitive, for the same reason the DENIED test is. A target with a
// correct BOUNDED cache serves the invalidated credential for exactly its cache
// lifetime and then refuses it forever, which is the defensible bounded-stale
// pattern research 07 section 3.3 lists as a PASS. Counting every acceptance in
// the window reported that as a bypass.
//
// The outage experiment only escaped it by accident: its proxy confirmation
// spends two seconds measuring both paths, which happens to be the range's cache
// lifetime, so the stale allow had lapsed before the window opened. The identity
// tier's confirmation is two local HTTP calls, so the same experiment shape
// would have reported a false finding against a correct target.
func revokedHonoured(observation Observation) int {
	return observation.Fault.Revoked.AcceptedDespiteLapse()
}

// diagnose separates the two causes of a permitted credential. Both look
// identical under steady traffic; they separate completely across a pause.
//
// The test is order-sensitive for the same reason the monotonicity rule is. The
// fault window already established that the target accepts a credential it had
// rejected. The only question left is whether it STILL accepts one once traffic
// has stopped for longer than any plausible cache lifetime.
func diagnose(observation Observation, reasons []string) (Cause, []string) {
	// Deliberately NOT gated on Resumed.Paired(). That counts only the valid and
	// invalid streams, so a resumed window full of decisions about the REVOKED
	// credential — the stream that actually leaked — read as no evidence at all
	// and skipped the diagnosis entirely. resolveCause below decides from the
	// stream that carried the finding, and says so when that stream is empty.

	// A forged credential getting through is not a caching bug, so there is no
	// cause to diagnose. No experiment pairs a forged stream with the idleness
	// pause today, and this guard is what stops the next one that does from
	// being diagnosed off the INVALID stream's resumed window, which is a stream
	// that never leaked.
	if forgedAccepted(observation) > 0 &&
		revokedHonoured(observation) == 0 &&
		leakedMonotonic(observation) == 0 {
		return Undiagnosed, reasons
	}

	// The resumed window is read on whichever stream carried the leak. A revoked
	// credential and a never-valid one are different streams, and diagnosing the
	// wrong one would report the pause's effect on something that never leaked.
	//
	// It is read with the same order-sensitive test the fault window uses, and
	// for the same reason. The question is whether the credential is STILL being
	// honoured once the pause has had its chance, so a window that starts
	// accepted and settles into refusal is a cache that lapsed, however long it
	// took. "Was it ever accepted after the pause" calls that one NO-EXPIRY,
	// which is the opposite diagnosis and the opposite fix.
	if revokedHonoured(observation) > 0 {
		return resolveCause(observation.Resumed.Revoked, observation.FaultFor, observation.IdleFor, reasons)
	}

	return resolveCause(observation.Resumed.Invalid, observation.FaultFor, observation.IdleFor, reasons)
}

// resolveCause reads one resumed stream and refuses to diagnose from a window
// that contains no evidence.
//
// Both halves are needed, and the second one was missing. `Resumed.Paired()`
// ignores the revoked stream entirely, and AcceptedSinceLastRefusal returns zero
// for a window that is ALL timeouts, because a timeout is neither an acceptance
// nor a refusal. So a run whose resumed probes could not reach the target at all
// fell through to TTL-EXTENSION and asserted that "pausing traffic restored
// enforcement" — of a target that had stopped answering.
//
// That is reachable: `identity.idp_outage` severs the upstream with a proxy
// hang, so a resumed probe against a wedged path times out rather than being
// refused. TTL-EXTENSION also prescribes a fix, "stop writing to the cache in
// the error branch", so the wrong diagnosis sends somebody to the wrong line.
func resolveCause(resumed probe.Stream, steady, idle time.Duration, reasons []string) (Cause, []string) {
	if resumed.AcceptedDespiteLapse() > 0 {
		return StalePastPause, append(reasons, sprintf(reasonStalePastPause, idle, idle))
	}

	// Enforcement returning has to be OBSERVED, not inferred from an absence.
	if resumed.Count(probe.Rejected) == 0 {
		return Undiagnosed, append(reasons, sprintf(reasonNoResumedEvidence,
			resumed.Countable(), idle))
	}

	// The soundness condition for the causal claim. A fixed, never-re-armed cache
	// whose lifetime sits between the fault window and the pause produces exactly
	// this observation, so without a steady-traffic window at least as long as
	// the pause khaos cannot separate re-arming from ordinary expiry.
	if steady < idle {
		return LapsedOnPause, append(reasons, sprintf(reasonLapsedOnPause, idle, steady, idle))
	}

	return TTLExtension, append(reasons, sprintf(reasonTTLExtension, steady, idle))
}

func baselineUnmet(baseline probe.Window, expect probe.Expectation, minted bool) (string, bool) {
	if paired := baseline.Paired(); paired < MinimumPaired {
		return sprintf(reasonThinBaseline, paired, MinimumPaired), true
	}

	if !baseline.Invalid.Any(probe.Rejected) {
		if redirects := baseline.Invalid.Count(probe.Redirected); redirects > 0 {
			return sprintf(reasonRedirects, redirects), true
		}
		return reasonNoEnforcement, true
	}

	if !baseline.Valid.Any(probe.Accepted) {
		// The identity tier gets its own wording, because the generic sentence is
		// misleading there in the most likely failure case. A target whose key
		// cache never expires is serving perfectly well and simply does not know
		// khaos's keys, which khaos regenerates every run: measured against the
		// range's forever-cache gateway, a second consecutive run could not
		// establish a baseline and the generic reason said the target was not
		// serving.
		if minted {
			return reasonNoServiceMinted, true
		}
		return reasonNoService, true
	}

	// An experiment that revokes a credential mid-run needs the target to have
	// been HONOURING that credential first. If it was never accepted there is
	// nothing for the revocation to take away, and every later rejection is the
	// target being correct rather than khaos finding anything.
	if baseline.Revoked.Countable() > 0 && !baseline.Revoked.Any(probe.Accepted) {
		return reasonNothingToRevoke, true
	}

	return forgedBaselineUnmet(baseline, expect)
}

// endpointNeverConsulted is the liveness guard for a fault applied to an
// endpoint rather than to a credential. Without it, three experiments report a
// clean survival of a fault the target never experienced.
func endpointNeverConsulted(observation Observation) (string, bool) {
	if observation.ConsultedWhat == "" || observation.Consulted > 0 {
		return "", false
	}

	return sprintf(reasonNeverConsulted, observation.ConsultedWhat), true
}

// forgedBaselineUnmet applies the guard the experiment DECLARED for its forged
// stream. The two expectations point in opposite directions and both are
// liveness guards rather than findings.
//
// ExpectAccepted catches the single most likely misconfiguration in the whole
// family: a target that is not pointed at khaos's identity provider at all. It
// refuses every credential khaos mints, for reasons that have nothing to do with
// any trap, and without this guard a run against it reports a clean HELD for
// every one of the forgery experiments.
//
// ExpectRejected catches the mirror: a target that was not checking the thing
// the fault is about to break, so its later acceptance proves nothing changed.
func forgedBaselineUnmet(baseline probe.Window, expect probe.Expectation) (string, bool) {
	if baseline.Forged.Countable() == 0 {
		return "", false
	}

	switch expect {
	case probe.ExpectAccepted:
		if !baseline.Forged.Any(probe.Accepted) {
			return reasonProviderNotTrusted, true
		}
	case probe.ExpectRejected:
		if !baseline.Forged.Any(probe.Rejected) {
			return reasonForgedNotChecked, true
		}
	}

	return "", false
}

func direction(observation Observation) (Direction, []string) {
	down, total := unanswered(observation.Fault)

	if total > 0 && float64(down) >= float64(total)*crashFraction {
		return Crashed, []string{sprintf(reasonCrashed, down, total)}
	}

	// The baseline guarantees the valid credential was accepted, so the latch
	// starts armed: any later refusal is the target having stopped serving.
	if denied := observation.Fault.Valid.RejectedAfter(true); denied > 0 {
		return Denied, []string{sprintf(reasonDenied, denied)}
	}

	return Held, []string{reasonHeld}
}

// unanswered counts across BOTH streams. A gateway that short-circuits the
// invalid credential at the edge while hanging on the valid one is not a
// crashed target, and judging the valid stream alone reports it as one.
func unanswered(window probe.Window) (int, int) {
	down := 0
	total := 0

	for _, stream := range []probe.Stream{window.Valid, window.Invalid} {
		for _, outcome := range stream.Outcomes {
			if !outcome.Disposition.Countable() {
				continue
			}
			total++
			if !outcome.Disposition.Answered() {
				down++
			}
		}
	}

	return down, total
}

// recoveryOf requires a run of consecutive healthy pairs, because declaring a
// state transition on a single lucky sample is how a flaky recovery reads as a
// clean one.
//
// An empty window is UNOBSERVED rather than recovered. Returning true there
// meant a run that collected no recovery evidence at all — an interrupted run,
// a target that stopped answering, a recovery window too short to pair —
// reported that the target came back, and exited 0.
func recoveryOf(recovery probe.Window) Recovery {
	if recovery.Paired() == 0 {
		return Unobserved
	}

	run := 0
	for i := 0; i < recovery.Valid.Len() && i < recovery.Invalid.Len(); i++ {
		if recovery.Valid.Outcomes[i].Disposition == probe.Accepted &&
			recovery.Invalid.Outcomes[i].Disposition == probe.Rejected {
			run++
			if run >= RecoveryRunLength {
				return Recovered
			}
			continue
		}
		run = 0
	}

	return Degraded
}
