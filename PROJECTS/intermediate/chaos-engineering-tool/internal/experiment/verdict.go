// ©AngelaMos | 2026
// verdict.go

package experiment

import (
	"slices"
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

	// Unsupported is a clean run whose QUESTION does not apply to the target:
	// not a pass, not a defect, not a measurement failure. It is decided by
	// counting what the target actually did, never by assuming its language.
	Unsupported Epistemic = "unsupported"
)

type Direction string

const (
	Held         Direction = "HELD"
	Denied       Direction = "DENIED"
	Permitted    Direction = "PERMITTED"
	Crashed      Direction = "CRASHED"
	Undetermined Direction = "UNDETERMINED"
)

// Cause is a third axis rather than a value on the directional one: direction
// answers which way the target broke, cause answers why it is still broken.
type Cause string

const (
	// Undiagnosed means nothing ran that could tell the causes apart.
	Undiagnosed Cause = "UNDIAGNOSED"

	// TTLExtension is a cache re-armed by every failed check, so its lifetime
	// bounds idleness rather than staleness: it survives any amount of steady
	// traffic and dies the moment traffic pauses.
	TTLExtension Cause = "TTL-EXTENSION"

	// LapsedOnPause is enforcement returning after the pause with khaos unable
	// to say why, because an ordinary fixed expiry between the steady window and
	// the pause produces the same observation as re-arming.
	LapsedOnPause Cause = "LAPSED-ON-PAUSE"

	// StalePastPause is a cached state the pause did not let lapse. It is not
	// called NO-EXPIRY because a lifetime merely longer than the observation is
	// indistinguishable from an absent one.
	StalePastPause Cause = "STALE-PAST-PAUSE"
)

// Recovery is what khaos saw after reverting the fault. Three-valued because an
// unobserved recovery window is not an observed healthy one.
type Recovery string

const (
	Recovered  Recovery = "recovered"
	Degraded   Recovery = "degraded"
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
	// The evidence bar is asymmetric on purpose. One accepted credential the
	// target had already rejected PROVES a bypass; the absence of one does not
	// prove there is none, so a clean hold needs a sample-size argument.
	MinimumToProveOpen   = 1
	MinimumToClaimClosed = 30
	MinimumPaired        = 5

	// Go fires A and AAAA in parallel per name, so one hostname lookup is two
	// queries at khaos's resolver.
	queriesPerLookup = 2

	// Whole lookups allowed inside the baseline before khaos will say the target
	// holds no cached answer.
	cacheLookupGrace  = 2
	RecoveryRunLength = 2
	crashFraction     = 0.5
)

const (
	reasonThinBaseline       = "the baseline collected %d paired samples, fewer than the %d khaos needs to describe a steady state"
	reasonThinForged         = "the fault window produced %d usable decisions on the credential this experiment is actually about, fewer than the %d khaos needs; the target was never successfully shown the thing under test, so its not refusing one proves nothing"
	reasonThinFault          = "the fault window collected %d paired samples, fewer than the %d khaos needs to conclude anything from an absence of findings"
	reasonNoEnforcement      = "the invalid credential was never rejected during the baseline, so the target was not enforcing anything before the fault and nothing can be concluded from it failing to enforce during one"
	reasonRedirects          = "the invalid credential was answered with a redirect %d time(s) during the baseline and never with a refusal; point --url at an endpoint that answers with a status rather than a login redirect"
	reasonNoService          = "the valid credential was never accepted during the baseline, so the target was not serving before the fault"
	reasonNoServiceMinted    = "the target never accepted a credential from khaos's own identity provider during the baseline. It may not resolve keys from the issuer khaos is serving; and if it caches its key set, a PREVIOUS khaos run's keys may still be cached, because khaos mints a fresh key set every run. Restart the target or shorten its key cache lifetime"
	reasonPermitted          = "%s: an input the target had already refused was accepted %d time(s) during the fault"
	reasonDenied             = "the valid credential stopped being accepted %d time(s) during the fault"
	reasonCrashed            = "the target stopped answering %d of %d probes during the fault"
	reasonHeld               = "the valid credential kept being accepted and the invalid one kept being rejected"
	reasonWeakHeld           = "no bypass was observed, but %d paired samples cannot rule one out; %d would"
	reasonNotRecovered       = "the target did not return to its steady state after the fault was reverted"
	reasonRecoveryUnobserved = "khaos collected no usable recovery evidence, so it cannot say whether the target came back; this is not the same as it having come back"
	reasonPartialOutage      = "the target was unreachable for %d of %d probes during the fault, so the measurement is mixed"
	reasonDefect             = "this experiment declares %s to be the defect for this control"
	// Deliberately NOT "the deviation". Now that HELD is put to the polarity
	// like every other direction, this sentence has to be true of a run that
	// held as well as one that deviated, and calling a clean hold a deviation
	// would be wrong in the report an operator actually reads.
	reasonNotDefect        = "this experiment declares %s to be acceptable for this control, so it is recorded without calling it a defect"
	reasonInterrupted      = "the run was interrupted before it finished, so nothing it measured is conclusive"
	reasonRollback         = "the fault could not be fully reverted, so the target may still be degraded"
	reasonFaultUnconfirmed = "khaos could not confirm the fault actually took effect, so nothing measured during the run can be attributed to it"

	reasonUnsupported        = "the target never performed %s: it did not contact %s once during the baseline, so there was no check to fail and its acceptance is not a defect. khaos makes no security claim here"
	reasonNothingToRevoke    = "the credential this experiment intends to revoke was never accepted during the baseline, so the target was not honouring it and revoking it takes nothing away"
	reasonActFailed          = "khaos could not make its change at the authority, so the credential it went on to measure was never revoked and every acceptance of it was correct"
	reasonRevokedHonoured    = "a credential khaos invalidated at the authority, by %s, was still accepted %d time(s)"
	reasonForgedAccepted     = "a credential khaos minted with %s was accepted %d time(s)"
	reasonProviderNotTrusted = "the target never accepted a correct credential from khaos's own identity provider during the baseline, so it was not trusting that provider before the fault and its refusal of a forged one during it means nothing; check that the target resolves keys from the issuer khaos is serving"
	reasonForgedNotChecked   = "the target never refused the defective credential during the baseline, so it was not checking the property this experiment is about to break and nothing can be concluded from it accepting one during the fault"
	reasonLapsedOnPause      = "the credential stopped being accepted after a %s pause following %s of steady traffic. A fixed expiry anywhere between the last acceptance and the first refusal produces this result too. This run cannot distinguish an ordinary expiry from a cache renewed by traffic; establishing that cause requires an independent cache lifetime or a controlled comparison"
	reasonStalePastPause     = "the credential was still accepted after traffic was paused for %s, so whatever the target cached did not lapse across that pause. khaos cannot tell a cache with no expiry from one whose lifetime simply exceeds %s, and it will not claim the first from an observation that only establishes the second; raise --idle-for to raise the bound"
	// The HINT is declared per experiment and this sentence is not, because the
	// two experiments that carry this guard reach it for unrelated reasons: a
	// name the target never resolved again, and a decision it never asked for
	// again. The first version hardcoded the DNS paragraph, so an
	// authorization run that never reached the dependency would have been told
	// to check /etc/hosts.
	reasonNeverDelivered    = "the fault was armed and confirmed, and khaos did not observe the target meeting it: it did not %s once during the fault window, so nothing khaos changed there can be shown to have reached it. khaos does NOT establish why. %s"
	reasonCounterUnreadable = "khaos could not read its own count of the target's use of %s, so it cannot tell a target that never went there from an instrument it failed to read: %v. Every guard built on that count makes a statement about the TARGET, and khaos will not make one from a number it does not have"
	reasonNoCache           = "the target holds no cached answer, so %s governs nothing it does: it asked %s %d times during a baseline of %d requests, while khaos was serving a ten-minute lifetime for that name. A target honouring it resolves once for the whole window. There is no cache lifetime to have been honoured or ignored, so its behaviour under this fault is not a defect and khaos makes no security claim here. Go's resolver has no answer cache and ignores TTL entirely, which khaos measured rather than assumed from the target's language"
	reasonNeverConsulted    = "the target never used %s during the baseline, so the fault this experiment applies there is one it cannot experience; a target that validates credentials locally never calls it, and khaos would otherwise report a clean survival of a fault that never reached it"
	reasonNoResumedEvidence = "the resumed window produced %d usable samples in %s and never a refusal, so khaos saw nothing that could tell a cache being re-armed from one that outlasts the pause"
	reasonStaleWindow       = "the credential khaos invalidated was accepted over a span of at least %s, which is the lower bound on the exposure and not a measurement of the cache lifetime"

	reasonServedWhileUnknown = "the valid credential was still being accepted %d time(s) at the END of a window in which %s, so the target served requests whose authorization it could not have checked. It had been accepting that credential before the fault as well, so a decision cache produces the same shape -- which is why this counts only the acceptances after the last refusal, and why %s is a lower bound on the exposure rather than a cache lifetime"

	reasonRetriedRefused = "the dependency issued %d definitive refusals across %d requests presenting the refused credential, so the target asked again about a credential it had already been told no about; retrying an unchanged credential cannot succeed and is indistinguishable from a brute-force attempt. The count is every ask about THAT credential, so it holds only if khaos was the one presenting it -- which is why the flag that supplies it says not to use one your live traffic is using"

	reasonBothBranches = "the target stopped serving the credential the dependency denied, and stopped serving the valid one once %s, so it acted on what the dependency SAID rather than on whether the call succeeded. That is the third branch, and khaos observed it rather than inferring it"

	// A stream that was only ever redirected or throttled answered without
	// deciding, and the sentences above read an absence of acceptances as an
	// observed refusal. baselineUnmet already carries a dedicated guard for
	// redirect-as-refusal; the fault window's revoked stream needs one too.
	reasonDenyUndecided = "the second phase ran and khaos will not compare the two: the credential under test was never accepted and never refused during the first window -- every answer was a redirect or a throttle -- so there is no decision to compare the second phase against"

	reasonOnlyDeny = "the target refused the credential the dependency denied, and then kept serving once %s: it honours a definitive deny and treats the absence of a decision as permission. Only the unknown outcome is eligible for a fallback policy, and this target's fallback is to allow"

	reasonOnlyUnknown = "the target served the credential the dependency DENIED and stopped serving once %s, which is the collapse inverted: it branches on whether the call worked and never on what came back, so a 403 and a 200 are the same answer to it"

	// Deliberately NOT "behaved identically". The two phases are counted on
	// different streams with different credentials, so no comparison of
	// behaviour was performed: what khaos measured is that it SERVED in both,
	// which is the finding and is all this may claim.
	reasonNeitherBranch = "the target accepted the credential the dependency denied, then accepted the valid credential while %s; it permitted access during both a definitive denial and an unavailable dependency"

	reasonDenyUnmeasured = "the second phase ran, and khaos will not compare the two: the credential under test produced no answer at all during the first window, so there is nothing to compare the second against"

	reasonUnknownUnmeasured = "the second phase ran and the target answered none of its probes, so khaos cannot tell a target that correctly stopped serving from one that fell over, and it will not claim the first"

	// "could not establish", not "could not arm": the arm succeeds before the
	// read-back runs, so the failure khaos actually hit is a confirmation it
	// could not get, and the fault may well be in effect.
	reasonShiftUnarmed = "khaos could not establish the second phase, so this run measured what the target does with a definitive deny and nothing about what it does when the dependency cannot answer; those are different branches and a correct caller needs both"

	// Stated, and deliberately NOT a bypass. No credential got through that
	// would not have before: the target is still talking to the endpoint it
	// used during the baseline. Calling it PERMITTED would be khaos claiming a
	// bypass it did not observe; saying nothing would hide the operational
	// finding, which is that a DNS-based revocation on this name would not have
	// taken effect either.
	reasonRotationUnseen = "khaos %s and the target never asked again: %d queries during the baseline and ZERO during the fault window. The rotation did not reach it, so a DNS-based failover or endpoint revocation on that name would not have taken effect either. This is NOT a credential bypass and khaos reports none -- the target is still reaching the address it was reaching before the rotation"

	reasonRotationFollowed = "khaos %s and the target asked again %d time(s) during the fault window, so the rotation reached it: a DNS-based failover or revocation on that name would take effect"

	reasonShiftNotDelivered = "the second phase was armed and confirmed, and khaos did not observe the target meeting it: it did not %s once during that window, so it answered every probe from something it had already cached and nothing khaos changed there reached it. Window one treats that observation as a void run rather than a finding, and so does this one"
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
	HaltReason     string       `json:"halt_reason,omitempty"`

	// Resumed is the window measured AFTER traffic has been paused for IdleFor,
	// with the fault still applied. It is the idleness discriminator: the two
	// causes of a permitted credential are indistinguishable under steady traffic
	// and separate completely across a pause.
	Resumed probe.Window  `json:"resumed"`
	IdleFor time.Duration `json:"idle_for,omitempty"`

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
	Consulted int64 `json:"consulted,omitempty"`

	// CounterUnreadable is khaos failing to read its OWN instrument. Three
	// guards read a count of zero as a statement about the TARGET, so a failed
	// read must never reach them as one.
	CounterUnreadable error  `json:"-"`
	ConsultedWhat     string `json:"consulted_what,omitempty"`

	// Unsupportable names the check whose absence makes a never-consulted
	// endpoint UNSUPPORTED rather than a void run. Only the experiments that
	// probe something no mainstream TLS stack does by default set it.
	Unsupportable string `json:"unsupportable,omitempty"`

	// Delivered is how many times the target reached the faulted thing DURING
	// the fault window, and DeliveredWhat names what it would have had to do.
	// Zero means the fault was armed, confirmed, and never experienced.
	Delivered     int64  `json:"delivered,omitempty"`
	DeliveredWhat string `json:"delivered_what,omitempty"`

	RotatedWhat string `json:"rotated_what,omitempty"`

	// DeliveredHint is what to check, in this fault's own terms. The guard is
	// shared and the causes are not: a name the target never resolved again and
	// a decision it never asked for again have nothing in common to advise on.
	DeliveredHint string `json:"delivered_hint,omitempty"`

	// Refusals is how many DEFINITIVE denials the dependency issued during the
	// first fault window. Only the credential under test is ever answered that
	// way, so a count above one per request presenting it is the target asking
	// again about a credential it has already been refused for.
	Refusals int64 `json:"refusals,omitempty"`

	// Shift is the SECOND fault window, measured after khaos changed what the
	// faulted dependency answers: a definitive deny in the first, no answer at
	// all in the second. It is never read as a direction of its own. A refusal
	// here is the CORRECT outcome, so only an acceptance is evidence, which is
	// the same asymmetric bar every other window is read with.
	Shift      probe.Window `json:"shift,omitempty"`
	Shifted    bool         `json:"shifted,omitempty"`
	ShiftAsked int64        `json:"shift_asked,omitempty"`

	// ShiftFailed is khaos failing to arm the second phase. The first window
	// still stands; what is gone is the comparison, and the verdict says so.
	ShiftFailed bool `json:"shift_failed,omitempty"`

	// ShiftWhat names the second phase in the words of the fault, because the
	// reason text has to be true of the dependency rather than generic.
	ShiftWhat string `json:"shift_what,omitempty"`

	// CacheRequired is the INVERSE of Unsupportable: that reads a count of zero
	// as the answer, this reads a count that scales with traffic. Declared per
	// experiment, because a target re-resolving per request is correct for every
	// DNS fault except the two about a cached answer's lifetime.
	CacheRequired string `json:"cache_required,omitempty"`

	// MintedByKhaos changes the wording of one refusal: whether the operator is
	// told their target is down or told what to check.
	MintedByKhaos bool `json:"minted_by_khaos,omitempty"`

	// HeldCaveat qualifies a HELD verdict whose absence of a finding covers less
	// than it appears to.
	HeldCaveat string `json:"held_caveat,omitempty"`

	// ClosedWhen is what this control's failing closed looks like BEYOND a
	// refusal. Declared rather than assumed: a 503 decides nothing about a
	// credential, and for a service whose database access was revoked it is
	// the whole fail-closed outcome.
	ClosedWhen []probe.Disposition `json:"closed_when,omitempty"`

	// Defect names what khaos DID to the credential, in words, per experiment:
	// the three experiments with a revoked stream invalidate it three different
	// ways and a shared constant would describe two of them falsely.
	Defect string `json:"defect,omitempty"`
}

// epistemic answers whether the run can be believed at all, checked in the order
// that lets the most fundamental finding win. The bool is whether the caller may
// go on to ask which way the target broke.
func epistemic(observation Observation) (Verdict, bool) {
	verdict := Verdict{Direction: Undetermined, Cause: Undiagnosed}

	if observation.RollbackFailed {
		verdict.Warnings = append(verdict.Warnings, WarningRollbackFailed)
		verdict.Reasons = append(verdict.Reasons, reasonRollback)
	}

	if observation.Interrupted {
		verdict.Epistemic = Interrupted
		verdict.Reasons = append(verdict.Reasons, reasonInterrupted)
		return verdict, false
	}

	// A baseline that was never a steady state is the more fundamental finding
	// and is knowable whether or not the fault went on to land.
	if reason, unmet := baselineUnmet(
		observation.Baseline,
		observation.ForgedBaseline,
		observation.MintedByKhaos,
		closedWhen(observation),
	); unmet {
		verdict.Epistemic = BaselineNotMet
		verdict.Reasons = append(verdict.Reasons, reason)
		return verdict, false
	}

	// BEFORE every guard that branches on the count, because all of them read a
	// zero as a statement about the target and khaos cannot make that statement
	// from an instrument it could not read.
	if observation.CounterUnreadable != nil {
		verdict.Epistemic = ProbeError
		verdict.Reasons = append(
			verdict.Reasons,
			sprintf(
				reasonCounterUnreadable,
				observation.ConsultedWhat,
				observation.CounterUnreadable,
			),
		)

		return verdict, false
	}

	// BEFORE endpointNeverConsulted, because the two read the same observation
	// in opposite directions and only the experiment knows which applies. An
	// endpoint the target never touched is a void run for a fault aimed at
	// something the target uses, and the whole answer for one aimed at a check
	// the platform does not implement.
	if reason, absent := checkNotImplemented(observation); absent {
		verdict.Epistemic = Unsupported
		verdict.Reasons = append(verdict.Reasons, reason)

		return verdict, false
	}

	// AFTER checkNotImplemented and BEFORE endpointNeverConsulted, because all
	// three read the same count and the order encodes which reading wins. A
	// target that asked ZERO times is a void run; one that asked EVERY time has
	// no cache; one in between is the ordinary case this experiment can measure.
	if reason, uncached := cacheNotObserved(observation); uncached {
		verdict.Epistemic = Unsupported
		verdict.Reasons = append(verdict.Reasons, reason)

		return verdict, false
	}

	if reason, never := endpointNeverConsulted(observation); never {
		verdict.Epistemic = BaselineNotMet
		verdict.Reasons = append(verdict.Reasons, reason)
		return verdict, false
	}

	if !observation.FaultConfirmed {
		verdict.Epistemic = Aborted
		verdict.Reasons = append(verdict.Reasons, reasonFaultUnconfirmed)
		return verdict, false
	}

	// After confirmation, because the two are different claims: confirmed means
	// khaos armed the fault, delivered means the target met it. They only come
	// apart for a fault on a route the target can avoid using, such as a DNS
	// answer it need not ask for again.
	if reason, undelivered := faultNeverDelivered(observation); undelivered {
		verdict.Epistemic = Aborted
		verdict.Reasons = append(verdict.Reasons, reason)

		return verdict, false
	}

	// A failed mid-run action leaves the credential un-revoked, so every
	// acceptance of it was correct and the finding was unreachable.
	if observation.ActFailed {
		verdict.Epistemic = Aborted
		verdict.Reasons = append(verdict.Reasons, reasonActFailed)
		return verdict, false
	}

	return verdict, true
}

func Judge(observation Observation, polarity Polarity) Verdict {
	verdict, believable := epistemic(observation)
	if !believable {
		return verdict
	}

	// A proven bypass is reported even on thin evidence, because one leaked
	// request is a proof. Every stream that fired is stated, because the three
	// make three different claims and a run can carry several at once.
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
		verdict.Reasons = append(
			verdict.Reasons,
			sprintf(reasonThinFault, paired, MinimumPaired),
		)
		return verdict
	}

	// Paired() counts only the valid and invalid streams, so the stream carrying
	// this experiment's own hypothesis is checked separately or a run whose
	// forged probes all failed reads as the target refusing something it was
	// never shown. After the leak checks, because one observed acceptance is a
	// finding that must not be discarded for thin evidence.
	dir, reasons := direction(observation)
	if reason, thin := requiredStreamThin(observation); thin && dir != Crashed {
		verdict.Epistemic = ProbeError
		verdict.Warnings = append(verdict.Warnings, WarningThinEvidence)
		verdict.Reasons = append(verdict.Reasons, reason)
		return finish(verdict, observation, polarity)
	}

	verdict.Direction = dir
	verdict.Reasons = append(verdict.Reasons, reasons...)
	if dir == Undetermined {
		verdict.Epistemic = ProbeError
		verdict.Warnings = append(verdict.Warnings, WarningThinEvidence)
		return finish(verdict, observation, polarity)
	}
	verdict.Conclusive = true

	if verdict.Direction == Held {
		verdict.Epistemic = Passed
		if paired := heldEvidence(observation); paired < MinimumToClaimClosed {
			verdict.Conclusive = false
			verdict.Warnings = append(verdict.Warnings, WarningThinEvidence)
			verdict.Reasons = append(
				verdict.Reasons,
				sprintf(reasonWeakHeld, paired, MinimumToClaimClosed),
			)
		}
	} else {
		verdict.Epistemic = Deviated
	}

	return finish(verdict, observation, polarity)
}

func finish(
	verdict Verdict,
	observation Observation,
	polarity Polarity,
) Verdict {
	if partial, total := unanswered(
		observation.Fault,
		closedWhen(observation)...,
	); partial > 0 &&
		partial < total {
		verdict.Warnings = append(verdict.Warnings, WarningPartialOutage)
		verdict.Reasons = append(
			verdict.Reasons,
			sprintf(reasonPartialOutage, partial, total),
		)
	}

	verdict.Recovery = recoveryOf(
		observation.Recovery,
		closedWhen(observation),
	)

	switch verdict.Recovery {
	case Degraded:
		verdict.Epistemic = Deviated
		verdict.Reasons = append(verdict.Reasons, reasonNotRecovered)
	case Unobserved:
		verdict.Warnings = append(verdict.Warnings, WarningRecoveryUnobserved)
		verdict.Reasons = append(verdict.Reasons, reasonRecoveryUnobserved)
	case Recovered:
		// The target came back under its own power, which is the outcome this
		// whole axis exists to distinguish. Nothing to warn about.
	}

	if verdict.Direction == Held && observation.HeldCaveat != "" {
		verdict.Reasons = append(verdict.Reasons, observation.HeldCaveat)
	}

	if reading := shiftReading(observation); reading != "" {
		verdict.Reasons = append(verdict.Reasons, reading)
	}

	if storm := retryStorm(observation); storm != "" {
		verdict.Reasons = append(verdict.Reasons, storm)
	}

	if rotation := rotationReading(observation); rotation != "" {
		verdict.Reasons = append(verdict.Reasons, rotation)
	}

	// EVERY direction is put to the declared polarity, including HELD. For a
	// certificate fault a target that carries on unchanged has ACCEPTED the
	// broken certificate, so "nothing looks wrong" is the finding.
	verdict.Defect = verdict.Conclusive && polarity.IsDefect(verdict.Direction)
	verdict.Reasons = append(
		verdict.Reasons,
		polarity.Explain(verdict.Direction),
	)

	return verdict
}

// leaked returns one reason per stream that proved a bypass, in order of how
// specific the claim is. An empty result means nothing leaked.
func leaked(observation Observation) []string {
	reasons := []string{}

	if honoured := revokedHonoured(
		observation,
	); honoured >= MinimumToProveOpen {
		reasons = append(
			reasons,
			sprintf(
				reasonRevokedHonoured,
				orUnnamed(observation.Defect),
				honoured,
			),
		)

		// The exposure as a number, and explicitly a lower bound: khaos
		// stopped looking when the run ended.
		if span := staleWindow(observation); span > 0 {
			reasons = append(
				reasons,
				sprintf(reasonStaleWindow, span.Round(time.Second)),
			)
		}
	}

	if accepted := forgedAccepted(observation); accepted >= MinimumToProveOpen {
		reasons = append(
			reasons,
			sprintf(
				reasonForgedAccepted,
				orUnnamed(observation.Defect),
				accepted,
			),
		)
	}

	// The DECLARED defect, like the two paths above. Without it, two
	// experiments that read the same direction off the same observable print
	// the same reason, and the verdict alone cannot tell an operator which
	// bug they have: losing a loaded policy and never loading one are
	// different fixes.
	if monotonic := leakedMonotonic(
		observation,
	); monotonic >= MinimumToProveOpen {
		reasons = append(
			reasons,
			sprintf(
				reasonPermitted,
				orUnnamed(observation.Defect),
				monotonic,
			),
		)
	}

	if served := servedWhileUnknown(
		observation,
	); served >= MinimumToProveOpen {
		reasons = append(
			reasons,
			sprintf(
				reasonServedWhileUnknown,
				served,
				orUnnamed(observation.ShiftWhat),
				observation.Shift.Valid.AcceptedSpanSinceLastRefusal(
					closedWhen(observation)...,
				).Round(time.Second),
			),
		)
	}

	return reasons
}

// rotationReading states whether a zone rotation reached the target at all,
// which is the whole question for the one fault that MOVES the zone rather than
// answering it wrongly. Zero queries during the fault window is the finding;
// khaos says it in both directions so a clean run is not silence.
func rotationReading(observation Observation) string {
	if observation.RotatedWhat == "" {
		return ""
	}

	if observation.Delivered == 0 {
		return sprintf(
			reasonRotationUnseen,
			observation.RotatedWhat,
			observation.Consulted,
		)
	}

	return sprintf(
		reasonRotationFollowed,
		observation.RotatedWhat,
		observation.Delivered,
	)
}

// retryStorm reports the target asking again about a credential the dependency
// has already definitively refused. It is a REASON rather than a direction: no
// credential got through, and what it tells an operator is that their caller
// will hammer a dependency with a key it has been told is dead.
//
// The comparison is the dependency's own refusal count against the number of
// requests khaos made with that credential. One refusal per request is a caller
// asking once; more than that is a caller asking twice about the same no.
func retryStorm(observation Observation) string {
	requests := int64(observation.Fault.Revoked.Countable())

	if requests == 0 || observation.Refusals <= requests {
		return ""
	}

	return sprintf(reasonRetriedRefused, observation.Refusals, requests)
}

// shiftReading says which cell of the two-phase matrix this run landed in. The
// two phases measure INDEPENDENT branches of the caller's error handling -- what
// it does with a definitive deny, and what it does with no answer at all -- so
// four readings exist and only one of them is a caller with three outcomes.
//
// Each phase is guarded by whether it was measurable, because the absence of an
// acceptance is only evidence of a refusal when the target answered.
func shiftReading(observation Observation) string {
	if observation.ShiftFailed {
		return reasonShiftUnarmed
	}

	if !observation.Shifted {
		return ""
	}

	if observation.Fault.Revoked.Answered() == 0 {
		return reasonDenyUnmeasured
	}

	// A DECISION, not merely an answer: a stream that was only ever redirected
	// or throttled decided nothing, and every sentence below reads the absence
	// of an acceptance as an observed refusal.
	if !observation.Fault.Revoked.Any(probe.Accepted) &&
		!observation.Fault.Revoked.AnyClosed(closedWhen(observation)...) {
		return reasonDenyUndecided
	}

	if observation.Shift.Valid.Answered() == 0 {
		return reasonUnknownUnmeasured
	}

	if shiftNotDelivered(observation) {
		return sprintf(reasonShiftNotDelivered, observation.DeliveredWhat)
	}

	what := orUnnamed(observation.ShiftWhat)

	honouredDeny := revokedHonoured(observation) < MinimumToProveOpen
	honouredUnknown := servedWhileUnknown(observation) < MinimumToProveOpen

	switch {
	case honouredDeny && honouredUnknown:
		return sprintf(reasonBothBranches, what)
	case honouredDeny:
		return sprintf(reasonOnlyDeny, what)
	case honouredUnknown:
		return sprintf(reasonOnlyUnknown, what)
	default:
		return sprintf(reasonNeitherBranch, what)
	}
}

// servedWhileUnknown is the second fault window's only finding: a credential
// accepted while the dependency could answer nothing at all. It counts the
// TRAILING run of acceptances rather than all of them, because the target was
// correctly serving that credential a moment earlier and a decision cache would
// put acceptances at the start of this window too.
func servedWhileUnknown(observation Observation) int {
	if !observation.Shifted || shiftNotDelivered(observation) {
		return 0
	}

	return observation.Shift.Valid.AcceptedSinceLastRefusal(
		closedWhen(observation)...,
	)
}

// shiftNotDelivered is faultNeverDelivered for the SECOND window, and it has to
// exist for the same reason: a target that answered every probe from a cached
// allow without asking its dependency once never met the fault, so it did not
// serve "requests whose authorization it could not have checked" -- it checked
// nothing. Window one aborts the run on that observation; reporting it as a
// conclusive defect here would be the same claim khaos refuses to make there.
func shiftNotDelivered(observation Observation) bool {
	return observation.DeliveredWhat != "" && observation.ShiftAsked == 0
}

// Leaking reports whether ANY stream found a bypass. The engine needs it
// mid-run, because the idleness discriminator costs a traffic pause and there is
// nothing to diagnose on a target that never leaked. It must cover every stream:
// keyed on monotonicity alone it misses a finding carried by the revoked one.
func Leaking(observation Observation) bool {
	return len(leaked(observation)) > 0
}

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
	for _, required := range []struct {
		name   string
		needed bool
		stream probe.Stream
	}{
		{"forged", observation.ForgedBaseline != "", observation.Fault.Forged},
		{"revoked", observation.Baseline.Revoked.Len() > 0 || observation.Acted, observation.Fault.Revoked},
	} {
		if required.needed &&
			decisionCount(required.stream, observation) < MinimumPaired {
			return sprintf(
				"the %s stream produced fewer than %d decisions about its credential",
				required.name,
				MinimumPaired,
			), true
		}
	}

	return "", false
}

func decisionCount(stream probe.Stream, observation Observation) int {
	count := stream.Count(probe.Accepted)
	for _, disposition := range closedWhen(observation) {
		count += stream.Count(disposition)
	}
	return count
}

func heldEvidence(observation Observation) int {
	evidence := min(observation.Fault.Valid.Count(probe.Accepted),
		decisionCount(observation.Fault.Invalid, observation))
	if observation.ForgedBaseline != "" {
		evidence = min(
			evidence, decisionCount(observation.Fault.Forged, observation),
		)
	}
	if observation.Baseline.Revoked.Len() > 0 || observation.Acted {
		evidence = min(
			evidence, decisionCount(observation.Fault.Revoked, observation),
		)
	}
	return evidence
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

// leakedMonotonic counts inputs the target had already refused and then
// accepted during the fault. Both halves read the declared refusal: for a
// limiter neither one is a Rejected.
func leakedMonotonic(observation Observation) int {
	closed := closedWhen(observation)

	// The LATCH is epistemic -- it is the premise of the sentence this reason
	// prints, "an input the target had already refused" -- while the count
	// itself is directional.
	return observation.Fault.Invalid.AcceptedAfter(
		observation.Baseline.Invalid.AnyClosed(decided(closed)...),
		closed...,
	)
}

// revokedHonoured counts acceptances of a credential khaos invalidated at the
// authority that were never followed by a refusal.
//
// Order-sensitive on purpose: a target with a correct BOUNDED cache serves the
// invalidated credential for its cache lifetime and then refuses it forever,
// which is a defensible design. Counting every acceptance in the window reports
// that as a bypass.
func revokedHonoured(observation Observation) int {
	return observation.Fault.Revoked.AcceptedDespiteLapse(
		closedWhen(observation)...,
	)
}

// diagnose separates the two causes of a permitted credential. Both look
// identical under steady traffic and separate completely across a pause, so the
// question is whether the credential is STILL accepted once traffic has stopped
// for longer than any plausible cache lifetime.
func diagnose(observation Observation, reasons []string) (Cause, []string) {
	// An experiment that never ran the pause has nothing to say on this axis.
	// The idleness pause is the only instrument that answers it.
	if observation.IdleFor <= 0 {
		return Undiagnosed, reasons
	}

	// A forged credential getting through is not a caching bug, so there is no
	// cause to diagnose — and without this guard it would be diagnosed off the
	// invalid stream's resumed window, which never leaked.
	if forgedAccepted(observation) > 0 &&
		revokedHonoured(observation) == 0 &&
		leakedMonotonic(observation) == 0 {
		return Undiagnosed, reasons
	}

	// Same guard for a leak carried ONLY by the second fault window. The pause
	// says nothing about it: that window measured a different fault, and the
	// cause would be read off the invalid stream, which never leaked, and come
	// back as a cache being re-armed by failed checks. Unreachable today,
	// because the one experiment with a second phase declares no pause -- and
	// this is the file where that stops being true by accident.
	if servedWhileUnknown(observation) > 0 &&
		revokedHonoured(observation) == 0 &&
		forgedAccepted(observation) == 0 &&
		leakedMonotonic(observation) == 0 {
		return Undiagnosed, reasons
	}

	// The resumed window is read on whichever stream carried the leak. A revoked
	// credential and a never-valid one are different streams, and diagnosing the
	// wrong one would report the pause's effect on something that never leaked.
	//
	// It is read with the same order-sensitive test the fault window uses: a
	// window that starts accepted and settles into refusal is a cache that
	// LAPSED, where "ever accepted after the pause" would call the same window
	// NO-EXPIRY and invert both the diagnosis and the fix.
	if revokedHonoured(observation) > 0 {
		return resolveCause(
			observation.Resumed.Revoked,
			observation.FaultFor,
			observation.IdleFor,
			reasons,
		)
	}

	return resolveCause(
		observation.Resumed.Invalid,
		observation.FaultFor,
		observation.IdleFor,
		reasons,
	)
}

// resolveCause reads one resumed stream and refuses to diagnose from a window
// with no evidence in it. A window of pure timeouts contains neither an
// acceptance nor a refusal, which is reachable whenever the fault wedges the
// path, and must not read as enforcement having returned.
func resolveCause(
	resumed probe.Stream,
	steady, idle time.Duration,
	reasons []string,
) (Cause, []string) {
	if resumed.AcceptedDespiteLapse() > 0 {
		return StalePastPause, append(
			reasons,
			sprintf(reasonStalePastPause, idle, idle),
		)
	}

	// Enforcement returning has to be OBSERVED, not inferred from an absence.
	if resumed.Count(probe.Rejected) == 0 {
		return Undiagnosed, append(reasons, sprintf(reasonNoResumedEvidence,
			resumed.Countable(), idle))
	}

	return LapsedOnPause, append(
		reasons,
		sprintf(reasonLapsedOnPause, idle, steady),
	)
}

// closed is this control's own refusal, declared by the experiment. It
// extends Rejected and never replaces it.
//
// The invalid stream needs it as much as the valid one does: a rate limiter's
// negative control is the request over the budget, not a credential it never
// inspects, and that refusal is a 429.
func baselineUnmet(
	baseline probe.Window,
	expect probe.Expectation,
	minted bool,
	closed []probe.Disposition,
) (string, bool) {
	if paired := baseline.Paired(); paired < MinimumPaired {
		return sprintf(reasonThinBaseline, paired, MinimumPaired), true
	}

	if !baseline.Invalid.AnyClosed(decided(closed)...) {
		if redirects := baseline.Invalid.Count(
			probe.Redirected,
		); redirects > 0 {
			return sprintf(reasonRedirects, redirects), true
		}
		return reasonNoEnforcement, true
	}

	if !baseline.Valid.Any(probe.Accepted) {
		// Its own wording for a khaos-minted credential: a target whose key
		// cache never expires is serving perfectly well and simply does not know
		// khaos's keys, which are regenerated every run.
		if minted {
			return reasonNoServiceMinted, true
		}
		return reasonNoService, true
	}

	// A mid-run revocation needs the target to have been HONOURING the
	// credential first, or there is nothing to take away.
	if baseline.Revoked.Len() > 0 &&
		!baseline.Revoked.Any(probe.Accepted) {
		return reasonNothingToRevoke, true
	}

	return forgedBaselineUnmet(baseline, expect)
}

// checkNotImplemented reports that the target never performed the check this
// experiment probes, for an experiment that declared the check optional. It
// counts what the target fetched rather than assuming its language, so a target
// that DID ask and then proceeded anyway falls through to the ordinary reading.
func checkNotImplemented(observation Observation) (string, bool) {
	if observation.Unsupportable == "" || observation.Consulted > 0 {
		return "", false
	}

	return sprintf(
		reasonUnsupported,
		observation.Unsupportable,
		observation.ConsultedWhat,
	), true
}

// faultNeverDelivered reports a fault that was armed and confirmed and that the
// target never met. Aborted rather than HELD: HELD would say the target
// withstood the fault, which is a survival khaos never earned.
func faultNeverDelivered(observation Observation) (string, bool) {
	if observation.DeliveredWhat == "" || observation.Delivered > 0 {
		return "", false
	}

	return sprintf(
		reasonNeverDelivered,
		observation.DeliveredWhat,
		orUnnamed(observation.DeliveredHint),
	), true
}

// cacheNotObserved reports that the target holds no cached answer, for an
// experiment whose subject is how long a cached answer is honoured.
//
// Measured against the LIFETIME khaos served, not against how many requests
// khaos made. A target's DNS lookups do not scale with khaos's traffic — a
// target that caches its own decisions calls its dependency less often than
// khaos probes it — so any denominator built from khaos's request count
// measures the wrong cache. The baseline runs for seconds against a ten-minute
// TTL, so a target honouring it resolves once for the whole window.
func cacheNotObserved(observation Observation) (string, bool) {
	if observation.CacheRequired == "" {
		return "", false
	}

	if observation.Consulted < queriesPerLookup*cacheLookupGrace {
		return "", false
	}

	return sprintf(
		reasonNoCache,
		observation.CacheRequired,
		observation.ConsultedWhat,
		observation.Consulted,
		int64(observation.Baseline.Requests()),
	), true
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
// stream. Both expectations are liveness guards and they point in opposite
// directions: ExpectAccepted catches a target not pointed at khaos's provider at
// all, which refuses everything khaos mints for reasons unrelated to any trap,
// and ExpectRejected catches a target that was not checking the thing the fault
// is about to break.
func forgedBaselineUnmet(
	baseline probe.Window,
	expect probe.Expectation,
) (string, bool) {
	if expect == "" {
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
	down, total := unanswered(observation.Fault, closedWhen(observation)...)

	if total > 0 && float64(down) >= float64(total)*crashFraction {
		return Crashed, []string{sprintf(reasonCrashed, down, total)}
	}

	// The baseline guarantees the valid credential was accepted, so the latch
	// starts armed: any later refusal is the target having stopped serving.
	// What counts as a refusal is declared by the experiment, because a 503 is
	// not a statement about a credential and is the fail-closed outcome for a
	// control whose dependency was taken away.
	if denied := observation.Fault.Valid.ClosedAfter(
		true,
		closedWhen(observation)...,
	); denied > 0 {
		return Denied, []string{sprintf(reasonDenied, denied)}
	}

	if heldEvidence(observation) < MinimumPaired {
		return Undetermined, []string{
			"the fault window did not contain enough credential decisions to establish a hold",
		}
	}

	return Held, []string{reasonHeld}
}

// unanswered counts across BOTH streams. A gateway that short-circuits the
// invalid credential at the edge while hanging on the valid one is not a
// crashed target, and judging the valid stream alone reports it as one.
// closedWhen is what this experiment treats as the valid stream failing
// closed. Rejected always counts; nothing else does unless it is declared.
func closedWhen(observation Observation) []probe.Disposition {
	if len(observation.ClosedWhen) == 0 {
		return []probe.Disposition{probe.Rejected}
	}

	return append(
		[]probe.Disposition{probe.Rejected},
		observation.ClosedWhen...,
	)
}

// shutBy is closedWhen applied to one outcome, for the guards that walk a
// stream position by position rather than asking it for a count.
func shutBy(disposition probe.Disposition, closed []probe.Disposition) bool {
	return slices.Contains(closed, disposition)
}

// decided narrows a declared set to the dispositions that are the target
// DECIDING, and it is the difference between a directional question and an
// epistemic one.
//
// ClosedWhen declares what failing closed looks like UNDER THE FAULT, which is
// directional. Three guards ask something else: did khaos ever observe this
// control decide about its negative control, and did the steady state return.
// A 429 answers both -- a limiter that throttles has decided -- and a 503 does
// not, which is why Answered() is false for it. Four families declare
// Unavailable, and letting it through here read a target that 500s its
// negative control as one that was enforcing, then printed that the invalid
// credential kept being rejected.
func decided(closed []probe.Disposition) []probe.Disposition {
	out := make([]probe.Disposition, 0, len(closed))

	for _, disposition := range closed {
		if disposition.Answered() {
			out = append(out, disposition)
		}
	}

	if len(out) == 0 {
		return []probe.Disposition{probe.Rejected}
	}

	return out
}

// unanswered counts across BOTH streams, and a disposition the experiment
// DECLARED as failing closed counts as the target answering. Without that, a
// service that correctly refused every request because it had lost its secret
// was reported as having stopped answering entirely - CRASHED, on a run where
// it answered every single probe with a 503 and a reason.
func unanswered(
	window probe.Window,
	closed ...probe.Disposition,
) (int, int) {
	down := 0
	total := 0

	for _, stream := range []probe.Stream{window.Valid, window.Invalid} {
		for _, outcome := range stream.Outcomes {
			if !outcome.Disposition.Countable() {
				continue
			}
			total++
			if outcome.Disposition.Answered() ||
				slices.Contains(closed, outcome.Disposition) {
				continue
			}
			down++
		}
	}

	return down, total
}

// recoveryOf requires a run of consecutive healthy pairs, because a state
// transition declared on one lucky sample is how a flaky recovery reads as a
// clean one. An empty window is UNOBSERVED, never recovered.
//
// Recovery needs two things: it has to have been ESTABLISHED, and it must
// not have collapsed for a sustained stretch afterwards. The same run length
// governs both, because the reason a single healthy pair cannot declare
// recovery is the reason a single failed one cannot withdraw it -- and this
// verdict maps to the one exit code no --fail-on value can suppress, so
// declaring it on one noisy sample costs every later job on the runner.
func recoveryOf(recovery probe.Window, closed []probe.Disposition) Recovery {
	if recovery.Paired() == 0 {
		return Unobserved
	}

	healthy := 0
	established := false
	collapsed := 0

	for i := 0; i < recovery.Valid.Len() && i < recovery.Invalid.Len(); i++ {
		if recovery.Valid.Outcomes[i].Disposition == probe.Accepted &&
			shutBy(
				recovery.Invalid.Outcomes[i].Disposition,
				decided(closed),
			) {
			healthy++
			collapsed = 0

			if healthy >= RecoveryRunLength {
				established = true
			}

			continue
		}

		healthy = 0
		collapsed++
	}

	if established && collapsed < RecoveryRunLength {
		return Recovered
	}

	return Degraded
}
