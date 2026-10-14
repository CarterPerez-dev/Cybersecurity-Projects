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
	reasonPermitted          = "a credential the target had already rejected was accepted %d time(s) during the fault"
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
	reasonTTLExtension       = "the credential survived %s of STEADY traffic and then stopped being accepted after a %s pause, and no fixed lifetime behaves that way: every failed check was re-arming whatever the target had cached, a decision or a key set, so the lifetime was bounding IDLENESS rather than staleness. The fix is to stop writing to the cache in the error branch"
	reasonLapsedOnPause      = "the credential stopped being accepted after the %s pause, but the steady-traffic window before it was only %s, so an ordinary fixed expiry between those two durations produces this exact result and khaos will not call it re-arming. Re-run with --fault-for at least %s to separate them"
	reasonStalePastPause     = "the credential was still accepted after traffic was paused for %s, so whatever the target cached did not lapse across that pause. khaos cannot tell a cache with no expiry from one whose lifetime simply exceeds %s, and it will not claim the first from an observation that only establishes the second; raise --idle-for to raise the bound"
	reasonNeverDelivered     = "the fault was armed and confirmed, and khaos did not observe the target meeting it: it did not %s once during the fault window, so nothing khaos changed there can be shown to have reached it. khaos does NOT establish why. A kept-alive connection produces this shape -- Go's HTTP transport resolves a name once when it opens a connection and never again while that connection lives, measured at two lookups across forty-six requests -- and so would the target's own resolver cache, an /etc/hosts entry, or resolution over DoH, none of which khaos ruled out. What to check, in that order: the target's connection lifetime, its own DNS cache, /etc/hosts, and whether it resolves over plain DNS at all"
	reasonCounterUnreadable  = "khaos could not read its own count of the target's use of %s, so it cannot tell a target that never went there from an instrument it failed to read: %v. Every guard built on that count makes a statement about the TARGET, and khaos will not make one from a number it does not have"
	reasonNoCache            = "the target holds no cached answer, so %s governs nothing it does: it asked %s %d times during a baseline of %d requests, while khaos was serving a ten-minute lifetime for that name. A target honouring it resolves once for the whole window. There is no cache lifetime to have been honoured or ignored, so its behaviour under this fault is not a defect and khaos makes no security claim here. Go's resolver has no answer cache and ignores TTL entirely, which khaos measured rather than assumed from the target's language"
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
	); partial > 0 &&
		partial < total {
		verdict.Warnings = append(verdict.Warnings, WarningPartialOutage)
		verdict.Reasons = append(
			verdict.Reasons,
			sprintf(reasonPartialOutage, partial, total),
		)
	}

	verdict.Recovery = recoveryOf(observation.Recovery)

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

	// EVERY direction is put to the declared polarity, including HELD. For a
	// certificate fault a target that carries on unchanged has ACCEPTED the
	// broken certificate, so "nothing looks wrong" is the finding.
	verdict.Defect = polarity.IsDefect(verdict.Direction)
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

	if monotonic := leakedMonotonic(
		observation,
	); monotonic >= MinimumToProveOpen {
		reasons = append(reasons, sprintf(reasonPermitted, monotonic))
	}

	return reasons
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
// Order-sensitive on purpose: a target with a correct BOUNDED cache serves the
// invalidated credential for its cache lifetime and then refuses it forever,
// which is a defensible design. Counting every acceptance in the window reports
// that as a bypass.
func revokedHonoured(observation Observation) int {
	return observation.Fault.Revoked.AcceptedDespiteLapse()
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

	// The soundness condition for the causal claim: a fixed, never-re-armed
	// cache whose lifetime sits between the fault window and the pause produces
	// this same observation.
	if steady < idle {
		return LapsedOnPause, append(
			reasons,
			sprintf(reasonLapsedOnPause, idle, steady, idle),
		)
	}

	return TTLExtension, append(
		reasons,
		sprintf(reasonTTLExtension, steady, idle),
	)
}

func baselineUnmet(
	baseline probe.Window,
	expect probe.Expectation,
	minted bool,
) (string, bool) {
	if paired := baseline.Paired(); paired < MinimumPaired {
		return sprintf(reasonThinBaseline, paired, MinimumPaired), true
	}

	if !baseline.Invalid.Any(probe.Rejected) {
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
	if baseline.Revoked.Countable() > 0 &&
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

	return sprintf(reasonNeverDelivered, observation.DeliveredWhat), true
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

// recoveryOf requires a run of consecutive healthy pairs, because a state
// transition declared on one lucky sample is how a flaky recovery reads as a
// clean one. An empty window is UNOBSERVED, never recovered.
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
