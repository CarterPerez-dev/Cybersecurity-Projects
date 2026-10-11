// ©AngelaMos | 2026
// sample.go

package probe

import "time"

type Stream struct {
	Credential Credential `json:"credential"`
	Outcomes   []Outcome  `json:"outcomes"`
}

func (s Stream) Count(d Disposition) int {
	n := 0
	for _, outcome := range s.Outcomes {
		if outcome.Disposition == d {
			n++
		}
	}
	return n
}

func (s Stream) Len() int {
	return len(s.Outcomes)
}

func (s Stream) Countable() int {
	n := 0
	for _, outcome := range s.Outcomes {
		if outcome.Disposition.Countable() {
			n++
		}
	}
	return n
}

func (s Stream) Any(d Disposition) bool {
	return s.Count(d) > 0
}

func (s Stream) Answered() int {
	n := 0
	for _, outcome := range s.Outcomes {
		if outcome.Disposition.Answered() {
			n++
		}
	}
	return n
}

func (s Stream) Distribution() map[Disposition]int {
	out := make(map[Disposition]int, len(s.Outcomes))
	for _, outcome := range s.Outcomes {
		out[outcome.Disposition]++
	}
	return out
}

// AcceptedAfter is the monotonicity test for a control that stopped enforcing.
// A plain "anything was accepted" check is wrong twice over: a service that
// keeps serving a still-valid credential during an outage is behaving
// correctly, and an acceptance that happened before the target ever rejected
// anything is a warm-up, not a control giving way. The caller seeds `rejected`
// from an earlier phase so a baseline blip cannot be counted as a fault-phase
// leak.
func (s Stream) AcceptedAfter(rejected bool) int {
	count := 0

	for _, outcome := range s.Outcomes {
		switch outcome.Disposition {
		case Rejected:
			rejected = true
		case Accepted:
			if rejected {
				count++
			}
		default:
			// A probe that neither answered nor refused is not evidence in
			// either direction, so it must not move the count OR the latch. An
			// outage counted as a refusal would manufacture the control giving
			// way that this function exists to detect.
		}
	}

	return count
}

func (s Stream) AcceptedAfterRejected() int {
	return s.AcceptedAfter(false)
}

// AcceptedSinceLastRefusal counts acceptances that were never followed by a
// refusal, which is the order-sensitive test for a credential khaos invalidated
// at an authority.
//
// Counting every acceptance in the window is wrong, and wrong in the direction
// that manufactures findings. A target with a correct BOUNDED cache serves the
// invalidated credential for exactly as long as its cache lifetime and then
// refuses it forever: accept, accept, refuse, refuse, refuse. That is the
// defensible bounded-stale pattern, and a plain count reports it as a bypass.
//
// The two shapes separate completely on this test. A bounded cache lapses and
// scores zero; a cache that is being re-armed, or that has no expiry, never
// lapses and scores every acceptance. A target that refuses and then accepts
// again also scores, which is correct: re-populating a decision for a credential
// it has already refused is its own bug.
//
// This is the exact mirror of RejectedAfter, which exists because the same
// fixture served a valid credential from cache for the first seconds of an
// outage and "was it ever accepted" reported that as a clean survival.
// AcceptedSpan is the time from the first acceptance in this stream to the last.
//
// For a credential khaos invalidated it is research 07 section 2.2's
// `stale_accept_window`, which that table calls "the real exposure window of a
// leaked key". It is a LOWER BOUND and never a cache lifetime: khaos stopped
// looking when the window ended, so the true span can only be longer.
func (s Stream) AcceptedSpan() time.Duration {
	var first, last time.Time

	for _, outcome := range s.Outcomes {
		if outcome.Disposition != Accepted {
			continue
		}
		if first.IsZero() {
			first = outcome.At
		}
		last = outcome.At
	}

	if first.IsZero() {
		return 0
	}

	return last.Sub(first)
}

func (s Stream) AcceptedSinceLastRefusal() int {
	count := 0

	for _, outcome := range s.Outcomes {
		switch outcome.Disposition {
		case Rejected:
			count = 0
		case Accepted:
			count++
		default:
			// Neither an acceptance nor a refusal, so the run is neither
			// extended nor broken by it.
		}
	}

	return count
}

// AcceptedDespiteLapse counts acceptances that a correct bounded cache cannot
// explain: every acceptance when the stream never lapsed at all, and only the
// acceptances that FOLLOW a refusal when it did.
//
// AcceptedSinceLastRefusal gets the first case right and silently destroys the
// second. It keeps only the trailing run, so `Rejected, Accepted, Rejected`
// scores zero — the target refused the invalidated credential, honoured it
// again, and then refused it once more, and khaos forgot the middle. That
// sequence is reachable across inconsistent verifier replicas, and it is a
// worse finding than the one this function exists to report: enforcement had
// already resumed and the credential got through anyway.
//
// The two cases are different claims and both are kept:
//
//	A A A A    never lapsed          -> 4, the cache is not bounded by anything observed
//	A A R R R  lapsed and stayed     -> 0, the defensible bounded-stale pattern
//	R A R      came back after a lapse -> 1, enforcement resumed and was then bypassed
func (s Stream) AcceptedDespiteLapse() int {
	if !s.Any(Rejected) {
		return s.Count(Accepted)
	}

	return s.AcceptedAfter(false)
}

// RejectedAfter is the mirror of AcceptedAfter, for the credential that should
// be honoured. A target that served from a cache for the first seconds of an
// outage and then started refusing has stopped serving, and asking only
// whether it ever served reports that as a clean survival.
func (s Stream) RejectedAfter(accepted bool) int {
	count := 0

	for _, outcome := range s.Outcomes {
		switch outcome.Disposition {
		case Accepted:
			accepted = true
		case Rejected:
			if accepted {
				count++
			}
		default:
			// Not evidence either way, so neither the count nor the latch moves.
		}
	}

	return count
}

type Window struct {
	Valid   Stream `json:"valid"`
	Invalid Stream `json:"invalid"`
	Revoked Stream `json:"revoked,omitempty"`
	Forged  Stream `json:"forged,omitempty"`
}

// Paired is the number of samples where both halves of the pair exist, which
// is what a comparative verdict can actually be built from.
func (w Window) Paired() int {
	return min(w.Valid.Countable(), w.Invalid.Countable())
}

func (w Window) Len() int {
	return w.Paired()
}

func (w *Window) Record(outcome Outcome) {
	switch outcome.Credential {
	case Invalid:
		w.Invalid.Credential = Invalid
		w.Invalid.Outcomes = append(w.Invalid.Outcomes, outcome)
	case Revoked:
		w.Revoked.Credential = Revoked
		w.Revoked.Outcomes = append(w.Revoked.Outcomes, outcome)
	case Forged:
		w.Forged.Credential = Forged
		w.Forged.Outcomes = append(w.Forged.Outcomes, outcome)
	default:
		w.Valid.Credential = Valid
		w.Valid.Outcomes = append(w.Valid.Outcomes, outcome)
	}
}
