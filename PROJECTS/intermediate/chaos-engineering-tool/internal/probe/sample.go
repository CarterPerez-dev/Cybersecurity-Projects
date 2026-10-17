// ©AngelaMos | 2026
// sample.go

package probe

import (
	"slices"
	"time"
)

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

// AcceptedAfter counts only acceptances that follow a refusal, because an
// acceptance before the target ever refused anything is a warm-up. The caller
// seeds rejected from an earlier phase.
//
// closed is what THIS control's failing closed looks like, and an empty set
// means Rejected alone. Every order-sensitive count below takes it for the same
// reason ClosedAfter does: a 503 is not a statement about a credential, but for
// a control that declared it, becoming unavailable IS the refusal, and a latch
// that only watches Rejected never trips against a target that answers 503.
func (s Stream) AcceptedAfter(rejected bool, closed ...Disposition) int {
	count := 0

	for _, outcome := range s.Outcomes {
		switch {
		case shut(outcome.Disposition, closed):
			rejected = true
		case outcome.Disposition == Accepted:
			if rejected {
				count++
			}
		default:
			// Not evidence either way, so neither the count nor the latch moves.
		}
	}

	return count
}

// shut reads the declared set, defaulting to Rejected so a caller that names
// nothing keeps the meaning it had before the set existed.
func shut(disposition Disposition, closed []Disposition) bool {
	if len(closed) == 0 {
		return disposition == Rejected
	}

	return slices.Contains(closed, disposition)
}

// AnyClosed reports whether the stream ever failed closed, by this control's
// own definition of closed.
func (s Stream) AnyClosed(closed ...Disposition) bool {
	for _, outcome := range s.Outcomes {
		if shut(outcome.Disposition, closed) {
			return true
		}
	}

	return false
}

func (s Stream) AcceptedAfterRejected() int {
	return s.AcceptedAfter(false)
}

// AcceptedSpan is a LOWER BOUND and never a cache lifetime, because khaos
// stopped looking when the window ended.
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

// AcceptedSinceLastRefusal is the trailing run of acceptances, so a bounded
// cache that lapses and stays lapsed scores zero.
func (s Stream) AcceptedSinceLastRefusal(closed ...Disposition) int {
	count := 0

	for _, outcome := range s.Outcomes {
		switch {
		case shut(outcome.Disposition, closed):
			count = 0
		case outcome.Disposition == Accepted:
			count++
		default:
			// Neither extends nor breaks the run.
		}
	}

	return count
}

// AcceptedSpanSinceLastRefusal is the span of THAT run and not of every
// acceptance in the window, because the two describe different sets the moment
// a window contains a refusal in the middle: the count is order-sensitive and a
// first-to-last span is not, so quoting them in one sentence states an exposure
// over a period the target spent refusing.
func (s Stream) AcceptedSpanSinceLastRefusal(
	closed ...Disposition,
) time.Duration {
	var first, last time.Time

	for _, outcome := range s.Outcomes {
		switch {
		case shut(outcome.Disposition, closed):
			first, last = time.Time{}, time.Time{}
		case outcome.Disposition == Accepted:
			if first.IsZero() {
				first = outcome.At
			}
			last = outcome.At
		default:
			// Neither extends nor breaks the run.
		}
	}

	if first.IsZero() {
		return 0
	}

	return last.Sub(first)
}

// AcceptedDespiteLapse counts acceptances a correct bounded cache cannot
// explain: all of them when the stream never lapsed, and only the ones
// following a refusal when it did.
func (s Stream) AcceptedDespiteLapse(closed ...Disposition) int {
	if !s.AnyClosed(closed...) {
		return s.Count(Accepted)
	}

	return s.AcceptedAfter(false, closed...)
}

// RejectedAfter is the mirror of AcceptedAfter, for the credential that should
// be honoured: a target that served from cache and then started refusing has
// stopped serving.
func (s Stream) RejectedAfter(accepted bool) int {
	return s.ClosedAfter(accepted, Rejected)
}

// ClosedAfter is RejectedAfter over a DECLARED set of dispositions, because
// what counts as failing closed is a property of the control rather than of
// the protocol. A 503 is not a statement about a credential, so it is never
// Rejected - but for a service whose database access was revoked, becoming
// unavailable IS the fail-closed outcome, and reading it as "kept serving"
// would report the correct behaviour as the defect.
func (s Stream) ClosedAfter(accepted bool, closed ...Disposition) int {
	count := 0

	for _, outcome := range s.Outcomes {
		switch {
		case outcome.Disposition == Accepted:
			accepted = true
		case slices.Contains(closed, outcome.Disposition):
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

// Paired is the number of samples where both halves of the pair exist.
func (w Window) Paired() int {
	return min(w.Valid.Countable(), w.Invalid.Countable())
}

func (w Window) Len() int {
	return w.Paired()
}

// Requests is the denominator for a per-REQUEST ratio, and Paired is not: one
// paired sample is at least two requests.
func (w Window) Requests() int {
	return w.Valid.Countable() +
		w.Invalid.Countable() +
		w.Revoked.Countable() +
		w.Forged.Countable()
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
