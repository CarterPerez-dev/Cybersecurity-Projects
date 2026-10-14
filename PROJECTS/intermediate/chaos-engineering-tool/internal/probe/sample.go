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

// AcceptedAfter counts only acceptances that follow a refusal, because an
// acceptance before the target ever refused anything is a warm-up. The caller
// seeds rejected from an earlier phase.
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
			// Not evidence either way, so neither the count nor the latch moves.
		}
	}

	return count
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
func (s Stream) AcceptedSinceLastRefusal() int {
	count := 0

	for _, outcome := range s.Outcomes {
		switch outcome.Disposition {
		case Rejected:
			count = 0
		case Accepted:
			count++
		default:
			// Neither extends nor breaks the run.
		}
	}

	return count
}

// AcceptedDespiteLapse counts acceptances a correct bounded cache cannot
// explain: all of them when the stream never lapsed, and only the ones
// following a refusal when it did.
func (s Stream) AcceptedDespiteLapse() int {
	if !s.Any(Rejected) {
		return s.Count(Accepted)
	}

	return s.AcceptedAfter(false)
}

// RejectedAfter is the mirror of AcceptedAfter, for the credential that should
// be honoured: a target that served from cache and then started refusing has
// stopped serving.
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
