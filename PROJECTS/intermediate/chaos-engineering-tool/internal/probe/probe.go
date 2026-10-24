// ©AngelaMos | 2026
// probe.go

package probe

import (
	"context"
	"time"
)

type Disposition string

const (
	// Unknown is the zero value on purpose, so a half-built Outcome reads as
	// wrong rather than as a target failure.
	Unknown Disposition = "unknown"

	Accepted   Disposition = "accepted"
	Rejected   Disposition = "rejected"
	Redirected Disposition = "redirected"
	Throttled  Disposition = "throttled"

	// Unavailable is the target ANSWERING that it cannot serve: a 5xx with a
	// status line. Unreachable is the target not answering at all. They were
	// one value, and the conflation made a control's declared fail-closed
	// outcome cover a target that had DIED: four experiments declare a 503 as
	// their refusal, so a crashed target read as one that failed closed, with a
	// reason saying the valid credential "stopped being accepted". Keeping them
	// apart is what lets a declaration name one without the other.
	Unavailable Disposition = "unavailable"
	Unreachable Disposition = "unreachable"

	TimedOut Disposition = "timed-out"

	// ProbeFailed is khaos's own fault and is excluded from every rate.
	ProbeFailed Disposition = "probe-failed"
)

func (d Disposition) String() string {
	if d == "" {
		return string(Unknown)
	}
	return string(d)
}

// Answered reports whether the target responded at all, whatever it said.
func (d Disposition) Answered() bool {
	switch d {
	case Accepted, Rejected, Redirected, Throttled:
		return true
	default:
		return false
	}
}

// Countable excludes khaos's own failures from every rate computation.
func (d Disposition) Countable() bool {
	return d != ProbeFailed && d != Unknown
}

type Credential string

const (
	Valid   Credential = "valid"
	Invalid Credential = "invalid"

	// Revoked was legitimately accepted and then revoked at the authority,
	// which is a different claim from never having been acceptable.
	Revoked Credential = "revoked"

	// Forged was minted to be wrong in exactly one named way. Its baseline
	// depends on the trap, so it cannot be folded into Invalid.
	Forged Credential = "forged"
)

// Expectation is what a stream must do during the baseline for the fault window
// to mean anything. It is declared per experiment rather than derived, because
// it points in opposite directions for traps that look alike.
type Expectation string

const (
	// ExpectAccepted: a target that never accepted was not trusting khaos.
	ExpectAccepted Expectation = "accepted"

	// ExpectRejected: a target that never refused was not checking.
	ExpectRejected Expectation = "rejected"
)

func (c Credential) String() string {
	return string(c)
}

type Outcome struct {
	At          time.Time   `json:"at"`
	Credential  Credential  `json:"credential"`
	Disposition Disposition `json:"disposition"`
	Status      int         `json:"status,omitempty"`
	LatencyMS   int64       `json:"latency_ms"`
	Detail      string      `json:"detail,omitempty"`
}

func (o *Outcome) SetLatency(d time.Duration) {
	o.LatencyMS = d.Milliseconds()
}

type Probe interface {
	Name() string
	Describe() string
	Credential() Credential
	Run(context.Context) Outcome
}

// Pair is the valid probe and its negative control; Revoked and Forged are
// optional.
type Pair struct {
	Valid   Probe
	Invalid Probe
	Revoked Probe
	Forged  Probe

	ForgedBaseline Expectation
}

func (p Pair) Complete() bool {
	return p.Valid != nil && p.Invalid != nil
}

// All returns the probes to fire, in a stable order.
func (p Pair) All() []Probe {
	probes := []Probe{p.Valid, p.Invalid}
	if p.Revoked != nil {
		probes = append(probes, p.Revoked)
	}
	if p.Forged != nil {
		probes = append(probes, p.Forged)
	}
	return probes
}
