// ©AngelaMos | 2026
// probe.go

package probe

import (
	"context"
	"time"
)

type Disposition string

const (
	// Unknown is the zero value on purpose: a half-built Outcome must read as
	// obviously wrong rather than as a plausible target failure.
	Unknown Disposition = "unknown"

	Accepted    Disposition = "accepted"
	Rejected    Disposition = "rejected"
	Redirected  Disposition = "redirected"
	Throttled   Disposition = "throttled"
	Unavailable Disposition = "unavailable"
	TimedOut    Disposition = "timed-out"

	// ProbeFailed is khaos's own fault, never the target's. It is excluded from
	// every rate, because folding a tool bug into a target outcome manufactures
	// findings out of a typo in --url.
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

	// Revoked is a credential that was LEGITIMATELY accepted and that khaos then
	// revoked at the authority during the fault. It is a third kind rather than a
	// flavour of Invalid because the two make different claims: an invalid
	// credential was never acceptable, and a revoked one was and then stopped
	// being. Reporting the second as the first would say the target honoured
	// something it had already rejected, which is not what happened.
	Revoked Credential = "revoked"

	// Forged is a credential khaos MINTED to be wrong in exactly one named way,
	// and confirmed wrong at the provider before presenting it. It is a fourth
	// kind rather than a flavour of Invalid because the claims differ again, and
	// because the baseline requirement is different: the invalid stream has to be
	// REJECTED during the baseline to prove the target enforces anything at all,
	// while a forged stream's baseline requirement depends on the trap and is
	// declared by the experiment.
	//
	// Folding it into Invalid also breaks the run outright for the traps whose
	// forged credential is accepted at steady state: the baseline check would
	// report "the invalid credential was never rejected" and void the run, which
	// is khaos refusing to report the very finding it went looking for.
	Forged Credential = "forged"
)

// Expectation is what a stream must do during the baseline for the fault window
// to mean anything. It is DECLARED per experiment rather than derived, because
// it points in opposite directions for traps that look alike: a token forged to
// be malformed has to be refused before the fault, and a token that is correct
// until the provider is armed has to be ACCEPTED before it.
type Expectation string

const (
	// ExpectAccepted is the liveness guard for a trap whose credential is
	// honest until the fault lands. If the target never accepted one, it was not
	// trusting khaos's provider and its later refusals say nothing.
	ExpectAccepted Expectation = "accepted"

	// ExpectRejected is the enforcement guard for a trap whose credential is
	// already malformed. If the target never refused one, it was not checking
	// the thing the fault is about to break.
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

// Pair is the valid probe and its negative control. Revoked and Forged are
// optional, and only the experiments that revoke or forge a credential set them;
// the two-stream verdict logic is untouched when both are nil.
type Pair struct {
	Valid   Probe
	Invalid Probe
	Revoked Probe
	Forged  Probe

	// ForgedBaseline is what the forged stream must do before the fault. It is
	// meaningless without Forged and the verdict ignores it then.
	ForgedBaseline Expectation
}

func (p Pair) Complete() bool {
	return p.Valid != nil && p.Invalid != nil
}

// All returns the probes to fire, in a stable order so a sampling pass produces
// comparable streams.
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
