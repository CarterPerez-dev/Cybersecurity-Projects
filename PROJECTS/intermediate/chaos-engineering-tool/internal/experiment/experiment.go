// ©AngelaMos | 2026
// experiment.go

package experiment

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/inject/proxy"
	"github.com/CarterPerez-dev/khaos/internal/pki"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	hypothesisTemplate = "In the event of %s, we are confident that our system will respond with %s."

	DefaultSampleInterval = 500 * time.Millisecond
	DefaultBaselineFor    = 5 * time.Second
	// Long enough to clear MinimumToClaimClosed at the default sample interval.
	DefaultFaultFor    = 20 * time.Second
	DefaultRecoveryFor = 5 * time.Second
)

// Polarity declares which directions of breakage are defects for this control.
// It is a set, not one direction: failing open is not universally a defect, so
// each control declares its own.
type Polarity struct {
	Defects   []Direction
	Rationale string
}

func (p Polarity) IsDefect(direction Direction) bool {
	return slices.Contains(p.Defects, direction)
}

// Declared is the directions this control treats as a defect, for display.
func (p Polarity) Declared() string {
	out := make([]string, 0, len(p.Defects))
	for _, direction := range p.Defects {
		out = append(out, string(direction))
	}
	return strings.Join(out, " or ")
}

func (p Polarity) Explain(direction Direction) string {
	if p.IsDefect(direction) {
		return sprintf(reasonDefect, direction)
	}
	return sprintf(reasonNotDefect, direction)
}

type Hypothesis struct {
	Condition string
	Response  string
}

func (h Hypothesis) String() string {
	return fmt.Sprintf(hypothesisTemplate, h.Condition, h.Response)
}

type Fault struct {
	Kind   string
	Target string
}

type Timing struct {
	SampleInterval time.Duration
	BaselineFor    time.Duration
	FaultFor       time.Duration
	RecoveryFor    time.Duration
}

func (t Timing) withDefaults() Timing {
	if t.SampleInterval <= 0 {
		t.SampleInterval = DefaultSampleInterval
	}
	if t.BaselineFor <= 0 {
		t.BaselineFor = DefaultBaselineFor
	}
	if t.FaultFor <= 0 {
		t.FaultFor = DefaultFaultFor
	}
	if t.RecoveryFor <= 0 {
		t.RecoveryFor = DefaultRecoveryFor
	}
	return t
}

type Experiment struct {
	Name       string
	Family     string
	Summary    string
	Hypothesis Hypothesis
	Fault      Fault
	Polarity   Polarity
	Probes     probe.Pair
	Timing     Timing

	// A non-nil ProxyFault is what tells the run to stand a fault proxy up at all.
	ProxyFault *proxy.Fault

	// ProxyListen is where the run binds the proxy, ProxyUpstream what it
	// forwards to.
	ProxyListen   string
	ProxyUpstream string

	// The provider is built by the catalogue rather than the run, because the
	// probes mint credentials out of it and minting needs no listener.
	IdP     *idp.Provider
	IdPTrap *idp.Trap

	// AuthorityBase is the URL the TARGET reaches the revocation endpoints by,
	// which is pinned rather than derived from wherever khaos binds.
	Authority       *pki.Authority
	PKITrap         *pki.Trap
	AuthorityBase   string
	AuthorityListen string
	AuthorityTLS    string

	// There is no resolver object here, only the fault and where to find one: an
	// unprivileged process cannot bind port 53, so the resolver runs in a
	// container on the target's network and the run attaches a client to it by
	// label. DNSHost is the name under fault.
	DNSTrap         *dnsrv.Trap
	ResolverNetwork string
	DNSHost         string

	// Defect names what khaos did to the credential, in words, for the verdict.
	Defect string

	// HeldCaveat qualifies a HELD verdict where the absence of a finding covers
	// less than it appears to.
	HeldCaveat string

	// Consulted and ConsultedWhat are the liveness guard for an experiment that
	// faults an ENDPOINT rather than a credential, where the probe streams cannot
	// see whether the fault ever landed.
	Consulted     func() (int64, error)
	ConsultedWhat string

	// Unsupportable names the check whose ABSENCE is itself the finding, which
	// turns a never-consulted endpoint into UNSUPPORTED instead of a void run.
	// Nothing in a request count distinguishes the two readings, so only an
	// experiment that declares this gets the second one: no mainstream TLS stack
	// checks revocation by default and Go's does not check it at all, so a target
	// that never asked has no revocation check that could have failed.
	Unsupportable string

	// CacheRequired names the behaviour this experiment can only measure in a
	// target that caches, which turns a target re-resolving per request into
	// UNSUPPORTED rather than a clean survival.
	CacheRequired string

	// DeliveredWhat names what the target would have had to DO for the fault to
	// reach it, which turns an armed-and-confirmed fault the target never met
	// into an aborted run rather than a clean survival.
	DeliveredWhat string

	// IdleFor must exceed the target's own decision-cache lifetime, which khaos
	// cannot discover, so the experiment declares it.
	IdleFor time.Duration

	// Act runs once, after the fault is confirmed and before anything is measured
	// under it, for the one thing fault injection cannot express: making a change
	// at an authority the target can no longer reach.
	Act       func(context.Context) error
	ActDetail string
}

type Result struct {
	Experiment  string        `json:"experiment"`
	RunID       string        `json:"run_id"`
	Hypothesis  string        `json:"hypothesis"`
	StartedAt   time.Time     `json:"started_at"`
	Duration    time.Duration `json:"duration"`
	Observation Observation   `json:"observation"`
	Verdict     Verdict       `json:"verdict"`
}

func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
