// ©AngelaMos | 2026
// experiment.go

package experiment

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/authz"
	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/inject"
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
// It is a set, not one direction: failing open is not universally a defect.
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
	Name          string
	Family        string
	Summary       string
	Hypothesis    Hypothesis
	Fault         Fault
	Polarity      Polarity
	Probes        probe.Pair
	Timing        Timing
	Configuration Configuration
	AbortAfter    int

	// A non-nil ProxyFault is what tells the run to stand a fault proxy up at all.
	ProxyFault *proxy.Fault

	ProxyListen   string
	ProxyUpstream string

	// What the confirmation probe says to the dependency. Empty keeps HTTP.
	ProxyProbe string

	IdP     *idp.Provider
	IdPTrap *idp.Trap

	Authority *pki.Authority
	PKITrap   *pki.Trap

	// A non-nil AuthzTrap is what tells the run to bind the authorization
	// dependency khaos plays.
	Authz       *authz.Dependency
	AuthzTrap   *authz.Trap
	AuthzListen string

	// AuthorityBase is the URL the TARGET reaches the revocation endpoints by,
	// which is pinned rather than derived from wherever khaos binds.
	AuthorityBase   string
	AuthorityListen string
	AuthorityTLS    string

	// No resolver object, only the fault and where to find one: an unprivileged
	// process cannot bind port 53, so it runs in a container on the target's
	// network and the run attaches a client to it by label.
	DNSTrap         *dnsrv.Trap
	ResolverNetwork string
	DNSHost         string

	// Cred is the one authority khaos does not replace, so the run opens a
	// client for a stock engine instead of standing a fake one up.
	Cred *CredSpec

	// Secret is a file inside the target, broken in place by a helper
	// container that mounts only the mount containing it.
	Secret *inject.SecretPlan

	// Env replaces the container, because a container's environment is fixed
	// at creation and the update endpoint silently ignores it.
	Env *inject.EnvPlan

	Defect string

	HeldCaveat string

	ClosedWhen []probe.Disposition

	// ColdStart restarts the target inside the fault window so it initialises
	// with the dependency already gone. The baseline precedes it deliberately:
	// a target that boots broken refuses nothing and voids its own run.
	ColdStart bool

	// The liveness guard for an experiment that faults an ENDPOINT rather than a
	// credential, where the probe streams cannot see whether the fault landed.
	Consulted     func() (int64, error)
	ConsultedWhat string

	// RotatedWhat names a zone rotation whose arrival khaos measures by whether
	// the target asked again at all.
	RotatedWhat string

	// Refusals is the count of definitive denials the dependency issued, which
	// only the credential under test is ever answered with.
	Refusals func() (int64, error)

	// Shift is the second fault phase. The one fault class that needs it is an
	// authorization dependency, whose deny and whose silence are different
	// answers that a defective caller reads as the same one.
	Shift       func(context.Context) error
	ShiftDetail string
	ShiftWhat   string

	// Nothing in a request count separates the two readings of a never-consulted
	// endpoint, so only an experiment declaring this treats silence as a finding.
	Unsupportable string

	CacheRequired string

	DeliveredWhat string
	Delivered     func() (int64, error)
	DeliveredHint string

	// IdleFor must exceed the target's own decision-cache lifetime, which khaos
	// cannot discover, so the experiment declares it.
	IdleFor time.Duration

	// Act is for the one thing fault injection cannot express: making a change at
	// an authority the target can no longer reach.
	Act       func(context.Context) error
	ActDetail string
}

type Result struct {
	Experiment string `json:"experiment"`
	Family     string `json:"family"`
	RunID      string `json:"run_id"`
	Hypothesis string `json:"hypothesis"`

	// Fault is carried on the RESULT rather than left on the spec, because
	// the record is the product: a record that cannot say what was injected
	// or where is not a record of the run.
	Fault Fault `json:"fault"`

	StartedAt     time.Time     `json:"started_at"`
	Duration      time.Duration `json:"duration"`
	Observation   Observation   `json:"observation"`
	Verdict       Verdict       `json:"verdict"`
	Configuration Configuration `json:"configuration"`
}

func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
