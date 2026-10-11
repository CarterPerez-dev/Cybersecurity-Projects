// ©AngelaMos | 2026
// experiment.go

package experiment

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/inject/proxy"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	hypothesisTemplate = "In the event of %s, we are confident that our system will respond with %s."

	DefaultSampleInterval = 500 * time.Millisecond
	DefaultBaselineFor    = 5 * time.Second
	// Long enough to clear MinimumToClaimClosed at the default sample interval,
	// with room for the jitter. At ten seconds a healthy target produced about
	// twenty paired samples against a threshold of thirty, so every default run
	// carried `Conclusive=false` and a thin-evidence warning — and exited 0
	// anyway. Raising the window is the honest lever: it buys confidence with
	// time rather than by probing the target harder.
	DefaultFaultFor    = 20 * time.Second
	DefaultRecoveryFor = 5 * time.Second
)

// Polarity declares which way breaking is a defect for the control under test.
// Failing open is not universally a defect: an authentication check that stops
// enforcing is catastrophic, while a rate-limit counter that stops counting
// when its datastore is unreachable is a trade plenty of teams make on purpose.
// Defects is a SET, not one direction, and the single-direction version was a
// live bug. `identity.key_rotation` declares DENIED its defect, so PERMITTED
// fell to the else branch and khaos printed "this experiment declares PERMITTED
// to be acceptable for this control" — which nobody declared, and which is not
// true of any control khaos ships. The run then exited 0, because the exit code
// keys off Defect alone, so a target that failed wide open passed a CI build.
//
// The axis still means what the design contract says: failing open is not
// universally a defect, and a rate limiter that stops counting when its
// datastore is unreachable is a trade teams make on purpose. That is why this is
// a declared set rather than a hardcoded rule.
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

	// ProxyFault is non-nil only for an experiment that injects through khaos's
	// own fault proxy, and it is what tells the run to stand one up at all.
	ProxyFault *proxy.Fault

	// ProxyListen is the host address the run binds the proxy on, and
	// ProxyUpstream is the dependency it forwards to.
	ProxyListen   string
	ProxyUpstream string

	// IdP and IdPTrap are non-nil only for an experiment that arms khaos's own
	// identity provider. The provider is BUILT here rather than by the run,
	// because the probes have to mint credentials out of it and minting needs no
	// listener: the run only has to bind it where the target is already looking.
	IdP     *idp.Provider
	IdPTrap *idp.Trap

	// Defect names what khaos did to the credential the finding is about, in
	// words, so the verdict can state the actual observation rather than a
	// constant that is only true of one experiment.
	Defect string

	// HeldCaveat qualifies a HELD verdict where the absence of a finding covers
	// less than it appears to.
	HeldCaveat string

	// Consulted and ConsultedWhat are the liveness guard for the experiments
	// that fault an ENDPOINT rather than a credential.
	//
	// Three of them break khaos's introspection endpoint, and their only
	// enforcement evidence was that the invalid control got refused. A target
	// doing purely local JWT validation refuses a non-JWT bearer token itself
	// and never calls introspection at all, so the baseline passed, the trap
	// confirmed at khaos's own provider, and the fault window looked exactly
	// like the baseline: `passed / HELD`, conclusive, over a fault the target
	// never experienced.
	//
	// khaos already had the instrument and was not using it. Research 07's
	// requirement R5 names a fetch counter as a thing no third-party provider
	// will give you, and khaos built one and then read it nowhere.
	Consulted     func() int64
	ConsultedWhat string

	// Unsupportable names the check whose ABSENCE is a finding in its own
	// right, and turns a never-consulted endpoint into UNSUPPORTED instead of
	// BASELINE-NOT-MET.
	//
	// The two readings of "the target never touched the endpoint" are opposite
	// and both are sometimes right. For the introspection experiments it means
	// khaos faulted something the target does not use, so the run is void and
	// baseline-not-met is honest. For the revocation experiments it is THE
	// ANSWER: no mainstream TLS stack checks revocation by default, Go's does
	// not check it at all, and a target that never asked has no revocation
	// check that could have failed.
	//
	// Only an experiment that declares this gets the second reading, because
	// nothing in a request count distinguishes the two situations.
	Unsupportable string

	// IdleFor turns on the idleness discriminator. It must be longer than the
	// target's own decision-cache lifetime, which khaos cannot discover, so the
	// experiment declares it as a parameter and the verdict names the pause it
	// actually used.
	IdleFor time.Duration

	// Act runs once, after the fault is confirmed and before anything is measured
	// under it. It exists for the one thing no amount of fault injection can
	// express: making a change at an authority the target can no longer reach.
	// ActDetail is what the operator is told khaos is about to do.
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
