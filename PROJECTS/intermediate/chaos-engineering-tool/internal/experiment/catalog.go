// ©AngelaMos | 2026
// catalog.go

package experiment

import (
	"context"
	"errors"
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
	FamilyNetwork = "network"

	NameDependencyOutage = "network.dependency_outage"

	// Not a signed token in any format, so a target that honours it is not
	// verifying anything at all.
	DefaultInvalidToken = "khaos.invalid.credential.not.a.signed.token"

	probeValidName   = "valid-credential"
	probeInvalidName = "invalid-credential"
	probeRevokedName = "revoked-credential"

	nameSep    = ", "
	errUnknown = "%w: %q (known experiments: %s)"
	errStray   = "%w: %s reads %s, which it does not declare; declare them in its Params or stop reading them"
)

var ErrUnknownExperiment = errors.New(
	"no experiment is registered under that name",
)

var ErrStrayParam = errors.New(
	"an experiment read a parameter it never declared",
)

// Shape is the part of an experiment that depends on the operator's parameters;
// identity, polarity, fault kind and timing come from the declaration instead.
type Shape struct {
	Condition string
	Target    string
	Probes    probe.Pair

	ProxyFault *proxy.Fault

	ProxyListen   string
	ProxyUpstream string

	// What the confirmation probe says to the dependency. Empty keeps the
	// HTTP request; a dependency that does not speak HTTP answers one with
	// nothing, which the oracle correctly reads as unreachable.
	ProxyProbe string

	IdP     *idp.Provider
	IdPTrap *idp.Trap

	Authority *pki.Authority
	PKITrap   *pki.Trap

	// The dependency khaos plays so one can answer a definitive deny. The
	// listen address is the one the target's own authorization check already
	// calls, so it is given rather than chosen.
	Authz       *authz.Dependency
	AuthzTrap   *authz.Trap
	AuthzListen string

	DNSTrap         *dnsrv.Trap
	ResolverNetwork string
	DNSHost         string

	// Grouped rather than spread: this tier needs seven inputs and Shape
	// already carries one field per tier.
	Cred *CredSpec

	// The secret tier's plan. The MOUNT is filled by the run, which is the
	// only place that has the target's own inspection.
	Secret *inject.SecretPlan

	// The environment tier's plan, which is the only fault class that replaces
	// the container.
	Env *inject.EnvPlan

	// Separate fields because the target addresses khaos by a name khaos cannot
	// see from its own listener, so neither can be derived from the other.
	AuthorityBase   string
	AuthorityListen string
	AuthorityTLS    string

	Defect string

	HeldCaveat string

	ClosedWhen []probe.Disposition

	// RotatedWhat names a zone rotation, and it is the one observable read as a
	// finding when it is ZERO: a target that never asked again never saw the
	// rotation, which is a revocation that did not take effect.
	RotatedWhat string

	// The liveness guard for a fault whose landing the probe streams cannot see.
	Consulted     func() (int64, error)
	ConsultedWhat string

	// Refusals counts the definitive denials the faulted dependency issued, for
	// the retry storm: a caller presenting a credential that has already been
	// refused once per request asks about it once per request.
	Refusals func() (int64, error)

	// Shift changes what the faulted dependency ANSWERS, between two fault
	// windows on the same run, so the two can be compared.
	Shift       func(context.Context) error
	ShiftDetail string
	ShiftWhat   string

	// ColdStart restarts the target inside the fault window, so it
	// INITIALISES with the dependency already unreachable. The baseline has
	// to precede it: a target that boots broken refuses nothing, so khaos's
	// own guard would void the run rather than measure one.
	ColdStart bool

	Unsupportable string
	CacheRequired string
	DeliveredWhat string
	DeliveredHint string

	IdleFor time.Duration

	// Act is the change khaos makes at an authority once the target can no longer
	// reach it.
	Act       func(context.Context) error
	ActDetail string
}

type Definition struct {
	Name       string
	Family     string
	Summary    string
	Hypothesis Hypothesis
	Polarity   Polarity
	FaultKind  string

	// Control is which of a gateway's controls this experiment severs, for
	// the family whose four members share one mechanism and one gateway and
	// differ only in the dependency they take away.
	Control ControlSubject

	Params []Param
	Build  func(*Params) (Shape, error)
}

const (
	outageSummary   = "take a dependency away and see whether the control in front of it fails closed or fails open"
	outageResponse  = "refusing credentials it would have refused anyway, rather than letting them through"
	outageCondition = "%s becoming unreachable"
	outageGeneric   = "a dependency of the target becoming unreachable"

	usageTarget       = "the consenting container whose outage you want to survive"
	usageURL          = "the endpoint khaos probes to see how the target behaves"
	usageToken        = "a credential the target should accept"
	usageInvalidToken = "a credential the target should refuse; this is the negative control"
)

var outagePolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "a control that stops rejecting invalid credentials when its dependency is down has stopped being a control",
}

var outageParams = []Param{
	{Name: ParamTarget, Usage: usageTarget, Required: true},
	{Name: ParamURL, Usage: usageURL, Required: true},
	{Name: ParamToken, Usage: usageToken, Required: true},
	{
		Name:    ParamInvalidToken,
		Usage:   usageInvalidToken,
		Default: DefaultInvalidToken,
	},
}

func probePair(params *Params) probe.Pair {
	url := params.Get(ParamURL)

	return probe.Pair{
		Valid: probe.NewHTTP(probe.HTTPOptions{
			Name:       probeValidName,
			URL:        url,
			Token:      params.Get(ParamToken),
			Credential: probe.Valid,
		}),
		Invalid: probe.NewHTTP(probe.HTTPOptions{
			Name:       probeInvalidName,
			URL:        url,
			Token:      params.Get(ParamInvalidToken),
			Credential: probe.Invalid,
			Unique:     true,
		}),
	}
}

func buildDependencyOutage(params *Params) (Shape, error) {
	target := params.Get(ParamTarget)

	return Shape{
		Condition: fmt.Sprintf(outageCondition, target),
		Target:    target,
		Probes:    probePair(params),
	}, nil
}

var catalog = map[string]Definition{
	NameDependencyOutage: {
		Name:    NameDependencyOutage,
		Family:  FamilyNetwork,
		Summary: outageSummary,
		Hypothesis: Hypothesis{
			Condition: outageGeneric,
			Response:  outageResponse,
		},
		Polarity:  outagePolarity,
		FaultKind: inject.KindPause,
		Params:    outageParams,
		Build:     buildDependencyOutage,
	},
}

// catalogAdd is how a family registers from its own init, which keeps every
// family's definitions in the file that explains them.
func catalogAdd(definition Definition) {
	catalog[definition.Name] = definition
}

func Names() []string {
	names := make([]string, 0, len(catalog))
	for name := range catalog {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func Catalog() []Definition {
	out := make([]Definition, 0, len(catalog))
	for _, name := range Names() {
		out = append(out, catalog[name])
	}
	return out
}

func Lookup(name string) (Definition, error) {
	definition, ok := catalog[name]
	if !ok {
		return Definition{}, fmt.Errorf(
			errUnknown,
			ErrUnknownExperiment,
			name,
			strings.Join(Names(), nameSep),
		)
	}
	return definition, nil
}

func Build(
	name string,
	supplied map[string]string,
	timing Timing,
) (Experiment, error) {
	definition, err := Lookup(name)
	if err != nil {
		return Experiment{}, err
	}

	params, err := Bind(definition.Params, supplied)
	if err != nil {
		return Experiment{}, err
	}

	shape, err := definition.Build(params)
	if err != nil {
		return Experiment{}, err
	}

	if stray := params.strayReads(); len(stray) > 0 {
		return Experiment{}, fmt.Errorf(
			errStray,
			ErrStrayParam,
			name,
			strings.Join(stray, nameSep),
		)
	}

	spec := Experiment{
		Name:          definition.Name,
		Family:        definition.Family,
		Summary:       definition.Summary,
		Hypothesis:    definition.Hypothesis,
		Polarity:      definition.Polarity,
		Fault:         Fault{Kind: definition.FaultKind, Target: shape.Target},
		Probes:        shape.Probes,
		ProxyFault:    shape.ProxyFault,
		ProxyListen:   shape.ProxyListen,
		ProxyUpstream: shape.ProxyUpstream,
		ProxyProbe:    shape.ProxyProbe,
		IdP:           shape.IdP,
		IdPTrap:       shape.IdPTrap,

		Authority:       shape.Authority,
		PKITrap:         shape.PKITrap,
		Authz:           shape.Authz,
		AuthzTrap:       shape.AuthzTrap,
		AuthzListen:     shape.AuthzListen,
		Refusals:        shape.Refusals,
		Shift:           shape.Shift,
		ShiftDetail:     shape.ShiftDetail,
		ShiftWhat:       shape.ShiftWhat,
		ColdStart:       shape.ColdStart,
		AuthorityBase:   shape.AuthorityBase,
		AuthorityListen: shape.AuthorityListen,
		AuthorityTLS:    shape.AuthorityTLS,
		Defect:          shape.Defect,
		HeldCaveat:      shape.HeldCaveat,
		ClosedWhen:      shape.ClosedWhen,
		Consulted:       shape.Consulted,
		ConsultedWhat:   shape.ConsultedWhat,
		Unsupportable:   shape.Unsupportable,
		CacheRequired:   shape.CacheRequired,
		DeliveredWhat:   shape.DeliveredWhat,
		DeliveredHint:   shape.DeliveredHint,
		RotatedWhat:     shape.RotatedWhat,
		DNSTrap:         shape.DNSTrap,
		ResolverNetwork: shape.ResolverNetwork,
		DNSHost:         shape.DNSHost,
		Cred:            shape.Cred,
		Secret:          shape.Secret,
		Env:             shape.Env,
		IdleFor:         shape.IdleFor,
		Act:             shape.Act,
		ActDetail:       shape.ActDetail,
		Timing:          timing,
		Configuration:   configuration(name, params, timing),
	}

	if shape.Condition != "" {
		spec.Hypothesis.Condition = shape.Condition
	}

	return spec, nil
}
