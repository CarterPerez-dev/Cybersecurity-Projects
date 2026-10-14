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
	// verifying anything.
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

// Shape is the part of an experiment that depends on the operator's parameters.
// Identity, polarity, fault kind and timing come from the declaration instead, so
// a builder cannot disagree with the catalogue about what it is.
type Shape struct {
	Condition string
	Target    string
	Probes    probe.Pair

	// The experiment owns the magnitude because the operator declares it as a
	// parameter, so the CLI never has to infer a fault from a kind.
	ProxyFault *proxy.Fault

	ProxyListen   string
	ProxyUpstream string

	// Built by the builder because its probes mint out of it.
	IdP     *idp.Provider
	IdPTrap *idp.Trap

	Authority *pki.Authority
	PKITrap   *pki.Trap

	DNSTrap         *dnsrv.Trap
	ResolverNetwork string
	DNSHost         string

	// AuthorityBase is the URL the TARGET reaches the CRL and OCSP endpoints by,
	// AuthorityListen where khaos binds them. They are separate because the
	// target addresses khaos by a name khaos cannot see from its own listener.
	AuthorityBase   string
	AuthorityListen string
	AuthorityTLS    string

	Defect     string
	HeldCaveat string

	// Consulted reads how many times the target has reached the faulted endpoint,
	// and ConsultedWhat names it; together they are the liveness guard for a fault
	// whose landing the probe streams cannot see.
	Consulted     func() (int64, error)
	ConsultedWhat string

	Unsupportable string
	CacheRequired string
	DeliveredWhat string

	// IdleFor asks the engine for the idleness discriminator.
	IdleFor time.Duration

	// Act is the change khaos makes at an authority once the target can no longer
	// reach it, and ActDetail is what the operator is told about it.
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
	Params     []Param
	Build      func(*Params) (Shape, error)
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
		IdP:           shape.IdP,
		IdPTrap:       shape.IdPTrap,

		Authority:       shape.Authority,
		PKITrap:         shape.PKITrap,
		AuthorityBase:   shape.AuthorityBase,
		AuthorityListen: shape.AuthorityListen,
		AuthorityTLS:    shape.AuthorityTLS,
		Defect:          shape.Defect,
		HeldCaveat:      shape.HeldCaveat,
		Consulted:       shape.Consulted,
		ConsultedWhat:   shape.ConsultedWhat,
		Unsupportable:   shape.Unsupportable,
		CacheRequired:   shape.CacheRequired,
		DeliveredWhat:   shape.DeliveredWhat,
		DNSTrap:         shape.DNSTrap,
		ResolverNetwork: shape.ResolverNetwork,
		DNSHost:         shape.DNSHost,
		IdleFor:         shape.IdleFor,
		Act:             shape.Act,
		ActDetail:       shape.ActDetail,
		Timing:          timing,
	}

	if shape.Condition != "" {
		spec.Hypothesis.Condition = shape.Condition
	}

	return spec, nil
}
