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

	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/inject/proxy"
	"github.com/CarterPerez-dev/khaos/internal/pki"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	FamilyNetwork = "network"

	NameDependencyOutage = "network.dependency_outage"

	// A credential no correct verifier can accept: it is not a signed token in
	// any format, so a target that honours it is not verifying anything.
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
// Identity, polarity, fault kind and timing all come from the declaration, so a
// builder cannot disagree with the catalogue about what it is or forget to carry
// something universal through.
type Shape struct {
	Condition string
	Target    string
	Probes    probe.Pair

	// ProxyFault is set only by an experiment that injects through khaos's own
	// fault proxy. The experiment owns the magnitude because the operator declares
	// it as a parameter, and the CLI must not have to infer a fault from a kind.
	ProxyFault *proxy.Fault

	// ProxyListen and ProxyUpstream are where the run binds the proxy and what
	// it forwards to. They come from declared parameters, so an operator can
	// point a proxy experiment at their own stack.
	ProxyListen   string
	ProxyUpstream string

	// IdP and IdPTrap are set only by an experiment that arms khaos's own
	// identity provider, and the provider is built by the builder because its
	// probes mint out of it.
	IdP     *idp.Provider
	IdPTrap *idp.Trap

	// Authority and PKITrap are set only by an experiment that arms khaos's own
	// certificate authority, which plays the dependency whose certificate is
	// under test.
	Authority *pki.Authority
	PKITrap   *pki.Trap

	// AuthorityBase is the URL the TARGET uses to reach the authority's CRL and
	// OCSP endpoints, and AuthorityListen is where khaos binds them. They are
	// separate because the target addresses khaos by a name khaos cannot see
	// from its own listener, and deriving one from the other is the identity
	// provider's most expensive bug.
	AuthorityBase   string
	AuthorityListen string
	AuthorityTLS    string

	// Defect names what khaos did to the credential, for the verdict's wording.
	Defect string

	// HeldCaveat qualifies a HELD verdict that covers less than it appears to.
	HeldCaveat string

	// Consulted reads how many times the target has reached the endpoint this
	// experiment faults, and ConsultedWhat names it. Together they are the
	// liveness guard for a fault whose landing the probe streams cannot see.
	Consulted     func() int64
	ConsultedWhat string

	// Unsupportable names the check whose absence is itself the finding, which
	// turns a never-consulted endpoint into UNSUPPORTED rather than a void run.
	Unsupportable string

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
