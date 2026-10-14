// ©AngelaMos | 2026
// idptier.go

package experiment

import (
	"context"
	"fmt"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	ParamIssuer  = "issuer"
	ParamKeyForm = "key-form"

	usageIssuer = "the issuer khaos's own identity provider must mint under, which has to be the exact string the target was configured to trust"

	usageKeyForm = "which serialization of the issuer's public key to use as the HMAC secret, because the attack only works with the bytes the target actually loaded: spki-pem, spki-der, pkcs1-pem or modulus"

	probeForgedName = "forged-credential"

	idpResponse = "refusing a credential its own identity provider should never have produced"

	defaultIdPDelay = "2s"

	defaultClaimShift = "1h"

	claimShiftFloor = 5 * time.Minute

	idpDelayFloor = time.Second

	becauseClockSkew = "a claim moved less than that sits inside the clock-skew allowance RFC 7519 permits a verifier to carry, so a correct target may accept it and khaos would report that as a bypass"

	becauseTimeout = "a hold shorter than that is absorbed by most callers' timeouts, so the target sees a slow success rather than a failure and the experiment can only ever report that it held"
)

var idpPolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "a verifier that accepts a credential its own issuer declared defective has stopped being a verifier, and every credential it will ever be shown reaches it the same way",
}

// rotationPolarity is the one inversion in the family: an overlapping rotation
// should break nothing, so refusing a correctly signed new-key token is the
// failure. PERMITTED stays a defect too.
var rotationPolarity = Polarity{
	Defects:   []Direction{Denied, Permitted},
	Rationale: "an overlapping rotation publishes both keys precisely so nothing breaks, so a verifier that refuses a correctly signed token under the new key has turned a routine key rotation into an outage",
}

// idpParams needs no --token: khaos's own provider mints the valid credential,
// so there is nothing for the operator to supply.
func idpParams(extra ...Param) []Param {
	return append([]Param{
		{Name: ParamTarget, Usage: usageTarget, Required: true},
		{Name: ParamURL, Usage: usageURL, Required: true},
		{Name: ParamIssuer, Usage: usageIssuer, Required: true},
		{
			Name:    ParamInvalidToken,
			Usage:   usageInvalidToken,
			Default: DefaultInvalidToken,
		},
	}, extra...)
}

var keyFormParam = Param{
	Name:    ParamKeyForm,
	Usage:   usageKeyForm,
	Default: string(idp.SPKIPEM),
}

var idpDelayParam = Param{
	Name:    ParamDelay,
	Usage:   usageIdPDelay,
	Default: defaultIdPDelay,
}

var claimShiftParam = Param{
	Name:    ParamDelay,
	Usage:   usageClaimShift,
	Default: defaultClaimShift,
}

const (
	ConsultsJWKS          = "khaos's key set endpoint"
	ConsultsIntrospection = "khaos's introspection endpoint"

	usageIdPDelay   = "how long khaos's identity provider holds each introspection call; it has to outlast the target's own timeout to reach the branch this experiment tests"
	usageClaimShift = "how far into the past or future to move the claim khaos corrupts"
)

type streams struct {
	validTrapped bool

	validStable bool

	// A JWT valid stream would supply the new-key traffic whose refetch evicts a
	// retired key, so khaos would cause the recovery it then reports.
	validOpaque bool

	forged probe.Expectation

	forgedFixed func(*idp.Provider) (string, error)

	revoked func(*idp.Provider) (string, error)
}

// idpPair mints the valid stream per sample rather than freezing a token at
// build time, because the provider's state changes mid-run.
func idpPair(
	params *Params,
	provider *idp.Provider,
	wiring streams,
) (probe.Pair, error) {
	url := params.Get(ParamURL)

	mintValid := provider.HonestToken
	if wiring.validTrapped {
		mintValid = provider.TrappedToken
	}
	if wiring.validStable {
		mintValid = provider.StableToken
	}

	valid := probe.HTTPOptions{
		Name:       probeValidName,
		URL:        url,
		Credential: probe.Valid,
		Mint:       mintEvery(mintValid),
	}

	if wiring.validOpaque {
		// Fixed and NOT unique: an opaque credential is a grant the provider
		// holds. Not the revocable one either, or the mutator would revoke the
		// stream that proves the target is still serving.
		valid = probe.HTTPOptions{
			Name:       probeValidName,
			URL:        url,
			Credential: probe.Valid,
			Token:      provider.Opaque(),
		}
	}

	pair := probe.Pair{
		Valid: probe.NewHTTP(valid),
		Invalid: probe.NewHTTP(probe.HTTPOptions{
			Name:       probeInvalidName,
			URL:        url,
			Token:      params.Get(ParamInvalidToken),
			Credential: probe.Invalid,
			Unique:     true,
		}),
	}

	if wiring.forged != "" {
		forged, err := forgedProbe(url, provider, wiring)
		if err != nil {
			return probe.Pair{}, err
		}
		pair.Forged = forged
		pair.ForgedBaseline = wiring.forged
	}

	if wiring.revoked != nil {
		credential, err := wiring.revoked(provider)
		if err != nil {
			return probe.Pair{}, err
		}

		// NOT unique per request, unlike the invalid control above: the question
		// is whether the cached decision for THIS credential outlives revocation.
		pair.Revoked = probe.NewHTTP(probe.HTTPOptions{
			Name:       probeRevokedName,
			URL:        url,
			Token:      credential,
			Credential: probe.Revoked,
		})
	}

	return pair, nil
}

func forgedProbe(
	url string,
	provider *idp.Provider,
	wiring streams,
) (probe.Probe, error) {
	options := probe.HTTPOptions{
		Name:       probeForgedName,
		URL:        url,
		Credential: probe.Forged,
	}

	if wiring.forgedFixed != nil {
		credential, err := wiring.forgedFixed(provider)
		if err != nil {
			return nil, err
		}
		options.Token = credential
		return probe.NewHTTP(options), nil
	}

	options.Mint = mintEvery(provider.TrappedToken)

	return probe.NewHTTP(options), nil
}

// mintEvery ignores the context because minting is local arithmetic with no I/O.
func mintEvery(
	mint func() (string, error),
) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		return mint()
	}
}

type idpSpec struct {
	name      string
	summary   string
	condition string
	defect    string

	heldCaveat func(*Params) string
	trap       idp.Kind
	polarity   Polarity
	wiring     streams
	extra      []Param

	// consults names the provider endpoint the target has to have been using for
	// this fault to reach it; empty means the probe streams see it directly.
	consults string

	magnitude func(*Params, *idp.Trap) error
}

func idpDefinition(spec idpSpec) Definition {
	polarity := spec.polarity
	if len(polarity.Defects) == 0 {
		polarity = idpPolarity
	}

	return Definition{
		Name:       spec.name,
		Family:     FamilyIdentity,
		Summary:    spec.summary,
		Hypothesis: Hypothesis{Condition: outageGeneric, Response: idpResponse},
		Polarity:   polarity,
		FaultKind:  inject.IdPKind(spec.trap),
		Params:     idpParams(spec.extra...),
		Build:      buildIdP(spec),
	}
}

func buildIdP(spec idpSpec) func(*Params) (Shape, error) {
	return func(params *Params) (Shape, error) {
		target := params.Get(ParamTarget)
		issuer := params.Get(ParamIssuer)

		provider, err := idp.New(idp.Config{})
		if err != nil {
			return Shape{}, err
		}

		// Pinned to what the TARGET trusts, not to where khaos listens: minting
		// under khaos's own bridge address would get every credential refused on
		// `iss` for a reason that has nothing to do with the trap.
		provider.SetIssuer(issuer)

		trap := idp.Trap{Kind: spec.trap}

		if spec.magnitude != nil {
			if err := spec.magnitude(params, &trap); err != nil {
				return Shape{}, err
			}
		}

		pair, err := idpPair(params, provider, spec.wiring)
		if err != nil {
			return Shape{}, err
		}

		shape := Shape{
			Condition: fmt.Sprintf(spec.condition, target),
			Target:    target,
			Probes:    pair,
			IdP:       provider,
			IdPTrap:   &trap,
			Defect:    spec.defect,
		}

		if spec.heldCaveat != nil {
			shape.HeldCaveat = spec.heldCaveat(params)
		}

		if spec.consults != "" {
			shape.ConsultedWhat = spec.consults
			shape.Consulted = counterFor(provider, spec.consults)
		}

		if spec.wantsIdleness() {
			idle, err := params.Duration(ParamIdleFor)
			if err != nil {
				return Shape{}, err
			}
			shape.IdleFor = idle
		}

		return shape, nil
	}
}

func (s idpSpec) wantsIdleness() bool {
	for _, param := range s.extra {
		if param.Name == ParamIdleFor {
			return true
		}
	}
	return false
}

// counterFor always returns a nil error; the signature carries one for the DNS
// tier, whose counter lives in another container.
func counterFor(
	provider *idp.Provider,
	endpoint string,
) func() (int64, error) {
	read := provider.Introspections
	if endpoint == ConsultsJWKS {
		read = provider.JWKSFetches
	}

	return func() (int64, error) { return read(), nil }
}

func claimShiftMagnitude(params *Params, trap *idp.Trap) error {
	shift, err := params.AtLeast(ParamDelay, claimShiftFloor, becauseClockSkew)
	if err != nil {
		return err
	}
	trap.Delay = shift
	return nil
}

func holdMagnitude(params *Params, trap *idp.Trap) error {
	hold, err := params.AtLeast(ParamDelay, idpDelayFloor, becauseTimeout)
	if err != nil {
		return err
	}
	trap.Delay = hold
	return nil
}

func keyFormMagnitude(params *Params, trap *idp.Trap) error {
	trap.KeyForm = idp.KeyForm(params.Get(ParamKeyForm))
	return trap.Validate()
}
