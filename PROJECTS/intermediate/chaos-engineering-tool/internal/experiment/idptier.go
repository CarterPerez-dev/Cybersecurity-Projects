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

	// The identity tier's own response. It is not the proxy tier's wording,
	// because the dependency here is reachable and answering: the question is
	// whether the target believes what it says.
	idpResponse = "refusing a credential its own identity provider should never have produced"

	// Generous against the range, for the same reason the proxy tier's delay
	// default is: the hold has to exceed the target's own upstream timeout or the
	// trap is not expressible at all. A caller whose timeout is longer than the
	// hold sees a slow SUCCESS, which is correct behaviour and not a finding.
	defaultIdPDelay = "2s"

	// How far a corrupted claim is moved. Far enough that no clock skew
	// tolerance a sane verifier carries can absorb it: the reference verifier
	// allows 60 seconds and real ones allow more.
	defaultClaimShift = "1h"

	// The floor, and it is not decoration. Measured: a 30 second shift against a
	// verifier allowing the textbook 60 seconds of skew reported `PERMITTED`,
	// defect, exit 2 against a target doing exactly what RFC 7519 section 4.1.4
	// permits. Five minutes clears the generous configurations as well as the
	// typical ones.
	claimShiftFloor = 5 * time.Minute

	// The same hazard for a hold. A hold a target's timeout absorbs produces a
	// slow SUCCESS, which is correct behaviour, so khaos can only report HELD
	// and teaches the operator nothing. One second clears the sub-second
	// timeouts that are common and is far above the jitter the differential
	// confirmation has to see through.
	idpDelayFloor = time.Second

	becauseClockSkew = "a claim moved less than that sits inside the clock-skew allowance RFC 7519 permits a verifier to carry, so a correct target may accept it and khaos would report that as a bypass"

	becauseTimeout = "a hold shorter than that is absorbed by most callers' timeouts, so the target sees a slow success rather than a failure and the experiment can only ever report that it held"
)

// idpPolarity is the identity tier's default. Honouring a credential the
// provider marked wrong is the defect; refusing one is the control working.
var idpPolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "a verifier that accepts a credential its own issuer declared defective has stopped being a verifier, and every credential it will ever be shown reaches it the same way",
}

// rotationPolarity is the ONE inversion in the family, and it is why khaos
// carries a directional axis at all. An overlapping key rotation is the
// availability-preserving operation every provider is supposed to perform, so
// refusing a correctly signed token under the new key is the failure and
// accepting it is correct. Reporting that as a bypass would be backwards.
// BOTH directions, and the second is the point. An overlapping rotation is
// supposed to break nothing, so refusing a correctly signed new-key token is the
// failure this experiment is named for. But a target that started accepting
// credentials it had been refusing is a defect under every experiment khaos
// ships, and declaring only DENIED made khaos print "this experiment declares
// PERMITTED to be acceptable for this control" over a target that failed wide
// open, and exit 0.
var rotationPolarity = Polarity{
	Defects:   []Direction{Denied, Permitted},
	Rationale: "an overlapping rotation publishes both keys precisely so nothing breaks, so a verifier that refuses a correctly signed token under the new key has turned a routine key rotation into an outage",
}

// idpParams is the identity tier's parameter set. It needs no --token: the valid
// credential is minted by khaos's own provider, so there is nothing for the
// operator to supply and nothing for the range to issue.
func idpParams(extra ...Param) []Param {
	return append([]Param{
		{Name: ParamTarget, Usage: usageTarget, Required: true},
		{Name: ParamURL, Usage: usageURL, Required: true},
		{Name: ParamIssuer, Usage: usageIssuer, Required: true},
		{Name: ParamInvalidToken, Usage: usageInvalidToken, Default: DefaultInvalidToken},
	}, extra...)
}

var keyFormParam = Param{Name: ParamKeyForm, Usage: usageKeyForm, Default: string(idp.SPKIPEM)}

var idpDelayParam = Param{Name: ParamDelay, Usage: usageIdPDelay, Default: defaultIdPDelay}

var claimShiftParam = Param{Name: ParamDelay, Usage: usageClaimShift, Default: defaultClaimShift}

const (
	// The two endpoints an identity experiment can fault, as they read in the
	// refusal an operator sees.
	ConsultsJWKS          = "khaos's key set endpoint"
	ConsultsIntrospection = "khaos's introspection endpoint"

	usageIdPDelay   = "how long khaos's identity provider holds each introspection call; it has to outlast the target's own timeout to reach the branch this experiment tests"
	usageClaimShift = "how far into the past or future to move the claim khaos corrupts"
)

// streams is how one experiment wires its probe streams. Each field is a choice
// the experiment makes, and they are not interchangeable: the research found the
// SAME hazard pointing in OPPOSITE directions for two experiments that look
// alike, so none of this is defaulted.
type streams struct {
	// validTrapped mints the valid stream under the armed trap instead of
	// honestly. Only the rotation experiment wants it, because there the question
	// is whether the target accepts a correctly signed token under a NEW key.
	validTrapped bool

	// validStable mints the valid stream under a key that is always published and
	// never rotated, so proving the target is serving does not disturb what the
	// experiment is measuring. See Provider.StableToken.
	validStable bool

	// validOpaque gives the valid stream an OPAQUE credential, so it travels the
	// introspection path and never touches key resolution at all.
	//
	// The rollover experiment requires it, and the requirement is forced rather
	// than chosen. Research 07 section 2.3: the eviction of a retired key is a
	// side effect of the refetch that a token under the NEW key triggers. A valid
	// stream minting JWTs supplies exactly that traffic, so khaos was causing the
	// recovery it then reported.
	//
	// Measured with the range verifier's key cache set to an hour, so its timer
	// could not fire inside a six-second fault window: the run still returned
	// `passed / HELD`. Nothing but khaos's own valid stream could have evicted
	// the retired key. There is no JWT that avoids this — the retired key is
	// withdrawn and any new-key token IS the contaminating traffic — so the
	// stream has to leave the key path entirely.
	validOpaque bool

	// forged declares a forged stream and what it must do during the baseline.
	// Empty means no forged stream.
	forged probe.Expectation

	// forgedFixed mints the forged credential ONCE, before the fault, instead of
	// per sample. The traps whose credential has to predate the fault need it:
	// a token minted after a rotation is signed by the new key and proves
	// nothing about the old one.
	forgedFixed func(*idp.Provider) (string, error)

	// revoked declares a revoked stream, which carries a credential that was
	// legitimately accepted and that the fault takes away.
	revoked func(*idp.Provider) (string, error)
}

// idpPair builds the probe streams for one identity-tier experiment.
//
// The valid stream MINTS PER SAMPLE rather than carrying a token captured at
// build time. That is not a convenience: the provider's state changes mid-run,
// and an experiment whose valid stream froze a token would be unable to tell a
// target that stopped trusting the provider from one that never picked up a
// rotation.
func idpPair(params *Params, provider *idp.Provider, wiring streams) (probe.Pair, error) {
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
		// Fixed and NOT unique per request. An opaque credential is a grant the
		// provider holds, so a fresh one per sample would be a credential the
		// target has never been told about. It is also deliberately NOT the
		// revocable one, or the mutator would revoke the stream that proves the
		// target is still serving.
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

		// Deliberately NOT unique per request. The whole question is whether the
		// target's cached decision for THIS credential outlives its revocation,
		// and a fresh identity every time would never reach that cache. The
		// invalid control above is the opposite: it must be unique, or a cached
		// refusal answers every probe. Same hazard, opposite directions.
		pair.Revoked = probe.NewHTTP(probe.HTTPOptions{
			Name:       probeRevokedName,
			URL:        url,
			Token:      credential,
			Credential: probe.Revoked,
		})
	}

	return pair, nil
}

func forgedProbe(url string, provider *idp.Provider, wiring streams) (probe.Probe, error) {
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

// mintEvery adapts a provider mint to the probe's per-request signature. The
// context is unused because minting is local arithmetic with no I/O, and giving
// it one would suggest a cancellation point that does not exist.
func mintEvery(mint func() (string, error)) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		return mint()
	}
}

// idpSpec is everything one identity-tier experiment declares beyond its name.
type idpSpec struct {
	name      string
	summary   string
	condition string
	defect    string

	// heldCaveat qualifies a HELD verdict. It is per experiment because only
	// some of them measure less than an unqualified "no bypass was observed"
	// implies.
	heldCaveat func(*Params) string
	trap       idp.Kind
	polarity   Polarity
	wiring     streams
	extra      []Param

	// consults names the provider endpoint the target has to have been using for
	// this experiment's fault to reach it. Empty means the fault lands on a
	// credential khaos presents, which the probe streams see directly.
	consults string

	// magnitude reads the operator's parameter into the trap. Only the traps
	// that carry one set it.
	magnitude func(*Params, *idp.Trap) error
}

// idpDefinition turns one declaration into a catalogue entry. Every identity
// experiment goes through here so none of them can forget to build a provider,
// pin the issuer, or carry its polarity through.
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

		// The issuer is pinned to what the TARGET was configured to trust, not to
		// where khaos happens to be listening. khaos binds the bridge gateway's
		// numeric address while the target addresses `host.docker.internal`, so
		// minting under khaos's own listener address would get every credential
		// refused on `iss` for a reason that has nothing to do with the trap, and
		// a refusal for the wrong reason reads exactly like a target that caught
		// it.
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

		// The liveness guard for a fault applied to an endpoint. Both halves are
		// set together, because a declared endpoint with no counter is a guard
		// that can never fire and a counter with no name is a refusal that
		// cannot say what to check.
		if spec.consults != "" {
			shape.ConsultedWhat = spec.consults
			shape.Consulted = counterFor(provider, spec.consults)
		}

		// Derived from the DECLARATION rather than from a second field. A
		// separate flag saying "read --idle-for" sat next to the parameter that
		// declares it and carried a duration of its own that nothing used, so it
		// read like the default while the real default lived in the Param. The
		// two could disagree and one of them would have been silently dead.
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

// wantsIdleness reports whether this experiment declared the idleness pause,
// which is the only thing that makes reading the parameter legal: Params refuses
// a read of a name the experiment never declared.
func (s idpSpec) wantsIdleness() bool {
	for _, param := range s.extra {
		if param.Name == ParamIdleFor {
			return true
		}
	}
	return false
}

// claimShiftMagnitude and holdMagnitude both read --delay and differ only in
// their floor, because the two faults are absorbed by different tolerances.
// counterFor maps the declared endpoint onto the provider's own measurement of
// it. The two endpoint names are constants rather than free text so a typo is a
// compile error and not a silently absent guard.
func counterFor(provider *idp.Provider, endpoint string) func() int64 {
	if endpoint == ConsultsJWKS {
		return provider.JWKSFetches
	}
	return provider.Introspections
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
