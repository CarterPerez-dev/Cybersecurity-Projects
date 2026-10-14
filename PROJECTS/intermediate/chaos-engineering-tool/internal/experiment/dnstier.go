// ©AngelaMos | 2026
// dnstier.go

package experiment

import (
	"fmt"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
	"github.com/CarterPerez-dev/khaos/internal/inject"
)

const (
	FamilyDNS = "dns"

	// ParamDNSHost is the dependency's NAME, and it is the parameter that makes
	// this family work at all.
	//
	// It has to be a name khaos's resolver is authoritative for, and a name the
	// target's own embedded resolver cannot answer. A container name or network
	// alias is answered locally out of the embedded resolver's own table and
	// never forwarded, so a fault aimed at one would be armed, never seen, and
	// reported as a clean survival.
	ParamDNSHost = "dns-host"

	// ParamResolverNetwork is the Docker network khaos's resolver serves, which
	// must be the target's own. khaos finds the resolver there by label rather
	// than being told where it is.
	ParamResolverNetwork = "resolver-network"

	// ParamDNSAddress is the address the redirect faults answer with, and
	// ParamDNSDelay is how long the slow fault holds a lookup.
	ParamDNSAddress = "dns-address"
	ParamDNSDelay   = "dns-delay"

	usageDNSHost         = "the dependency's DNS name, which khaos's resolver must be authoritative for; it cannot be a container name or network alias, because the target's own embedded resolver answers those locally and never forwards them"
	usageResolverNetwork = "the Docker network khaos's chaos resolver serves, which must be the target's own network"
	usageDNSAddress      = "the address the redirect faults answer with; point it at a service that behaves differently from the real dependency and the fault becomes a fail-open demonstration rather than an outage"
	usageDNSDelay        = "how long to hold the target's lookup; the ceiling is 3.999s, because Docker's embedded resolver answers SERVFAIL itself at a measured 4.001s and a larger delay would be a different fault"

	dnsCondition = "%s resolving its dependency through a resolver khaos has made wrong: %s"

	dnsResponse = "continuing to refuse credentials it would have refused anyway, rather than letting them through because it could not find its dependency"

	// ConsultsResolver is the endpoint the liveness guard names, as an operator
	// reads it in a verdict.
	ConsultsResolver = "khaos's chaos resolver"

	// cacheRequiredTTL is what the TTL faults declare they need. A target with
	// no cached answer has no lifetime to honour or ignore, so the TTL khaos
	// serves governs nothing it does.
	cacheRequiredTTL = "the lifetime of a cached DNS answer"

	// caveatRedirectUnseen is what khaos says instead of claiming the target
	// verified the host it reached. khaos has no instrument at the far end of an
	// operator-chosen address.
	caveatRedirectUnseen = "khaos served the redirect and measured that the target re-resolved, and it did NOT observe which host the target then connected to: the redirect address is an operator parameter and khaos has nothing listening at the far end of it. So this HELD means the target's control was not disturbed, and it does not establish that the target verified who it reached. If the address you redirected to answers at all, check its own logs for the target's requests before reading this as a pass"

	// deliveredResolve is what the target has to DO for a DNS fault to reach it,
	// phrased as the operator reads it in a verdict.
	deliveredResolve = "re-resolve its dependency's name"
)

// dnsPolarity is PERMITTED alone, and the two directions it leaves out are
// deliberate.
//
// DENIED is the correct outcome with an availability cost. A target that cannot
// resolve its identity provider and therefore refuses everything has failed
// closed; research 05 section 10 calls that bad in a different way -- DNS
// becomes a single point of failure and anyone who can break it can deny the
// service -- but it is not a security defect and khaos will not report it as
// one.
//
// HELD is not a defect either, and that is the opposite of the `tls.` family's
// polarity for a reason worth stating. There, carrying on unchanged means the
// target USED a certificate khaos deliberately broke. Here, carrying on
// unchanged means the target's control was not disturbed by its dependency
// moving or vanishing, which is what a correct control does. The case where
// carrying on hides something -- the target connected to the address khaos
// redirected it to and that address approved everything -- does not surface as
// HELD at all: it surfaces as the invalid credential being accepted, which is
// PERMITTED.
var dnsPolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "a control that stops rejecting invalid credentials because it could not resolve its dependency has moved its trust boundary into DNS, which nobody operating it controls; refusing to serve while continuing to enforce is the correct outcome with an availability cost, not a defect",
}

func dnsParams(extra ...Param) []Param {
	return append([]Param{
		{Name: ParamTarget, Usage: usageTarget, Required: true},
		{Name: ParamURL, Usage: usageURL, Required: true},
		{Name: ParamToken, Usage: usageToken, Required: true},
		{Name: ParamDNSHost, Usage: usageDNSHost, Required: true},
		{
			Name:     ParamResolverNetwork,
			Usage:    usageResolverNetwork,
			Required: true,
		},
		{
			Name:    ParamInvalidToken,
			Usage:   usageInvalidToken,
			Default: DefaultInvalidToken,
		},
	}, extra...)
}

var dnsAddressParam = Param{
	Name:    ParamDNSAddress,
	Usage:   usageDNSAddress,
	Default: dnsrv.DefaultWrongAddress,
}

var dnsDelayParam = Param{
	Name:    ParamDNSDelay,
	Usage:   usageDNSDelay,
	Default: dnsrv.DefaultDelay.String(),
}

// dnsSpec is one DNS experiment's declaration. Everything not derived from a
// parameter lives here, so a builder cannot restate its own name or forget its
// polarity.
type dnsSpec struct {
	name    string
	summary string
	fault   dnsrv.Kind

	// needsCache marks the two experiments whose question only applies to a
	// target that caches. It turns a target re-resolving per request into
	// UNSUPPORTED rather than a clean survival it never earned.
	needsCache bool

	extra []Param
}

// dnsDefinition turns one declaration into a catalogue entry. Every DNS
// experiment goes through here, so none of them can forget the liveness guard
// that makes its verdict interpretable.
func dnsDefinition(spec dnsSpec) Definition {
	return Definition{
		Name:       spec.name,
		Family:     FamilyDNS,
		Summary:    spec.summary,
		Hypothesis: Hypothesis{Condition: outageGeneric, Response: dnsResponse},
		Polarity:   dnsPolarity,
		FaultKind:  inject.DNSKind(spec.fault),
		Params:     dnsParams(spec.extra...),
		Build:      buildDNS(spec),
	}
}

func buildDNS(spec dnsSpec) func(*Params) (Shape, error) {
	return func(params *Params) (Shape, error) {
		target := params.Get(ParamTarget)
		host := params.Get(ParamDNSHost)

		trap := dnsrv.Trap{Kind: spec.fault, Host: host}

		if err := readDNSMagnitude(params, spec, &trap); err != nil {
			return Shape{}, err
		}

		// SHAPE only. A delay above the measured ceiling is refused here,
		// because that is an operator typing a number and they should hear it
		// immediately. Whether khaos will DELIVER the fault is not checked here:
		// the two masked faults are catalogued in order to be explained, so they
		// build, plan and describe like any other entry and are refused when
		// khaos is asked to arm one.
		if err := trap.ValidateShape(); err != nil {
			return Shape{}, err
		}

		shape := Shape{
			Condition: fmt.Sprintf(
				dnsCondition,
				target,
				trap.Describe(target),
			),
			Target:          target,
			Probes:          probePair(params),
			DNSTrap:         &trap,
			ResolverNetwork: params.Get(ParamResolverNetwork),
			DNSHost:         host,
			Defect:          spec.summary,

			// The proof-of-arrival control, and it is not optional. Research 05
			// section 12 states the reason: without it khaos cannot tell "the
			// control failed closed" from "the fault never reached the target",
			// and the second is the likely one, because `--dns` is fixed at
			// container creation and Docker offers no way to change it on a
			// running container. A target that was not recreated against khaos's
			// resolver never sends it a single query.
			ConsultedWhat: ConsultsResolver,

			// The caveat on a HELD verdict for the two REDIRECT faults, and it
			// is load-bearing rather than hedging.
			//
			// khaos measures that it served the wrong address and that the
			// target re-resolved. It does NOT measure which host the target
			// then connected to, because the redirect address is an operator
			// parameter and khaos has no instrument at the far end of it.
			//
			// That gap decides the polarity. Against the default documentation
			// address, with nothing listening, HELD honestly means the target
			// held through an unreachable dependency, which is correct
			// behaviour. Against an address that ANSWERS and mirrors the real
			// dependency's decisions, the same HELD means the target moved its
			// trust to a host nobody approved and khaos cleared it -- which is
			// the `tls.` family's rule one domain over, where carrying on
			// unchanged means the target USED the thing khaos broke.
			//
			// A blanket defect declaration would be wrong for the first case
			// and silence would be wrong for the second, so khaos states what
			// it did not observe.
			HeldCaveat: heldCaveatFor(spec),

			// The DELIVERY guard, which no other tier needs. Every other
			// fault acts on a path the target cannot avoid using; a DNS
			// answer is one it can simply not ask for again, and a target
			// holding a kept-alive connection does exactly that.
			//
			// The TTL pair is EXEMPT and that is not an oversight. For every
			// other fault, a target that did not re-resolve never met the
			// fault. For these two, not re-resolving is the measurement: the
			// experiment is about how long a cached answer is honoured, so a
			// target that re-asks less is a target that cached more. Applying
			// the guard there aborted the only run the experiment exists for,
			// and its own remediation ("run this against a service that
			// re-resolves") contradicted cacheNotObserved's four lines
			// earlier in the same verdict.
			DeliveredWhat: deliveredFor(spec),
		}

		if spec.needsCache {
			shape.CacheRequired = cacheRequiredTTL
		}

		return shape, nil
	}
}

// readDNSMagnitude reads whichever parameter this experiment declared. Params
// refuses a read of a name the experiment never declared, so this cannot read a
// flag that is not there.
func readDNSMagnitude(
	params *Params,
	spec dnsSpec,
	trap *dnsrv.Trap,
) error {
	for _, param := range spec.extra {
		switch param.Name {
		case ParamDNSAddress:
			trap.Address = params.Get(ParamDNSAddress)

		case ParamDNSDelay:
			delay, err := params.Duration(ParamDNSDelay)
			if err != nil {
				return err
			}

			trap.Delay = delay

		default:
			// A parameter this tier does not read, which is legal: the shared
			// set carries several.
		}
	}

	return nil
}

// heldCaveatFor returns the qualification a HELD verdict needs, or none.
//
// Only the two faults that MOVE the dependency's address carry one, because
// they are the only two where carrying on unchanged might mean the target
// reached somewhere khaos cannot see.
func heldCaveatFor(spec dnsSpec) string {
	if spec.fault != dnsrv.WrongAddress && spec.fault != dnsrv.CNAMEChain {
		return ""
	}

	return caveatRedirectUnseen
}

// deliveredFor returns the delivery question this experiment asks, or none.
//
// It is derived from the same `needsCache` declaration that turns on the cache
// reading, so the two cannot disagree about which faults are about caching.
func deliveredFor(spec dnsSpec) string {
	if spec.needsCache {
		return ""
	}

	return deliveredResolve
}

// DNSDelayCeiling is the measured bound an operator sees in a refusal, exported
// so the CLI and the gate name the same number the resolver enforces.
func DNSDelayCeiling() time.Duration {
	return dnsrv.MaxDelay
}
