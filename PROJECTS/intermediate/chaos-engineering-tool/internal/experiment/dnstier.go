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

	// Has to be a name khaos's resolver is authoritative for AND one the target's
	// embedded resolver cannot answer: a container name or alias is answered
	// locally and never forwarded, so a fault aimed at one is never seen.
	ParamDNSHost = "dns-host"

	// Must be the target's own network; khaos finds the resolver there by label.
	ParamResolverNetwork = "resolver-network"

	ParamDNSAddress = "dns-address"
	ParamDNSDelay   = "dns-delay"

	usageDNSHost         = "the dependency's DNS name, which khaos's resolver must be authoritative for; it cannot be a container name or network alias, because the target's own embedded resolver answers those locally and never forwards them"
	usageResolverNetwork = "the Docker network khaos's chaos resolver serves, which must be the target's own network"
	usageDNSAddress      = "the address the redirect faults answer with; point it at a service that behaves differently from the real dependency and the fault becomes a fail-open demonstration rather than an outage"
	usageDNSDelay        = "how long to hold the target's lookup; the ceiling is 3.999s, because Docker's embedded resolver answers SERVFAIL itself at a measured 4.001s and a larger delay would be a different fault"

	dnsCondition = "%s resolving its dependency through a resolver khaos has made wrong: %s"

	dnsResponse = "continuing to refuse credentials it would have refused anyway, rather than letting them through because it could not find its dependency"

	ConsultsResolver = "khaos's chaos resolver"

	cacheRequiredTTL = "the lifetime of a cached DNS answer"

	caveatRedirectUnseen = "khaos served the redirect and measured that the target re-resolved, and it did NOT observe which host the target then connected to: the redirect address is an operator parameter and khaos has nothing listening at the far end of it. So this HELD means the target's control was not disturbed, and it does not establish that the target verified who it reached. If the address you redirected to answers at all, check its own logs for the target's requests before reading this as a pass"

	deliveredResolve = "re-resolve its dependency's name"

	rotatedWhat = "moved %s to %s in the zone"

	// What to check when a DNS fault was armed, confirmed and never met. It
	// lives here rather than in the verdict's shared sentence because the only
	// other tier carrying that guard reaches it for an unrelated reason.
	hintResolve = "A kept-alive connection produces this shape -- Go's HTTP transport resolves a name once when it opens a connection and never again while that connection lives, measured at two lookups across forty-six requests -- and so would the target's own resolver cache, an /etc/hosts entry, or resolution over DoH, none of which khaos ruled out. What to check, in that order: the target's connection lifetime, its own DNS cache, /etc/hosts, and whether it resolves over plain DNS at all"
)

// dnsPolarity omits two directions deliberately: DENIED is correct with an
// availability cost, and HELD means the control was not disturbed -- the
// opposite of the `tls.` family.
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

type dnsSpec struct {
	name    string
	summary string
	fault   dnsrv.Kind

	// needsCache turns a target re-resolving per request into UNSUPPORTED rather
	// than a clean survival it never earned.
	needsCache bool

	// rotates MOVES the zone rather than answering it wrongly, and it is exempt
	// from the delivery guard for the same reason the TTL pair is: a target
	// that never asks again IS the measurement here, not a void run. Research
	// 05 section 6.5 carries the polarity.
	rotates bool

	extra []Param
}

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

		// Shape only: the two masked faults still build and describe like any
		// other entry, and are refused when khaos is asked to arm one.
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

			// The proof-of-arrival control: `--dns` is fixed at container
			// creation, so a target not recreated against khaos's resolver
			// never sends it a single query.
			ConsultedWhat: ConsultsResolver,

			HeldCaveat: heldCaveatFor(spec),

			// The delivery guard, which no other tier needs: a DNS answer is the
			// one fault a target can simply not ask for again. The TTL pair is
			// exempt, because there not re-resolving IS the measurement.
			DeliveredWhat: deliveredFor(spec),
			DeliveredHint: hintFor(spec),
		}

		if spec.needsCache {
			shape.CacheRequired = cacheRequiredTTL
		}

		// The rotation's own observable. A target that never asks again did not
		// see the rotation, which is a finding khaos must state and must not
		// call a bypass: it is still talking to the honest endpoint it used
		// during the baseline, so no credential got through that would not
		// have.
		if spec.rotates {
			shape.RotatedWhat = fmt.Sprintf(
				rotatedWhat,
				host,
				trap.Address,
			)
		}

		return shape, nil
	}
}

// readDNSMagnitude reads whichever parameter this experiment declared, since
// Params refuses a read of a name it never declared.
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

// heldCaveatFor qualifies HELD for the faults that MOVE the dependency's
// address, where carrying on might mean reaching somewhere khaos cannot see.
func heldCaveatFor(spec dnsSpec) string {
	if spec.fault != dnsrv.WrongAddress && spec.fault != dnsrv.CNAMEChain {
		return ""
	}

	return caveatRedirectUnseen
}

// deliveredFor is derived from the same needsCache declaration that turns on the
// cache reading, so the two cannot disagree about which faults are about caching.
func deliveredFor(spec dnsSpec) string {
	if spec.needsCache || spec.rotates {
		return ""
	}

	return deliveredResolve
}

func hintFor(spec dnsSpec) string {
	if spec.needsCache || spec.rotates {
		return ""
	}

	return hintResolve
}

// DNSDelayCeiling is exported so the CLI's refusal names the same number the
// resolver enforces.
func DNSDelayCeiling() time.Duration {
	return dnsrv.MaxDelay
}
