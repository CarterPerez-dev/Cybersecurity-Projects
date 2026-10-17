// ©AngelaMos | 2026
// dns.go

package experiment

import "github.com/CarterPerez-dev/khaos/internal/dnsrv"

// The `dns.` family, where the dependency is HEALTHY and the target cannot find
// it, or finds something else. The two faults khaos cannot deliver are entries
// as well, so asking for one gets the mechanism instead of silence.
const (
	NameDNSNXDomain        = "dns.nxdomain"
	NameDNSServFail        = "dns.servfail"
	NameDNSSlowResponse    = "dns.slow_response"
	NameDNSWrongAddress    = "dns.wrong_address"
	NameDNSCNAMEChain      = "dns.cname_chain"
	NameDNSCNAMELoop       = "dns.cname_loop"
	NameDNSTruncation      = "dns.truncation"
	NameDNSTruncationNoTCP = "dns.truncation_no_tcp"
	NameDNSTTLZero         = "dns.ttl_zero"
	NameDNSTTLLong         = "dns.ttl_long"
	NameDNSTTLRotate       = "dns.ttl_rotate"
	NameDNSRefused         = "dns.refused"
	NameDNSTimeout         = "dns.timeout"
)

const (
	summaryNXDomain = "answer the dependency's name with a definite NXDOMAIN and find out whether a control that cannot evaluate its own allowlist treats that as permission"

	summaryServFail = "answer the dependency's name with a TEMPORARY failure, which clients retry where they would have given up on NXDOMAIN, and find out whether a transient resolution error becomes a decision or a retry storm"

	summarySlowResponse = "hold the target's lookup of its dependency almost to the embedded resolver's 4 second ceiling and find out whether a slow name is treated as an absent one"

	summaryWrongAddress = "answer the dependency's name with an address nobody approved and find out what the target's control does about it, which is the one fault where a hostname allowlist can actively authorise a host rather than merely stop working"

	summaryCNAMEChain = "answer the dependency's name with a multi-hop CNAME ending somewhere else entirely, which asks whether name matching survives indirection out of the zone that was asked for"

	summaryCNAMELoop = "answer the dependency's name with a CNAME cycle and find out what the target's own loop handling does with it"

	summaryTruncation = "set the truncation bit on the dependency's lookup and answer completely only over TCP, and find out whether the target makes the RFC 5966 retry at all"

	summaryTruncationNoTCP = "set the truncation bit and refuse to complete over TCP either, which is what a deny-all-TCP-53 egress rule looks like from inside, and find out whether the target can resolve anything that does not fit in a UDP packet"

	summaryTTLZero = "answer the dependency's name correctly with a zero TTL so nothing may cache it, and measure whether the target re-resolves per request, which is both a DoS amplifier and the precondition for every other caching question"

	summaryTTLLong = "answer the dependency's name correctly with a week-long TTL and measure whether the target honours it, which is how long a stale answer would keep being trusted after the dependency moved"

	summaryTTLRotate = "MOVE the dependency's address in the zone, the way an operator performs a DNS failover or an endpoint revocation, and measure whether the change reaches the target at all -- a client still talking to the address that was rotated away is a revocation that never took effect"

	summaryRefused = "REFUSED through Docker's embedded resolver, which khaos refuses to approximate; the resolver rewrites it to SERVFAIL and a real library branches on the rcode"

	summaryTimeout = "a dropped query through Docker's embedded resolver, which khaos refuses to approximate; the resolver answers SERVFAIL itself at a measured 4.001s and a client never sees a socket timeout"
)

var dnsCatalogue = []dnsSpec{
	{
		name:    NameDNSNXDomain,
		summary: summaryNXDomain,
		fault:   dnsrv.NXDomain,
	},
	{
		name:    NameDNSServFail,
		summary: summaryServFail,
		fault:   dnsrv.ServFail,
	},
	{
		name:    NameDNSSlowResponse,
		summary: summarySlowResponse,
		fault:   dnsrv.SlowResponse,
		extra:   []Param{dnsDelayParam},
	},
	{
		name:    NameDNSWrongAddress,
		summary: summaryWrongAddress,
		fault:   dnsrv.WrongAddress,
		extra:   []Param{dnsAddressParam},
	},
	{
		name:    NameDNSCNAMEChain,
		summary: summaryCNAMEChain,
		fault:   dnsrv.CNAMEChain,
		extra:   []Param{dnsAddressParam},
	},
	{
		name:    NameDNSCNAMELoop,
		summary: summaryCNAMELoop,
		fault:   dnsrv.CNAMELoop,
	},
	{
		name:    NameDNSTruncation,
		summary: summaryTruncation,
		fault:   dnsrv.Truncation,
	},
	{
		name:    NameDNSTruncationNoTCP,
		summary: summaryTruncationNoTCP,
		fault:   dnsrv.TruncationNoTCP,
	},
	{
		name:       NameDNSTTLZero,
		summary:    summaryTTLZero,
		fault:      dnsrv.TTLZero,
		needsCache: true,
	},
	{
		name:       NameDNSTTLLong,
		summary:    summaryTTLLong,
		fault:      dnsrv.TTLLong,
		needsCache: true,
	},
	{
		name:    NameDNSTTLRotate,
		summary: summaryTTLRotate,
		fault:   dnsrv.AddressRotated,
		extra:   []Param{dnsAddressParam},
		rotates: true,
	},
	{
		name:    NameDNSRefused,
		summary: summaryRefused,
		fault:   dnsrv.Refused,
	},
	{
		name:    NameDNSTimeout,
		summary: summaryTimeout,
		fault:   dnsrv.Timeout,
	},
}

func init() {
	for _, spec := range dnsCatalogue {
		catalog[spec.name] = dnsDefinition(spec)
	}
}

// DNSNames is the family in catalogue order.
func DNSNames() []string {
	out := make([]string, 0, len(dnsCatalogue))
	for _, spec := range dnsCatalogue {
		out = append(out, spec.name)
	}
	return out
}

// DNSDeliverable splits the family into the faults khaos serves and the ones it
// refuses, derived from the resolver's own list so the two cannot drift.
func DNSDeliverable() (deliverable, refused []string) {
	for _, spec := range dnsCatalogue {
		if dnsrv.Deliverable(spec.fault) {
			deliverable = append(deliverable, spec.name)
			continue
		}
		refused = append(refused, spec.name)
	}

	return deliverable, refused
}
