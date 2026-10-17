// ©AngelaMos | 2026
// records.go

package dnsrv

import (
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

const (
	chainLabel = "hop"
	loopLabel  = "cycle"

	// chainExit is the zone the chain ends OUTSIDE. `.invalid` is reserved by
	// RFC 2606 and can never resolve publicly.
	chainExit = "khaos-elsewhere.invalid."

	errRecord = "build a %s record for %s: %w"
)

// ErrNoRecord means the question asked for a type these faults do not
// synthesize, so it should be forwarded rather than answered with an invention.
var ErrNoRecord = errors.New(
	"this fault does not synthesize an answer for that query type",
)

// addressAnswer is WrongAddress. It answers the question that was ASKED rather
// than both families, since a target handed a AAAA it never requested would
// make the fault about khaos instead of about the address.
func addressAnswer(question dns.Question, trap Trap) ([]dns.RR, error) {
	address := trap.address()

	parsed := net.ParseIP(address)
	if parsed == nil {
		return nil, fmt.Errorf(errBadAddress, ErrBadAddress, address)
	}

	isV4 := parsed.To4() != nil

	switch {
	case question.Qtype == dns.TypeA && isV4:
		return newRR(dns.TypeA, question.Name, trap.ttl(), address)
	case question.Qtype == dns.TypeAAAA && !isV4:
		return newRR(dns.TypeAAAA, question.Name, trap.ttl(), address)
	default:
		// The family asked for is not the family of the address khaos was
		// given, so an empty NOERROR is the only honest answer.
		return nil, nil
	}
}

// chainAnswer is CNAMEChain: a multi-hop CNAME whose last hop lands in a
// different zone from the one the target asked about. The whole chain is
// returned at once, which is what a real authoritative server does.
func chainAnswer(question dns.Question, trap Trap) ([]dns.RR, error) {
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return nil, nil
	}

	ttl := trap.ttl()
	name := dns.CanonicalName(question.Name)

	records := make([]dns.RR, 0, chainHops)

	// chainHops counts CNAME records, so the bound is inclusive.
	for hop := 1; hop <= chainHops; hop++ {
		next := fmt.Sprintf("%s%d.%s", chainLabel, hop, chainExit)
		rr, err := newRR(dns.TypeCNAME, name, ttl, next)
		if err != nil {
			return nil, err
		}
		records = append(records, rr...)
		name = next
	}

	final, err := addressAnswer(dns.Question{
		Name:  name,
		Qtype: question.Qtype,
	}, trap)
	if err != nil {
		return nil, err
	}

	return append(records, final...), nil
}

// loopAnswer is CNAMELoop: two CNAMEs pointing at each other plus the entry
// hop. Serving it does not hang the server; the client's loop handling is what
// is under test.
func loopAnswer(question dns.Question, trap Trap) ([]dns.RR, error) {
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return nil, nil
	}

	ttl := trap.ttl()
	asked := dns.CanonicalName(question.Name)
	first := fmt.Sprintf("%s1.%s", loopLabel, chainExit)
	second := fmt.Sprintf("%s2.%s", loopLabel, chainExit)

	hops := [][2]string{
		{asked, first},
		{first, second},
		{second, first},
	}

	records := make([]dns.RR, 0, len(hops))
	for _, hop := range hops {
		rr, err := newRR(dns.TypeCNAME, hop[0], ttl, hop[1])
		if err != nil {
			return nil, err
		}
		records = append(records, rr...)
	}

	return records, nil
}

// rettl rewrites every TTL in an answer, including the authority and additional
// sections: a resolver keyed off an SOA's TTL there would otherwise honour a
// lifetime khaos did not set, leaving the fault partially applied.
func rettl(msg *dns.Msg, ttl uint32) *dns.Msg {
	if msg == nil {
		return nil
	}

	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			rr.Header().Ttl = ttl
		}
	}

	return msg
}

// validAddress refuses a malformed WrongAddress magnitude before the trap arms,
// where it would answer an empty NOERROR and read as a target that resolved
// nothing.
// validAddress requires IPv4, and that is narrower than "parses as an IP" for a
// measured reason. Every khaos probe asks for an A record, and addressAnswer
// answers an empty NOERROR when the family asked for is not the family of the
// address it was given -- correctly, since inventing an A record from an IPv6
// address builds nothing (measured: `dns: bad A A`). So an IPv6 address passes
// a parse check, arms cleanly, and then makes khaos serve an EMPTY ANSWER while
// reporting that it armed a redirect. Refusing it here means the operator finds
// out when they ask for it rather than reading a verdict about a fault khaos
// never served.
func validAddress(address string) error {
	parsed := net.ParseIP(address)
	if parsed == nil {
		return fmt.Errorf(errBadAddress, ErrBadAddress, address)
	}

	if parsed.To4() == nil {
		return fmt.Errorf(errNotV4, ErrBadAddress, address)
	}

	return nil
}

func newRR(
	rrtype uint16,
	name string,
	ttl uint32,
	value string,
) ([]dns.RR, error) {
	text := fmt.Sprintf(
		"%s %d IN %s %s",
		dns.Fqdn(name),
		ttl,
		dns.TypeToString[rrtype],
		dns.Fqdn(value),
	)

	if rrtype == dns.TypeA || rrtype == dns.TypeAAAA {
		text = fmt.Sprintf(
			"%s %d IN %s %s",
			dns.Fqdn(name),
			ttl,
			dns.TypeToString[rrtype],
			value,
		)
	}

	rr, err := dns.NewRR(text)
	if err != nil {
		return nil, fmt.Errorf(
			errRecord,
			dns.TypeToString[rrtype],
			name,
			err,
		)
	}

	return []dns.RR{rr}, nil
}
