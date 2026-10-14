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
	// chainLabel and loopLabel prefix the hops khaos synthesizes. They are
	// deliberately readable rather than random, because the whole point of the
	// CNAME faults is that an operator reading the target's logs can see the
	// name it actually connected to was not the name it asked for.
	chainLabel = "hop"
	loopLabel  = "cycle"

	// chainExit is the zone the chain ends OUTSIDE. `.invalid` is reserved by
	// RFC 2606 and can never resolve publicly, so a target that follows the
	// chain and connects anyway is observably following it rather than quietly
	// reaching a real service.
	chainExit = "khaos-elsewhere.invalid."

	errRecord = "build a %s record for %s: %w"
)

// ErrNoRecord is returned when a question asks for a type khaos's synthesizing
// faults do not produce. It is not a failure: a target asking for SRV while
// khaos is faulting an address record should be forwarded, not answered with
// something invented.
var ErrNoRecord = errors.New(
	"this fault does not synthesize an answer for that query type",
)

// addressAnswer is WrongAddress: the name resolves, to somewhere nobody
// approved. It answers A for an IPv4 address and AAAA for an IPv6 one, and it
// answers the question that was ASKED rather than both, because a target that
// asked only for A and received a AAAA has been sent something it never
// requested and the fault would be about khaos rather than about the address.
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
		// The family the target asked for is not the family of the address khaos
		// was given, so there is no honest record to make. An empty NOERROR is
		// the right answer: the name exists and has no record of that type,
		// which is exactly true.
		return nil, nil
	}
}

// chainAnswer is CNAMEChain: a multi-hop CNAME whose last hop lands in a
// different zone from the one the target asked about.
//
// It is built as a `file`-zone-shaped full chain rather than a single CNAME,
// because research 05 section 8.2 measured that a resolver answering one CNAME
// at a time is a different thing to test than one answering the whole chain, and
// the whole chain is what a real authoritative server returns.
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

// loopAnswer is CNAMELoop: two CNAMEs pointing at each other, plus the entry
// hop. The server answering it does not hang, which the research measured; what
// is under test is the CLIENT's loop handling, and a client with none spins or
// exhausts its own retry budget.
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

// rettl rewrites every TTL in an answer, which is how the two TTL faults corrupt
// exactly one property of a real answer rather than inventing one.
//
// It rewrites the authority and additional sections too. A caching resolver
// keyed off an SOA's TTL in the authority section would otherwise honour a
// lifetime khaos did not set, and the fault would be partially applied with
// nothing saying so.
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

// validAddress refuses a WrongAddress magnitude that is not an address, before
// the trap reaches the journal. The fault's whole observable is the address the
// target connected to, so a malformed one would arm, answer an empty NOERROR
// and be reported as a target that resolved nothing.
func validAddress(address string) error {
	if net.ParseIP(address) == nil {
		return fmt.Errorf(errBadAddress, ErrBadAddress, address)
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
