// ©AngelaMos | 2026
// trap.go

package dnsrv

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Kind names one way khaos makes name resolution wrong for a target. Every kind
// maps to a row of the injectable fault matrix in research 05 section 9, and the
// two rows khaos cannot deliver are kinds here as well, so that asking for one
// gets an explanation rather than silence.
//
// What separates these from the other families is that the fault is not in the
// dependency at all. The dependency is healthy; the target cannot find it, or
// finds something else. That reaches a different branch of the target's code
// from an unreachable dependency and from one presenting a bad certificate, and
// research 05 section 10 is the argument for why those branches are where the
// fail-open lives.
type Kind string

const (
	// PassThrough is the zero value: the resolver answers correctly by
	// forwarding. A resolver with nothing armed has to be indistinguishable from
	// the one the target would otherwise use, because every baseline is measured
	// through it.
	PassThrough Kind = ""

	// NXDomain is a definite negative answer. The client stops immediately
	// without trying other servers, and a Go target gets `IsNotFound`. It is the
	// cleanest demonstration in research 05 section 10: a control whose
	// allowlist entry is a hostname cannot evaluate itself when the name does
	// not resolve, and a great deal of code reads "could not evaluate" as "not a
	// violation". Row 1.
	NXDomain Kind = "nxdomain"

	// ServFail is a TEMPORARY failure, and that single word is the difference
	// from NXDomain: clients with retry logic retry it, so it also measures
	// whether a transient resolution failure turns into a retry storm or a hang
	// rather than a decision. Row 2.
	ServFail Kind = "servfail"

	// SlowResponse answers correctly but late. Its ceiling is not a preference:
	// Docker's embedded resolver gives up at `extIOTimeout`, measured at exactly
	// 4.001s, and above that this fault silently becomes Timeout, which khaos
	// refuses. So the magnitude is bounded at MaxDelay and anything larger is
	// refused by name. Row 5.
	SlowResponse Kind = "slow-response"

	// WrongAddress is the money experiment of the family. The name resolves, to
	// an address the operator never approved. A hostname allowlist does not
	// merely stop working here, it actively authorises the wrong host, and TLS
	// is the only thing left that can object. Row 6.
	WrongAddress Kind = "wrong-address"

	// CNAMEChain answers with a multi-hop CNAME ending outside the queried zone.
	// It asks whether name-based matching happens on the name that was ASKED or
	// on the target the connection actually goes to, which research 05 section
	// 10 lists as the fourth distinct failure of hostname allowlisting. Row 10.
	CNAMEChain Kind = "cname-chain"

	// CNAMELoop answers with a CNAME cycle. The research measured CoreDNS
	// serving one without hanging and noted explicitly that the CLIENT's loop
	// handling is the thing under test, which no other kind here covers.
	CNAMELoop Kind = "cname-loop"

	// Truncation sets the `tc` bit on UDP and answers completely over TCP, which
	// is what a correct truncating server does. The client must notice and
	// re-ask over TCP per RFC 5966.
	//
	// This kind exists because of a CORRECTION rather than in spite of one.
	// Research 05 section 5 recorded truncation as absorbed entirely by the
	// embedded resolver, which would have made the fault undeliverable. It is
	// not: measured 2026-10-13, `tc=1` reaches the client in every truncating
	// shape and the client's TCP retry arrives here. The original measurement
	// used `dig` without `+ignore`, so dig performed the fallback itself and
	// reported the clean answer. Row 9.
	Truncation Kind = "truncation"

	// TruncationNoTCP sets `tc` and then never completes over TCP either. It is
	// a different question from Truncation and it is the one research 05 row 9
	// names as the security control: whether DNS over TCP is actually permitted
	// by the egress policy. A deny-all-TCP-53 rule turns every large answer into
	// total resolution failure.
	//
	// Measured consequence worth knowing before reading a verdict: to a Go
	// target this lands as `no such host` with `IsNotFound=true`, which is
	// NXDomain's classification. khaos names which one it served because the
	// target cannot.
	TruncationNoTCP Kind = "truncation-no-tcp"

	// TTLZero and TTLLong act on the answer's lifetime rather than its content.
	// They are the two kinds whose fault may be a measured NO-OP: Go has no
	// answer cache and ignores TTL entirely, proven against a 604800 TTL, so
	// against a Go target these test nothing.
	//
	// khaos does not guess. It counts the target's own queries during the fault
	// window, and a target that re-queries per probe is reported UNSUPPORTED,
	// the same way the revocation group reports a target that never asked.
	// Rows 7 and 8.
	TTLZero Kind = "ttl-zero"
	TTLLong Kind = "ttl-long"

	// Refused and Timeout are REFUSED BY KHAOS, and they are kinds rather than
	// omissions on purpose. Docker's embedded resolver rewrites both: REFUSED
	// becomes SERVFAIL because `forwardExtDNS` treats it as a reason to try the
	// next upstream, and a dropped query becomes SERVFAIL at a hard 4.001s.
	//
	// Delivering SERVFAIL while claiming REFUSED would be worse than refusing,
	// because the whole point is which branch of the target's code runs, and a
	// real library branches on the rcode. An operator who asks for one of these
	// gets the reason and the name of the mechanism instead of a wrong
	// measurement. Rows 3 and 4.
	Refused Kind = "refused"
	Timeout Kind = "timeout"
)

const (
	// MaxDelay is one millisecond under the measured `extIOTimeout` ceiling. At
	// or above 4.000s the embedded resolver answers SERVFAIL itself at 4.001s
	// and the delay never reaches the client, so a larger magnitude would be
	// Timeout wearing SlowResponse's name.
	MaxDelay = 3999 * time.Millisecond

	// DefaultDelay sits well inside the ceiling and above any plausible
	// sub-second client timeout, so the fault is observable without being at the
	// edge of the window khaos is allowed to use.
	DefaultDelay = 3 * time.Second

	// LongTTL is one week, matching the research's own measurement against Go.
	LongTTL = 604800

	// HonestTTL is what an unfaulted khaos answer carries. It matches the TTL
	// Docker's own embedded resolver puts on its internal answers, so a target
	// comparing them sees nothing unusual.
	HonestTTL = 600

	// DefaultWrongAddress is in TEST-NET-2, which RFC 5737 reserves for
	// documentation. Nothing can be running there, so a target that connects is
	// observably connecting to an address its operator never approved rather
	// than to some other real service.
	DefaultWrongAddress = "198.51.100.66"
)

const (
	describeNXDomain = "answer %s that the dependency's name does not exist"
	describeServFail = "answer %s that resolving the dependency's name failed temporarily"
	describeSlow     = "hold %s's lookup of the dependency for %s before answering correctly"
	describeWrong    = "answer %s that the dependency is at %s, an address nobody approved"
	describeChain    = "answer %s with a %d-hop CNAME ending outside the name it asked for"
	describeLoop     = "answer %s with a CNAME cycle"
	describeTrunc    = "answer %s over UDP with the truncation bit set, and completely over TCP"
	describeTruncNo  = "answer %s with the truncation bit set over UDP and refuse to complete over TCP either"
	describeTTLZero  = "answer %s correctly with a TTL of zero, so nothing may cache it"
	describeTTLLong  = "answer %s correctly with a TTL of %d seconds, so a cache pins it for a week"

	describeRefused = "answer %s REFUSED, which khaos cannot deliver"
	describeTimeout = "drop %s's query entirely, which khaos cannot deliver"

	describeUnknown = "an unrecognised DNS fault"
)

const (
	errUnknownKind = "%w: %q (known faults: %s)"
	errMasked      = "%w: %s"
	errDelayRange  = "%w: %s was asked for a %s delay, and the ceiling is %s"
	errNoHost      = "%w: %s needs the dependency's name, and none was given"
	errBadAddress  = "%w: %q is not an IP address"

	// maskedRefused and maskedTimeout are the refusals themselves. They name the
	// mechanism, what the target would actually have received, and what to ask
	// for instead, because a refusal that does not say what to do next is a dead
	// end rather than a diagnosis.
	maskedRefused = "Docker's embedded resolver rewrites REFUSED to SERVFAIL before the target sees it. `forwardExtDNS` treats REFUSED as a reason to try the next upstream, and with one upstream configured there is no next one, so the client is answered SERVFAIL. khaos will not deliver SERVFAIL and call it REFUSED, because a real library branches on the rcode and the branch is the finding. Run `dns.servfail` to measure the branch the target will actually take"

	maskedTimeout = "Docker's embedded resolver answers SERVFAIL at a measured 4.001s rather than letting a query go unanswered, so a true socket timeout cannot reach a container on a user-defined bridge. Its `extIOTimeout` is 4 seconds and the ceiling is not configurable. khaos will not deliver an rcode and call it a timeout. Run `dns.slow_response` with a delay under 4s for a late answer, or `dns.servfail` for the definite failure the target would really get"

	chainHops = 3
)

var ErrUnknownKind = errors.New("no DNS fault is registered under that name")

// ErrMasked is the refusal the M8 exit gate is about. It is a distinct error
// from an unknown fault, because the fault IS known, is catalogued, and is
// refused for a measured reason rather than missing.
var ErrMasked = errors.New(
	"khaos refuses this DNS fault because Docker's embedded resolver would rewrite it",
)

var ErrDelayRange = errors.New(
	"that delay is at or above the embedded resolver's ceiling, where this fault becomes a different one",
)

var ErrNoHost = errors.New("this DNS fault needs a name to act on")

var ErrBadAddress = errors.New("that is not an IP address")

// Trap is one armed fault, and it travels through the journal, so every field
// has to be enough to re-describe the fault from a cold start.
type Trap struct {
	Kind Kind   `json:"kind"`
	Host string `json:"host"`

	// Delay is SlowResponse's magnitude.
	Delay time.Duration `json:"delay,omitempty"`

	// Address is WrongAddress's answer.
	Address string `json:"address,omitempty"`

	// Inert is the negative control. An inert trap arms the resolver with
	// nothing, so every observable this fault is confirmed by must disappear.
	// Without it a confirmation that reads the trap RECORD rather than the
	// SERVED answer passes against a resolver that is doing nothing, which is
	// the bug the PKI tier's inert authority caught three times.
	Inert bool `json:"inert,omitempty"`
}

// Kinds names every fault in the catalogue, including the two khaos refuses, so
// a census over the catalogue covers them and cannot quietly lose one.
func Kinds() []string {
	return []string{
		string(NXDomain),
		string(ServFail),
		string(SlowResponse),
		string(WrongAddress),
		string(CNAMEChain),
		string(CNAMELoop),
		string(Truncation),
		string(TruncationNoTCP),
		string(TTLZero),
		string(TTLLong),
		string(Refused),
		string(Timeout),
	}
}

// Deliverable reports whether khaos can actually produce this fault as asked
// through Docker's embedded resolver. It is derived from one list so the
// catalogue, the refusal and the gate's census cannot disagree about which
// faults are masked.
func Deliverable(kind Kind) bool {
	return !slices.Contains(masked, kind)
}

var masked = []Kind{Refused, Timeout}

// MaskedReason is the refusal text for a fault khaos will not approximate.
func MaskedReason(kind Kind) string {
	switch kind {
	case Refused:
		return maskedRefused
	case Timeout:
		return maskedTimeout
	default:
		return ""
	}
}

// Known reports whether this is a catalogued fault at all, which is separate
// from whether it can be delivered.
func Known(kind Kind) bool {
	return kind == PassThrough || slices.Contains(Kinds(), string(kind))
}

// Describe says what the fault does to the target, in the operator's words. It
// is the only place the wording lives, so `khaos catalog`, `khaos plan` and the
// run record cannot describe the same fault three different ways.
func (t Trap) Describe(target string) string {
	switch t.Kind {
	case NXDomain:
		return fmt.Sprintf(describeNXDomain, target)
	case ServFail:
		return fmt.Sprintf(describeServFail, target)
	case SlowResponse:
		return fmt.Sprintf(describeSlow, target, t.delay())
	case WrongAddress:
		return fmt.Sprintf(describeWrong, target, t.address())
	case CNAMEChain:
		return fmt.Sprintf(describeChain, target, chainHops)
	case CNAMELoop:
		return fmt.Sprintf(describeLoop, target)
	case Truncation:
		return fmt.Sprintf(describeTrunc, target)
	case TruncationNoTCP:
		return fmt.Sprintf(describeTruncNo, target)
	case TTLZero:
		return fmt.Sprintf(describeTTLZero, target)
	case TTLLong:
		return fmt.Sprintf(describeTTLLong, target, LongTTL)
	case Refused:
		return fmt.Sprintf(describeRefused, target)
	case Timeout:
		return fmt.Sprintf(describeTimeout, target)
	case PassThrough:
		return describeUnknown
	default:
		return describeUnknown
	}
}

// Validate refuses a trap that cannot be armed, BEFORE it reaches the journal.
// A record khaos cannot arm is one `khaos reclaim` would retry forever, and a
// masked fault refused here is refused once with a reason rather than halfway
// through a run.
func (t Trap) Validate() error {
	if err := t.ValidateShape(); err != nil {
		return err
	}

	if !Deliverable(t.Kind) {
		return fmt.Errorf(errMasked, ErrMasked, MaskedReason(t.Kind))
	}

	return nil
}

// ValidateShape checks everything except whether khaos will deliver the fault at
// all, and the split exists because the two refusals belong at different moments.
//
// A delay above the ceiling is an operator typing a number, so it is refused
// here, at build time. A MASKED fault is not a mistake: it is a catalogued
// experiment whose answer is an explanation, so it has to build, plan and
// describe like any other entry, and Validate refuses it only when khaos is
// asked to arm one.
func (t Trap) ValidateShape() error {
	if !Known(t.Kind) {
		return fmt.Errorf(
			errUnknownKind,
			ErrUnknownKind,
			string(t.Kind),
			joinKinds(),
		)
	}

	if t.Kind == PassThrough {
		return nil
	}

	if t.Host == "" {
		return fmt.Errorf(errNoHost, ErrNoHost, string(t.Kind))
	}

	if t.Kind == SlowResponse && t.Delay > MaxDelay {
		return fmt.Errorf(
			errDelayRange,
			ErrDelayRange,
			string(t.Kind),
			t.Delay,
			MaxDelay,
		)
	}

	if t.Kind == WrongAddress && t.Address != "" {
		if err := validAddress(t.Address); err != nil {
			return err
		}
	}

	return nil
}

func (t Trap) delay() time.Duration {
	if t.Delay <= 0 {
		return DefaultDelay
	}
	return t.Delay
}

func (t Trap) address() string {
	if t.Address == "" {
		return DefaultWrongAddress
	}
	return t.Address
}

// ttl is the lifetime this trap puts on an answer it synthesizes. Every kind
// that answers at all goes through here, so a new kind cannot forget to carry
// one and serve a zero TTL by accident, which would look exactly like TTLZero.
func (t Trap) ttl() uint32 {
	switch t.Kind {
	case TTLZero:
		return 0
	case TTLLong:
		return LongTTL
	default:
		return HonestTTL
	}
}

func joinKinds() string {
	return joinWith(Kinds(), ", ")
}

func sorted(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return out
}
