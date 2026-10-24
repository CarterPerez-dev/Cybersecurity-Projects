// ©AngelaMos | 2026
// trap.go

package dnsrv

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Kind names one way khaos makes resolution wrong. The dependency stays
// healthy: the target cannot find it, or finds something else.
type Kind string

const (
	// The zero value forwards, so an unarmed resolver is indistinguishable
	// from the one the target would otherwise use.
	PassThrough Kind = ""

	// A definite negative answer: the client stops immediately and a Go target
	// gets `IsNotFound`.
	NXDomain Kind = "nxdomain"

	// A TEMPORARY failure, so clients with retry logic retry it.
	ServFail Kind = "servfail"

	// Correct but late. Docker's embedded resolver gives up at 4.001s, so a
	// larger magnitude would silently become Timeout and is refused instead.
	SlowResponse Kind = "slow-response"

	// Resolves to an address nobody approved, so a hostname allowlist actively
	// authorises the wrong host.
	WrongAddress Kind = "wrong-address"

	// A multi-hop CNAME ending outside the queried zone, which separates
	// matching on the asked name from matching on the reached one.
	CNAMEChain Kind = "cname-chain"

	// A CNAME cycle. The server serves it without hanging; the CLIENT's loop
	// handling is what is under test.
	CNAMELoop Kind = "cname-loop"

	// Sets `tc` on UDP and answers completely over TCP, so the client must
	// notice and re-ask over TCP per RFC 5966.
	Truncation Kind = "truncation"

	// Sets `tc` and never completes over TCP either, asking whether DNS over
	// TCP is permitted at all. To a Go target this lands as `no such host` with
	// `IsNotFound=true`, which is NXDomain's classification.
	TruncationNoTCP Kind = "truncation-no-tcp"

	// Act on the answer's lifetime rather than its content. Go has no answer
	// cache and ignores TTL, so khaos counts the target's own queries and
	// reports UNSUPPORTED instead of guessing.
	TTLZero Kind = "ttl-zero"
	TTLLong Kind = "ttl-long"

	AddressRotated Kind = "address-rotated"

	// REFUSED BY KHAOS: the embedded resolver rewrites both to SERVFAIL, and a
	// real library branches on the rcode, so delivering one under its own name
	// would be a wrong measurement rather than a fault.
	Refused Kind = "refused"
	Timeout Kind = "timeout"
)

const (
	// One millisecond under the embedded resolver's ceiling, above which it
	// answers SERVFAIL itself and the delay never reaches the client.
	MaxDelay = 3999 * time.Millisecond

	DefaultDelay = 3 * time.Second

	LongTTL = 604800

	// Matches the TTL Docker's embedded resolver puts on its own answers, so a
	// target comparing them sees nothing unusual.
	HonestTTL = 600

	// In TEST-NET-2, reserved by RFC 5737, so nothing can be running there.
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

	describeRotated = "MOVE %s's dependency to %s in the zone itself, the way an operator performs a DNS failover or an endpoint revocation, and measure whether the change reaches it at all"

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
	errNoRotation  = "%w: %s needs the address to move the name TO; a rotation with no destination is not a rotation"
	errNotV4       = "%w: %q is an IPv6 address, and this resolver answers the A queries khaos's probes send; an IPv6 answer to an A query is an empty NOERROR, so khaos would serve nothing while reporting that it armed a redirect"

	// Each names the mechanism, what the target would really have received, and
	// what to ask for instead.
	maskedRefused = "Docker's embedded resolver rewrites REFUSED to SERVFAIL before the target sees it. `forwardExtDNS` treats REFUSED as a reason to try the next upstream, and with one upstream configured there is no next one, so the client is answered SERVFAIL. khaos will not deliver SERVFAIL and call it REFUSED, because a real library branches on the rcode and the branch is the finding. Run `dns.servfail` to measure the branch the target will actually take"

	maskedTimeout = "Docker's embedded resolver answers SERVFAIL at a measured 4.001s rather than letting a query go unanswered, so a true socket timeout cannot reach a container on a user-defined bridge. Its `extIOTimeout` is 4 seconds and the ceiling is not configurable. khaos will not deliver an rcode and call it a timeout. Run `dns.slow_response` with a delay under 4s for a late answer, or `dns.servfail` for the definite failure the target would really get"

	chainHops = 3
)

var ErrUnknownKind = errors.New("no DNS fault is registered under that name")

// ErrMasked is distinct from an unknown fault: the fault IS catalogued.
var ErrMasked = errors.New(
	"khaos refuses this DNS fault because Docker's embedded resolver would rewrite it",
)

var ErrDelayRange = errors.New(
	"that delay is at or above the embedded resolver's ceiling, where this fault becomes a different one",
)

var ErrNoHost = errors.New("this DNS fault needs a name to act on")

var ErrNoRotation = errors.New(
	"a rotation needs the address it moves the name to",
)

var ErrBadAddress = errors.New("that is not an IP address")

// Trap travels through the journal, so every field has to be enough to
// re-describe the fault from a cold start.
type Trap struct {
	Kind Kind   `json:"kind"`
	Host string `json:"host"`

	// Delay is SlowResponse's magnitude.
	Delay time.Duration `json:"delay,omitempty"`

	// Address is WrongAddress's answer.
	Address string `json:"address,omitempty"`

	// An inert trap arms nothing, so every observable must disappear.
	Inert bool `json:"inert,omitempty"`
}

// Kinds names every fault in the catalogue, including the two khaos refuses.
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
		string(AddressRotated),
		string(Refused),
		string(Timeout),
	}
}

// Deliverable reports whether khaos can produce this fault as asked.
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

// Known reports whether this is a catalogued fault, separate from deliverable.
func Known(kind Kind) bool {
	return kind == PassThrough || slices.Contains(Kinds(), string(kind))
}

// Describe is the only place the operator-facing wording lives.
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
	case AddressRotated:
		return fmt.Sprintf(describeRotated, target, t.address())
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

// Validate refuses a trap that cannot be armed, BEFORE the journal sees it.
func (t Trap) Validate() error {
	if err := t.ValidateShape(); err != nil {
		return err
	}

	if !Deliverable(t.Kind) {
		return fmt.Errorf(errMasked, ErrMasked, MaskedReason(t.Kind))
	}

	return nil
}

// ValidateShape skips deliverability, because a masked fault still has to
// build, plan and describe like any other entry.
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

	// A rotation needs its destination at SHAPE time rather than defaulting to
	// one, because moving a name to an address khaos chose for it is not an
	// operational act anybody performs.
	if t.Kind == AddressRotated {
		if t.Address == "" {
			return fmt.Errorf(errNoRotation, ErrNoRotation, string(t.Kind))
		}

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

// ttl routes every kind that answers, so a new one cannot serve a zero TTL by
// accident and look exactly like TTLZero.
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
