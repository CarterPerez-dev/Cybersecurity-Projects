// ©AngelaMos | 2026
// observe.go

package dnsrv

import (
	"fmt"
	"slices"
	"time"

	"github.com/miekg/dns"
)

const (
	// slowMargin is how much slower the faulted name has to be than the control
	// before khaos will call a delay confirmed. It is a differential rather than
	// an absolute threshold, which is the proxy tier's most expensive lesson
	// restated: an absolute threshold confirms `hang` or `latency` for free
	// against any dependency that is simply slow.
	slowMargin = 500 * time.Millisecond

	// chainMinimum is how many CNAME hops have to be present before a chain is
	// a chain. One CNAME is an ordinary alias and every second zone has them;
	// the fault is the indirection, so two is the floor.
	chainMinimum = 2

	// unknownHonest stands in when khaos has not read the resolver's zone back.
	// It is named rather than blank so a reader can tell a missing read-back from
	// an address that happens to be empty.
	unknownHonest = "the address it really has"
)

const (
	observeNXDomain = "answering NXDOMAIN for %s while still resolving %s"
	observeServFail = "answering SERVFAIL for %s while still resolving %s"
	observeSlow     = "answering %s correctly after %s, against %s for the control on the same resolver"
	observeWrong    = "answering %s with %v instead of %s"
	observeChain    = "answering %s with a %d-hop CNAME ending at %s"
	observeLoop     = "answering %s with a CNAME cycle through %v"
	observeTrunc    = "setting the truncation bit for %s over UDP with an empty answer, and serving %v completely over TCP"
	observeTruncNo  = "setting the truncation bit for %s with an empty answer over UDP and over TCP, so no transport ever completes"
	observeTTL      = "answering %s with a TTL of %d, against %d for %s on the same resolver"

	refuteControl          = "the control name %s did not resolve through this resolver (%v), so the resolver is broken rather than lying"
	refuteNoFault          = "%s still resolves to %v through this resolver, so nothing is armed against it"
	refuteRcode            = "%s answered %s rather than %s"
	refuteNotAuthoritative = "%s answered %s without the authoritative bit, so it came from khaos's own failure path rather than from the armed fault"
	refuteSlowUnanswered   = "%s was never answered at all (%v), which is an unresponsive resolver rather than a slow one; khaos cannot report a delay it did not receive"
	refuteSlowNotAnswer    = "%s answered %s with %d addresses, and this fault serves the HONEST answer late: a slow failure is a different fault"
	refuteSlowWrong        = "%s answered %v late instead of %s, so the answer was changed as well as delayed and this fault changes only the timing"
	refuteWrong            = "%s answered %v, which does not contain %s"
	refuteWrongIndirect    = "%s answered the right address through CNAMEs %v: that is the chain fault, not a direct redirect"
	refuteChain            = "%s answered %d CNAME hops, and a chain needs %d"
	refuteChainCycle       = "%s answered CNAMEs %v, which cycle: that is the loop fault, not a chain"
	refuteTruncReach       = "%s could not be reached over TCP at all (%v), which is an unreachable resolver rather than one that truncates on both transports"
	refuteLoop             = "%s answered CNAMEs %v, which do not form a cycle"
	refuteSlow             = "%s answered in %s against the control's %s, a difference under the %s margin"
	refuteTruncUDP         = "%s was not truncated over UDP"
	refuteTruncTCP         = "%s was %s over TCP, and this fault requires the opposite"
	refuteTTL              = "%s answered TTLs %v, and this fault serves %d"
	refuteUnknown          = "no observable is defined for %q, so it cannot be confirmed"
	refuteMasked           = "%s is a fault khaos refuses to deliver, so there is nothing to confirm"
)

// Observe measures what the resolver actually SERVES and reports the observable
// alongside the verdict. It never reads the armed state back.
//
// That distinction is the whole design of this function. A state echo from
// /arm says which branch was chosen, not what a target would receive, and the
// PKI tier's inert-authority control caught fifteen traps confirming themselves
// off exactly that kind of read-back. Here the resolver is asked the same
// question the target asks, over the same transports, and the answer is the
// evidence.
//
// Every observation is TWO-SIDED. The faulted name has to show the fault AND
// the control name has to keep resolving, because those two failures look
// identical from one query: a resolver that has crashed answers nothing for
// both, and calling that a confirmed NXDOMAIN fault would be a finding
// manufactured out of khaos's own breakage.
func (c *Client) Observe(trap Trap) (string, bool, error) {
	if !Deliverable(trap.Kind) {
		return "", false, fmt.Errorf(
			errMasked,
			ErrMasked,
			fmt.Sprintf(refuteMasked, string(trap.Kind)),
		)
	}

	control := c.ask(c.ControlName, udpNet)
	if !control.resolved() {
		return refutation(
			refuteControl,
			c.ControlName,
			controlDetail(control),
		)
	}

	faulted := c.ask(trap.Host, udpNet)

	switch trap.Kind {
	case NXDomain:
		return rcodeObservation(
			trap, faulted, dns.RcodeNameError, observeNXDomain, c.ControlName,
		)

	case ServFail:
		return rcodeObservation(
			trap,
			faulted,
			dns.RcodeServerFailure,
			observeServFail,
			c.ControlName,
		)

	case WrongAddress:
		return wrongObservation(trap, faulted, c.honest(trap.Host))

	case CNAMEChain:
		return chainObservation(trap, faulted)

	case CNAMELoop:
		return loopObservation(trap, faulted)

	case SlowResponse:
		return slowObservation(trap, faulted, control, c.honest(trap.Host))

	case Truncation:
		return truncObservation(trap, faulted, c.ask(trap.Host, tcpNet))

	case TruncationNoTCP:
		return truncNoTCPObservation(trap, faulted, c.ask(trap.Host, tcpNet))

	case TTLZero, TTLLong:
		return ttlObservation(trap, faulted, control, c.ControlName)

	default:
		return refutation(refuteUnknown, string(trap.Kind))
	}
}

// rcodeObservation requires the rcode AND the authoritative bit.
//
// AA is what separates the armed fault from khaos's own breakage. Five paths in
// serveFault answer SERVFAIL — the armed arm, the unreachable-kind arm, the
// default, a record-building failure and a forwarding failure — so deleting
// `case ServFail:` fell through to `default`, served the same rcode, and left
// every test and the whole gate green. khaos IS authoritative for a name in its
// own zone, so the fault sets AA and the failure paths do not, which makes the
// two distinguishable from the outside by exactly the thing that differs.
func rcodeObservation(
	trap Trap,
	faulted answer,
	want int,
	observed string,
	controlName string,
) (string, bool, error) {
	if faulted.err != nil {
		return refutation(refuteRcode, trap.Host, faulted.err, rcodeName(want))
	}

	if faulted.rcode != want {
		return refutation(
			refuteRcode,
			trap.Host,
			rcodeName(faulted.rcode),
			rcodeName(want),
		)
	}

	if !faulted.authoritative {
		return refutation(refuteNotAuthoritative, trap.Host, rcodeName(want))
	}

	return fmt.Sprintf(observed, trap.Host, controlName), true, nil
}

// wrongObservation requires the wrong address to be answered DIRECTLY, with no
// CNAME in the reply, and the isolation control is what forced that too.
//
// Once the chain fault was made to end at the same address — which it has to, or
// the indirection goes nowhere and there is nothing for a control to have failed
// to notice — its final A record satisfied this observable and the two faults
// alibi each other again. The claims really are different: this one is "the name
// resolves somewhere else", and the chain's is "the name resolves somewhere else
// THROUGH indirection that defeats matching on the name you asked for".
func wrongObservation(
	trap Trap,
	faulted answer,
	honest string,
) (string, bool, error) {
	addresses := faulted.addresses()
	want := trap.address()

	if !slices.Contains(addresses, want) {
		return refutation(refuteWrong, trap.Host, addresses, want)
	}

	if hops := faulted.cnames(); len(hops) > 0 {
		return refutation(refuteWrongIndirect, trap.Host, hops)
	}

	// The HONEST address, not the one khaos was told to serve. Naming the served
	// address on both sides of "instead of" states the same thing twice and
	// tells a reader nothing about what was replaced.
	if honest == "" {
		honest = unknownHonest
	}

	return fmt.Sprintf(observeWrong, trap.Host, addresses, honest), true, nil
}

// honest reports the address this resolver really serves for a name, read back
// from the resolver rather than assumed.
func (c *Client) honest(host string) string {
	if c.Zone == nil {
		return ""
	}

	return c.Zone[dns.CanonicalName(host)]
}

// chainObservation requires hops that do NOT cycle, and the isolation control
// is what forced that.
//
// A loop also has three CNAME hops, so a hop count alone confirmed CNAMELoop's
// answer as a chain. Two observables that accept the same reply alibi each
// other: gut whichever one builds the records and the other's control stays
// green. The chain's claim is indirection ENDING somewhere, so it has to reject
// indirection that goes nowhere.
func chainObservation(trap Trap, faulted answer) (string, bool, error) {
	hops := faulted.cnames()
	if len(hops) < chainMinimum {
		return refutation(refuteChain, trap.Host, len(hops), chainMinimum)
	}

	if hasCycle(hops) {
		return refutation(refuteChainCycle, trap.Host, hops)
	}

	return fmt.Sprintf(
		observeChain,
		trap.Host,
		len(hops),
		hops[len(hops)-1],
	), true, nil
}

// loopObservation requires an actual cycle rather than merely several hops,
// because a chain also has several hops and the two faults would then alibi
// each other: gut whichever one produces the records and the other's control
// still passes.
func loopObservation(trap Trap, faulted answer) (string, bool, error) {
	hops := faulted.cnames()

	if !hasCycle(hops) {
		return refutation(refuteLoop, trap.Host, hops)
	}

	return fmt.Sprintf(observeLoop, trap.Host, hops), true, nil
}

func hasCycle(hops []string) bool {
	seen := make(map[string]bool, len(hops))
	for _, hop := range hops {
		if seen[hop] {
			return true
		}
		seen[hop] = true
	}
	return false
}

// slowObservation requires the slow answer to be an ANSWER, and the first
// version did not.
//
// It was the only observable in this file that never looked at `faulted.err` or
// `faulted.resolved()`. `ask` records a failure as `answer{elapsed, err}` and
// `probeTimeout` is 10s, and `miekg/dns` Client.Exchange is one dial, one write,
// one read with no retry — so a single dropped UDP datagram on khaos's own
// confirmation query produced `elapsed ≈ 10s` with a non-nil error and this
// returned CONFIRMED, wording it as "answering <name> after 10s". khaos had
// received nothing. It then measured a full fault window and attributed what it
// saw to a delay it could not prove was served.
//
// Every sibling already failed safe on exactly this — both truncation arms
// refute an unreachable TCP path BY NAME. The lesson was written in this file
// and not applied to the UDP case.
//
// The honest-address check is the second half. The kind promises an answer that
// is "correct but late", so a slow NXDOMAIN or a slow redirect satisfied the old
// predicate and the report said it answered correctly. The ordered cross-product
// cannot catch that, because it only ever confronts this fault with faults that
// are FAST.
func slowObservation(
	trap Trap,
	faulted answer,
	control answer,
	honest string,
) (string, bool, error) {
	if faulted.err != nil {
		return refutation(refuteSlowUnanswered, trap.Host, faulted.err)
	}

	if !faulted.resolved() {
		return refutation(
			refuteSlowNotAnswer,
			trap.Host,
			rcodeName(faulted.rcode),
			len(faulted.addresses()),
		)
	}

	if honest != "" && !slices.Contains(faulted.addresses(), honest) {
		return refutation(
			refuteSlowWrong,
			trap.Host,
			faulted.addresses(),
			honest,
		)
	}

	if faulted.elapsed-control.elapsed < slowMargin {
		return refutation(
			refuteSlow,
			trap.Host,
			faulted.elapsed.Round(time.Millisecond),
			control.elapsed.Round(time.Millisecond),
			slowMargin,
		)
	}

	return fmt.Sprintf(
		observeSlow,
		trap.Host,
		faulted.elapsed.Round(time.Millisecond),
		control.elapsed.Round(time.Millisecond),
	), true, nil
}

// truncObservation needs BOTH halves. A truncated UDP answer alone does not
// distinguish this fault from TruncationNoTCP, and the difference between them
// is the entire point: one tests whether the client makes the RFC 5966 retry,
// the other tests whether the retry is permitted to leave the network.
//
// The decision is split from the measuring so each arm has a control. Every arm
// below was reachable only through a live resolver before, and the gutting pass
// showed what that costs: deleting one left the whole suite green.
func truncObservation(
	trap Trap,
	overUDP answer,
	overTCP answer,
) (string, bool, error) {
	if !overUDP.truncated {
		return refutation(refuteTruncUDP, trap.Host)
	}

	if overTCP.err != nil {
		return refutation(refuteTruncReach, trap.Host, overTCP.err)
	}

	if overTCP.truncated {
		return refutation(refuteTruncTCP, trap.Host, "also truncated")
	}

	if !overTCP.resolved() {
		return refutation(
			refuteTruncTCP,
			trap.Host,
			"not answered completely",
		)
	}

	return fmt.Sprintf(
		observeTrunc,
		trap.Host,
		overTCP.addresses(),
	), true, nil
}

// truncNoTCPObservation requires the truncation bit ON TCP, not merely a TCP
// path that produced no answer. "The resolver truncates on both transports" and
// "TCP is unreachable" are different findings and only the first is this fault.
func truncNoTCPObservation(
	trap Trap,
	overUDP answer,
	overTCP answer,
) (string, bool, error) {
	if !overUDP.truncated {
		return refutation(refuteTruncUDP, trap.Host)
	}

	if overTCP.err != nil {
		return refutation(refuteTruncReach, trap.Host, overTCP.err)
	}

	if !overTCP.truncated {
		return refutation(refuteTruncTCP, trap.Host, "not truncated")
	}

	if overTCP.resolved() {
		return refutation(refuteTruncTCP, trap.Host, "answered completely")
	}

	return fmt.Sprintf(observeTruncNo, trap.Host), true, nil
}

// ttlObservation requires the armed TTL on the faulted name AND a different one
// on the control.
//
// The control half is load-bearing rather than decorative. A zone that happens
// to serve a zero TTL would confirm TTLZero against a resolver with nothing
// armed, so the fault has to be a DIFFERENCE from what the same resolver serves
// for a name it is not faulting.
func ttlObservation(
	trap Trap,
	faulted answer,
	control answer,
	controlName string,
) (string, bool, error) {
	want := trap.ttl()
	ttls := faulted.ttls()

	if len(ttls) == 0 || !allEqual(ttls, want) {
		return refutation(refuteTTL, trap.Host, ttls, want)
	}

	controlTTLs := control.ttls()
	if len(controlTTLs) > 0 && allEqual(controlTTLs, want) {
		return refutation(refuteTTL, controlName, controlTTLs, want)
	}

	return fmt.Sprintf(
		observeTTL,
		trap.Host,
		want,
		firstTTL(controlTTLs),
		controlName,
	), true, nil
}

func allEqual(values []uint32, want uint32) bool {
	for _, value := range values {
		if value != want {
			return false
		}
	}
	return len(values) > 0
}

func firstTTL(values []uint32) uint32 {
	if len(values) == 0 {
		return 0
	}
	return values[0]
}

func refutation(format string, args ...any) (string, bool, error) {
	return fmt.Sprintf(format, args...), false, nil
}

func controlDetail(control answer) any {
	if control.err != nil {
		return control.err
	}
	return rcodeName(control.rcode)
}

func rcodeName(rcode int) string {
	if name, ok := dns.RcodeToString[rcode]; ok {
		return name
	}
	return fmt.Sprint(rcode)
}
