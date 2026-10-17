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
	// slowMargin is a differential against the control rather than an absolute
	// threshold, which would confirm a delay for free against any dependency
	// that is merely slow.
	slowMargin = 500 * time.Millisecond

	// chainMinimum is two because one CNAME is an ordinary alias; the fault is
	// the indirection.
	chainMinimum = 2

	unknownHonest = "the address it really has"
)

const (
	observeNXDomain = "answering NXDOMAIN for %s while still resolving %s"
	observeServFail = "answering SERVFAIL for %s while still resolving %s"
	observeSlow     = "answering %s correctly after %s, against %s for the control on the same resolver"
	observeWrong    = "answering %s with %v instead of %s"

	observeRotated = "%s now answers %v where the zone served %s before khaos moved it, from the resolver's own honest path rather than from a fault, so a target that asks again follows the rotation"
	observeChain   = "answering %s with a %d-hop CNAME ending at %s"
	observeLoop    = "answering %s with a CNAME cycle through %v"
	observeTrunc   = "setting the truncation bit for %s over UDP with an empty answer, and serving %v completely over TCP"
	observeTruncNo = "setting the truncation bit for %s with an empty answer over UDP and over TCP, so no transport ever completes"
	observeTTL     = "answering %s with a TTL of %d, against %d for %s on the same resolver"

	refuteControl          = "the control name %s did not resolve through this resolver (%v), so the resolver is broken rather than lying"
	refuteNoFault          = "%s still resolves to %v through this resolver, so nothing is armed against it"
	refuteRcode            = "%s answered %s rather than %s"
	refuteNotAuthoritative = "%s answered %s without the authoritative bit, so it came from khaos's own failure path rather than from the armed fault"
	refuteSlowUnanswered   = "%s was never answered at all (%v), which is an unresponsive resolver rather than a slow one; khaos cannot report a delay it did not receive"
	refuteSlowNotAnswer    = "%s answered %s with %d addresses, and this fault serves the HONEST answer late: a slow failure is a different fault"
	refuteSlowWrong        = "%s answered %v late instead of %s, so the answer was changed as well as delayed and this fault changes only the timing"
	refuteWrong            = "%s answered %v, which does not contain %s"
	refuteWrongIndirect    = "%s answered the right address through CNAMEs %v: that is the chain fault, not a direct redirect"
	refuteRotated          = "%s answered %v, which does not contain the address khaos rotated it to, %s"
	refuteRotatedUnknown   = "%s answered the rotated address and khaos holds no record of what the zone served before the move, so it cannot show a rotation happened rather than a name that always pointed there"
	refuteRotatedSame      = "%s answered %s both before and after the rotation, so nothing moved"
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

// Observe measures what the resolver actually SERVES, never the armed state.
// Every observation is TWO-SIDED: the faulted name must show the fault AND the
// control must keep resolving, because a crashed resolver answers nothing for
// either and that would read as a confirmed fault.
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

	case AddressRotated:
		return rotatedObservation(trap, faulted, c.honest(trap.Host))

	default:
		return refutation(refuteUnknown, string(trap.Kind))
	}
}

// rcodeObservation requires the rcode AND the authoritative bit: several paths
// in serveFault answer SERVFAIL, and only the armed fault sets AA.
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

// wrongObservation requires the wrong address DIRECTLY, with no CNAME in the
// reply. The chain fault ends at the same address, so without the hop check
// either fault would satisfy both observables.
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

	// The HONEST address, since naming the served address on both sides of
	// "instead of" states the same thing twice.
	if honest == "" {
		honest = unknownHonest
	}

	return fmt.Sprintf(observeWrong, trap.Host, addresses, honest), true, nil
}

// rotatedObservation is the rotation's own observable, and it is DISTINCT from
// wrong-address's on purpose: that one answers wrongly while the zone stays
// put, and this one moved the zone, so the honest path serves the new address
// too. Naming both addresses is what tells an operator which act khaos
// performed.
//
// The snapshot the client holds was taken before the fault, so it is the
// address the rotation replaced. Requiring the two to DIFFER is the read-back
// half of the confirmation: Rotate already refuses a move to the address a name
// already answers with, and this proves the resolver served the move.
func rotatedObservation(
	trap Trap,
	faulted answer,
	before string,
) (string, bool, error) {
	addresses := faulted.addresses()
	want := trap.address()

	if !slices.Contains(addresses, want) {
		return refutation(refuteRotated, trap.Host, addresses, want)
	}

	if hops := faulted.cnames(); len(hops) > 0 {
		return refutation(refuteWrongIndirect, trap.Host, hops)
	}

	if before == "" {
		return refutation(refuteRotatedUnknown, trap.Host)
	}

	if before == want {
		return refutation(refuteRotatedSame, trap.Host, want)
	}

	return fmt.Sprintf(
		observeRotated,
		trap.Host,
		addresses,
		before,
	), true, nil
}

func (c *Client) honest(host string) string {
	if c.Zone == nil {
		return ""
	}

	return c.Zone[dns.CanonicalName(host)]
}

// chainObservation requires hops that do NOT cycle. A loop answers the same
// number of hops, and the chain's claim is indirection that ENDS somewhere.
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
// which a chain has too.
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

// slowObservation requires the slow answer to be an ANSWER, and the honest one.
// `miekg/dns` does not retry, so one dropped datagram elapses the full
// probeTimeout and would read as a served delay.
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

// truncObservation needs BOTH halves: a truncated UDP answer alone does not
// distinguish this fault from TruncationNoTCP, which asks whether the retry is
// allowed to leave the network rather than whether the client makes it.
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
// path that produced no answer: an unreachable TCP path is a different finding.
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
// on the control, since a zone that happens to serve a zero TTL would otherwise
// confirm TTLZero against a resolver with nothing armed.
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
