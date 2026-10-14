// ©AngelaMos | 2026
// control_test.go

package dnsrv

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Every test in this file exists because a gutting pass deleted the mechanism it
// covers and the whole suite stayed green. They are the controls, not the
// features.

// TestArmValidates is the control for Arm's call to Validate.
//
// Deleting that call left the suite green: the masked-fault test called
// Validate directly, and the zone guard sits in Arm's own body, so nothing
// asserted that arming a trap validates it at all. The control surface reaches
// Arm from outside khaos, so a masked fault or an over-ceiling delay arriving
// there has to be refused by Arm itself and not by the caller remembering to
// check first.
func TestArmValidates(t *testing.T) {
	cases := []struct {
		name string
		trap Trap
		want error
	}{
		{
			name: "a masked fault",
			trap: Trap{Kind: Refused, Host: testHost},
			want: ErrMasked,
		},
		{
			name: "a delay above the measured ceiling",
			trap: Trap{
				Kind:  SlowResponse,
				Host:  testHost,
				Delay: 30 * time.Second,
			},
			want: ErrDelayRange,
		},
		{
			name: "an unknown fault",
			trap: Trap{Kind: "not-a-fault", Host: testHost},
			want: ErrUnknownKind,
		},
		{
			name: "a redirect to something that is not an address",
			trap: Trap{Kind: WrongAddress, Host: testHost, Address: "nope"},
			want: ErrBadAddress,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			resolver, client := startResolver(t)

			if err := resolver.Arm(test.trap); !errors.Is(err, test.want) {
				t.Errorf("Arm error %v, want %v", err, test.want)
			}

			if _, err := client.Arm(t.Context(), test.trap); err == nil {
				t.Error("the control surface armed a trap Arm must refuse")
			}
		})
	}
}

// TestObserveRefutesAgainstAForeignResolver is the control for Observe's
// control-name check.
//
// Deleting that check left the suite green, because a dead resolver also fails
// the fault-side query. The case it really guards is worse and quieter: khaos
// pointed at a resolver it never armed. A resolver that NXDOMAINs everything
// answers NXDOMAIN for the faulted name too, so without the control half khaos
// confirms a fault it did not inject and reports a finding about a resolver that
// was never part of the experiment.
func TestObserveRefutesAgainstAForeignResolver(t *testing.T) {
	foreign := testUpstreamServer(t)

	client := NewClient(foreign, "http://127.0.0.1:1", testNonce, testControl)

	observable, confirmed, err := client.Observe(trapFor(NXDomain))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}

	if confirmed {
		t.Fatalf("confirmed NXDOMAIN against a resolver khaos never armed: %s",
			observable)
	}
}

// TestTTLObservationRequiresADifference is the control for ttlObservation's
// control half.
//
// That arm was unreachable through the live resolver, because khaos always
// serves HonestTTL for the control name, so deleting it changed nothing. It
// encodes a real rule even so: the fault is a DIFFERENCE from what the same
// resolver serves for a name it is not faulting, and a zone that happened to
// serve a zero TTL would otherwise confirm TTLZero against a resolver with
// nothing armed.
func TestTTLObservationRequiresADifference(t *testing.T) {
	trap := Trap{Kind: TTLZero, Host: testHost}

	withTTL := func(ttl uint32) answer {
		record, err := dns.NewRR("x.test. 0 IN A 10.0.0.1")
		if err != nil {
			t.Fatalf("build record: %v", err)
		}
		record.Header().Ttl = ttl
		return answer{records: []dns.RR{record}}
	}

	_, confirmed, _ := ttlObservation(
		trap,
		withTTL(0),
		withTTL(HonestTTL),
		testControl,
	)
	if !confirmed {
		t.Error("did not confirm a zero TTL the control did not share")
	}

	_, confirmed, _ = ttlObservation(
		trap,
		withTTL(0),
		withTTL(0),
		testControl,
	)
	if confirmed {
		t.Error("confirmed a zero TTL where the CONTROL also carried zero, " +
			"which is not a difference and therefore not this fault")
	}
}

// TestTruncationObservablesRejectEachOthersAnswers is the control for the
// truncation arms.
//
// Both faults set the bit over UDP, so UDP alone cannot separate them and every
// arm that does lived behind a live resolver where deleting one went unnoticed.
// Driving the pure functions directly gives each arm an input it must reject.
func TestTruncationObservablesRejectEachOthersAnswers(t *testing.T) {
	resolved := func() answer {
		record, err := dns.NewRR("x.test. 600 IN A 10.0.0.1")
		if err != nil {
			t.Fatalf("build record: %v", err)
		}
		return answer{records: []dns.RR{record}}
	}

	completeTCP := resolved()
	truncatedEmptyTCP := answer{truncated: true}
	truncatedWithRecordsTCP := resolved()
	truncatedWithRecordsTCP.truncated = true
	unreachableTCP := answer{err: errors.New("connection refused")}
	servfailTCP := answer{rcode: dns.RcodeServerFailure}

	trap := Trap{Kind: Truncation, Host: testHost}
	noTCPTrap := Trap{Kind: TruncationNoTCP, Host: testHost}
	truncatedUDP := answer{truncated: true}
	plainUDP := resolved()

	cases := []struct {
		name    string
		confirm bool
		got     func() (string, bool, error)
	}{
		{
			name:    "truncation with a complete TCP answer confirms",
			confirm: true,
			got: func() (string, bool, error) {
				return truncObservation(trap, truncatedUDP, completeTCP)
			},
		},
		{
			name:    "truncation refutes an untruncated UDP answer",
			confirm: false,
			got: func() (string, bool, error) {
				return truncObservation(trap, plainUDP, completeTCP)
			},
		},
		{
			name:    "truncation refutes the no-TCP fault's TCP answer",
			confirm: false,
			got: func() (string, bool, error) {
				return truncObservation(trap, truncatedUDP, truncatedEmptyTCP)
			},
		},
		{
			name:    "truncation refutes an unreachable TCP path",
			confirm: false,
			got: func() (string, bool, error) {
				return truncObservation(trap, truncatedUDP, unreachableTCP)
			},
		},
		{
			name:    "no-TCP confirms a truncated empty TCP answer",
			confirm: true,
			got: func() (string, bool, error) {
				return truncNoTCPObservation(
					noTCPTrap, truncatedUDP, truncatedEmptyTCP,
				)
			},
		},
		{
			name:    "no-TCP refutes an unreachable TCP path",
			confirm: false,
			got: func() (string, bool, error) {
				return truncNoTCPObservation(
					noTCPTrap, truncatedUDP, unreachableTCP,
				)
			},
		},
		{
			name:    "no-TCP refutes a TCP answer that is not truncated",
			confirm: false,
			got: func() (string, bool, error) {
				return truncNoTCPObservation(
					noTCPTrap,
					truncatedUDP,
					servfailTCP,
				)
			},
		},
		{
			name:    "no-TCP refutes a truncated TCP answer that still resolves",
			confirm: false,
			got: func() (string, bool, error) {
				return truncNoTCPObservation(
					noTCPTrap, truncatedUDP, truncatedWithRecordsTCP,
				)
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			observable, confirmed, err := test.got()
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			if confirmed != test.confirm {
				t.Errorf("confirmed=%t, want %t: %s",
					confirmed, test.confirm, observable)
			}
		})
	}
}
