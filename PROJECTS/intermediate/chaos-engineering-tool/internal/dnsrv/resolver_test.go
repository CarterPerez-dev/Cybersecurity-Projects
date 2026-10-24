// ©AngelaMos | 2026
// resolver_test.go

package dnsrv

import (
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestUnarmedResolverIsIndistinguishable is the baseline guard. Every
// experiment's baseline is measured through this resolver, so an unarmed one
// answering anything other than the honest address would void every run before
// a fault was ever applied.
func TestUnarmedResolverIsIndistinguishable(t *testing.T) {
	_, client := startResolver(t)

	for _, name := range []string{testHost, testControl} {
		got := ask(t, client, name, udpNet)

		if !got.resolved() {
			t.Fatalf("%s did not resolve unarmed: rcode=%s err=%v",
				name, rcodeName(got.rcode), got.err)
		}

		if addresses := got.addresses(); !slices.Contains(
			addresses,
			testAddress,
		) {
			t.Errorf("%s answered %v, want %s", name, addresses, testAddress)
		}

		if got.truncated {
			t.Errorf("%s was truncated unarmed", name)
		}

		for _, ttl := range got.ttls() {
			if ttl != HonestTTL {
				t.Errorf("%s TTL %d, want %d", name, ttl, HonestTTL)
			}
		}
	}
}

// TestOutsideZoneIsForwarded proves the resolver does not break the target's
// unrelated name resolution. A chaos resolver that NXDOMAINed everything it was
// not authoritative for would be a dependency outage wearing a DNS fault's name.
func TestOutsideZoneIsForwarded(t *testing.T) {
	resolver, client := startResolver(t)

	mustArm(t, client, trapFor(NXDomain))

	got := ask(t, client, testUpstream, udpNet)

	if !got.resolved() {
		t.Fatalf("%s did not resolve through the forward path: rcode=%s err=%v",
			testUpstream, rcodeName(got.rcode), got.err)
	}

	if addresses := got.addresses(); !slices.Contains(addresses, testUpAddr) {
		t.Errorf("forwarded answer %v, want %s", addresses, testUpAddr)
	}

	if stats := resolver.Stats(); stats.Forward == 0 {
		t.Error("the resolver recorded no forwarded query")
	}
}

// TestSearchSuffixIsFaulted is the measured sharp edge, and the one most likely
// to be lost in a refactor.
//
// A container's resolv.conf carries a forced `search` domain. Under a negative
// fault the absolute query fails and the client RETRIES with the suffix
// appended, which was observed arriving as `<name>.mynetworksettings.com.`. A
// resolver matching only the exact name answers that retry honestly and defeats
// its own fault, and the run reports a target that resolved its dependency
// fine.
// The assertion is on the resolver's own FAULTED counter, not on the rcode, and
// that is the second half of the lesson. The first version checked for NXDOMAIN
// and passed with the suffix match deleted, because an unmatched name is
// forwarded and the test upstream answers NXDOMAIN for anything it does not
// know. The test was right about the behaviour and wrong about the cause, which
// is the failure mode the gutting pass exists to find.
func TestSearchSuffixIsFaulted(t *testing.T) {
	resolver, client := startResolver(t)

	mustArm(t, client, trapFor(NXDomain))

	suffixed := testHost + "mynetworksettings.com."

	before := resolver.Stats()
	got := ask(t, client, suffixed, udpNet)
	after := resolver.Stats()

	if after.Faulted-before.Faulted != 1 {
		t.Fatalf("search-suffixed %s was not faulted (faulted %d->%d, "+
			"forwarded %d->%d): the client's retry escaped the fault",
			suffixed,
			before.Faulted, after.Faulted,
			before.Forward, after.Forward,
		)
	}

	if got.rcode != dns.RcodeNameError {
		t.Errorf("search-suffixed %s answered %s, want NXDOMAIN",
			suffixed, rcodeName(got.rcode))
	}
}

func TestFaultsServeWhatTheyClaim(t *testing.T) {
	type check func(*testing.T, answer)

	hasRcode := func(want int) check {
		return func(t *testing.T, got answer) {
			if got.rcode != want {
				t.Errorf("rcode %s, want %s",
					rcodeName(got.rcode), rcodeName(want))
			}
		}
	}

	cases := []struct {
		kind  Kind
		trap  Trap
		check check
	}{
		{
			kind:  NXDomain,
			check: hasRcode(dns.RcodeNameError),
		},
		{
			kind:  ServFail,
			check: hasRcode(dns.RcodeServerFailure),
		},
		{
			kind: WrongAddress,
			trap: Trap{Address: "203.0.113.9"},
			check: func(t *testing.T, got answer) {
				if addresses := got.addresses(); !slices.Contains(
					addresses,
					"203.0.113.9",
				) {
					t.Errorf("addresses %v, want 203.0.113.9", addresses)
				}
				if slices.Contains(got.addresses(), testAddress) {
					t.Error("the honest address survived a redirect fault")
				}
			},
		},
		{
			kind: CNAMEChain,
			check: func(t *testing.T, got answer) {
				if hops := got.cnames(); len(hops) < chainMinimum {
					t.Errorf(
						"%d CNAME hops, want at least %d",
						len(hops),
						chainMinimum,
					)
				}
				if hasCycle(got.cnames()) {
					t.Error(
						"a chain must not be a cycle, or the two faults alibi each other",
					)
				}
			},
		},
		{
			kind: CNAMELoop,
			check: func(t *testing.T, got answer) {
				if !hasCycle(got.cnames()) {
					t.Errorf("CNAMEs %v do not form a cycle", got.cnames())
				}
			},
		},
		{
			kind: Truncation,
			check: func(t *testing.T, got answer) {
				if !got.truncated {
					t.Error("tc not set over UDP")
				}
				if len(got.addresses()) != 0 {
					t.Error(
						"a truncated UDP answer still carried records, so a " +
							"client ignoring tc is never tested",
					)
				}
			},
		},
		{
			kind: TruncationNoTCP,
			check: func(t *testing.T, got answer) {
				if !got.truncated {
					t.Error("tc not set over UDP")
				}
			},
		},
		{
			kind: TTLZero,
			check: func(t *testing.T, got answer) {
				for _, ttl := range got.ttls() {
					if ttl != 0 {
						t.Errorf("TTL %d, want 0", ttl)
					}
				}
				if len(got.addresses()) == 0 {
					t.Error(
						"a TTL fault must still resolve, or it is an outage",
					)
				}
			},
		},
		{
			kind: TTLLong,
			check: func(t *testing.T, got answer) {
				for _, ttl := range got.ttls() {
					if ttl != LongTTL {
						t.Errorf("TTL %d, want %d", ttl, LongTTL)
					}
				}
			},
		},
		{
			kind: SlowResponse,
			trap: Trap{Delay: 700 * time.Millisecond},
			check: func(t *testing.T, got answer) {
				if got.elapsed < 700*time.Millisecond {
					t.Errorf("answered in %s, want at least 700ms", got.elapsed)
				}
				if len(got.addresses()) == 0 {
					t.Error("a slow answer must still be the honest answer")
				}
			},
		},
	}

	for _, test := range cases {
		t.Run(string(test.kind), func(t *testing.T) {
			_, client := startResolver(t)

			trap := test.trap
			trap.Kind = test.kind
			trap.Host = testHost

			mustArm(t, client, trap)

			test.check(t, ask(t, client, testHost, udpNet))

			// The control is checked on every case rather than once, because a
			// resolver that crashed on arming would otherwise read as a fault
			// that landed for every kind in the table.
			if control := ask(
				t,
				client,
				testControl,
				udpNet,
			); !control.resolved() {
				t.Errorf(
					"the control name stopped resolving under %s: rcode=%s err=%v",
					test.kind,
					rcodeName(control.rcode),
					control.err,
				)
			}
		})
	}
}

// TestTruncationCompletesOverTCP and its sibling are what separate the two
// truncation faults. Both set tc over UDP, so UDP alone cannot tell them apart,
// and the difference is the whole finding: one tests whether the client makes
// the RFC 5966 retry, the other whether the retry is allowed off the network.
func TestTruncationCompletesOverTCP(t *testing.T) {
	_, client := startResolver(t)

	mustArm(t, client, trapFor(Truncation))

	overTCP := ask(t, client, testHost, tcpNet)

	if !overTCP.resolved() {
		t.Fatalf("TCP did not complete: rcode=%s truncated=%t err=%v",
			rcodeName(overTCP.rcode), overTCP.truncated, overTCP.err)
	}

	if overTCP.truncated {
		t.Error("the TCP answer was still truncated, which is the other fault")
	}
}

func TestTruncationNoTCPNeverCompletes(t *testing.T) {
	_, client := startResolver(t)

	mustArm(t, client, trapFor(TruncationNoTCP))

	overTCP := ask(t, client, testHost, tcpNet)

	if overTCP.resolved() {
		t.Fatalf("TCP completed with %v, so this is the other truncation fault",
			overTCP.addresses())
	}

	if !overTCP.truncated {
		t.Error("tc not set over TCP")
	}
}

// TestArrivalsAreAttributedBySource guards the proof-of-arrival control. A total
// counter is non-zero on every run, including the runs where the target never
// used khaos's resolver at all, because khaos's own confirmation queries land in
// it.
func TestArrivalsAreAttributedBySource(t *testing.T) {
	resolver, client := startResolver(t)

	before := resolver.Arrivals("127.0.0.1")

	ask(t, client, testHost, udpNet)
	ask(t, client, testHost, udpNet)

	after := resolver.Arrivals("127.0.0.1")

	if after-before != 2 {
		t.Errorf("recorded %d arrivals from 127.0.0.1, want 2", after-before)
	}

	if other := resolver.Arrivals("10.99.99.99"); other != 0 {
		t.Errorf("recorded %d arrivals from an address that never asked", other)
	}
}

func TestResolverRefusesConfigThatCannotWork(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want error
	}{
		{
			name: "upstream is itself",
			cfg: Config{
				Listen:   "10.0.0.5:53",
				Upstream: "10.0.0.5:53",
				Control:  testControl,
				Zone:     map[string]string{testControl: testAddress},
			},
			want: ErrUpstreamLoop,
		},
		{
			name: "empty zone",
			cfg:  Config{Listen: loopbackAny, Control: testControl},
			want: ErrEmptyZone,
		},
		{
			name: "zone entry is not an address",
			cfg: Config{
				Listen:  loopbackAny,
				Control: testControl,
				Zone:    map[string]string{testControl: "not-an-address"},
			},
			want: ErrZoneAddress,
		},
		{
			name: "no control name",
			cfg: Config{
				Listen: loopbackAny,
				Zone:   map[string]string{testHost: testAddress},
			},
			want: ErrNoControl,
		},
		{
			name: "control name is not in the zone",
			cfg: Config{
				Listen:  loopbackAny,
				Control: "somewhere.else.test.",
				Zone:    map[string]string{testHost: testAddress},
			},
			want: ErrNoControl,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.cfg)
			if err == nil {
				t.Fatal("accepted a config that cannot work")
			}
			if !is(err, test.want) {
				t.Errorf("error %v, want %v", err, test.want)
			}
		})
	}
}

// TestArmRefusesAnOutOfZoneHost is the guard against the quietest possible
// operator mistake: a fault aimed at a name khaos does not answer arms fine,
// every query for it is forwarded untouched, and the run reports a clean
// survival against a fault that was applied to nothing.
func TestArmRefusesAnOutOfZoneHost(t *testing.T) {
	resolver, _ := startResolver(t)

	err := resolver.Arm(Trap{Kind: NXDomain, Host: "not.in.the.zone.test."})
	if err == nil {
		t.Fatal("armed a fault on a name the resolver does not answer")
	}

	if !is(err, ErrOutsideZone) {
		t.Errorf("error %v, want %v", err, ErrOutsideZone)
	}
}

// TestArmRefusesFaultingTheControl stops the confirmation oracle's positive
// control from being the thing under fault, which would make every observation
// self-refuting.
func TestArmRefusesFaultingTheControl(t *testing.T) {
	resolver, _ := startResolver(t)

	err := resolver.Arm(Trap{Kind: NXDomain, Host: testControl})
	if err == nil {
		t.Fatal("armed a fault on the confirmation control")
	}

	if !is(err, ErrControlIsHost) {
		t.Errorf("error %v, want %v", err, ErrControlIsHost)
	}
}
