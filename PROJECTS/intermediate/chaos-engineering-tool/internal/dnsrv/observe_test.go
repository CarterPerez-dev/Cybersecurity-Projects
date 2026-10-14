// ©AngelaMos | 2026
// observe_test.go

package dnsrv

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func is(err, target error) bool {
	return errors.Is(err, target)
}

func contains(text, substring string) bool {
	return strings.Contains(text, substring)
}

// TestEveryDeliverableFaultConfirms is the positive half. It iterates the
// catalogue rather than a hand-written list, so a new fault with no observable
// fails here instead of shipping as a fault that cannot be confirmed.
func TestEveryDeliverableFaultConfirms(t *testing.T) {
	for _, kind := range deliverableKinds() {
		t.Run(string(kind), func(t *testing.T) {
			_, client := startResolver(t)

			trap := trapFor(kind)
			mustArm(t, client, trap)

			observable, confirmed, err := client.Observe(trap)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}

			if !confirmed {
				t.Fatalf("%s did not confirm: %s", kind, observable)
			}

			if observable == "" {
				t.Error("confirmed with no observable, so the run record has " +
					"nothing a reader can audit")
			}
		})
	}
}

// TestInertResolverConfirmsNothing is the negative control, and it is the
// control that matters most in this package.
//
// An inert trap arms the resolver with a fault it then does not apply, so every
// observable has to disappear. Without this, a confirmation that read the armed
// STATE back rather than the served answer would pass against a resolver doing
// nothing at all — which is precisely the bug the PKI tier's inert-authority
// control caught three separate times, each one a trap reading the trap record
// instead of built state.
func TestInertResolverConfirmsNothing(t *testing.T) {
	for _, kind := range deliverableKinds() {
		t.Run(string(kind), func(t *testing.T) {
			_, client := startResolver(t)

			trap := trapFor(kind)
			trap.Inert = true
			mustArm(t, client, trap)

			observable, confirmed, err := client.Observe(trap)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}

			if confirmed {
				t.Fatalf("%s confirmed against an INERT resolver: %s",
					kind, observable)
			}
		})
	}
}

// TestNothingArmedConfirmsNothing is the second half of the negative control.
// Inert exercises the arming path with the mutation suppressed; this exercises
// no arming at all, which is the state a run is in during its baseline.
func TestNothingArmedConfirmsNothing(t *testing.T) {
	for _, kind := range deliverableKinds() {
		t.Run(string(kind), func(t *testing.T) {
			_, client := startResolver(t)

			observable, confirmed, err := client.Observe(trapFor(kind))
			if err != nil {
				t.Fatalf("observe: %v", err)
			}

			if confirmed {
				t.Fatalf(
					"%s confirmed with nothing armed: %s",
					kind,
					observable,
				)
			}
		})
	}
}

// TestObservingAWrongFaultRefutes is the isolation control: each fault's
// observable must reject the OTHER faults' answers.
//
// Two checks that both accept the same input alibi each other, so gutting
// either leaves the suite green. Here the resolver really serves fault A while
// khaos asks whether fault B is confirmed, for every ordered pair, and the
// answer has to be no.
func TestObservingAWrongFaultRefutes(t *testing.T) {
	kinds := deliverableKinds()

	for _, armedKind := range kinds {
		for _, askedKind := range kinds {
			if armedKind == askedKind {
				continue
			}

			name := string(armedKind) + "-asked-as-" + string(askedKind)

			t.Run(name, func(t *testing.T) {
				_, client := startResolver(t)

				mustArm(t, client, trapFor(armedKind))

				observable, confirmed, err := client.Observe(trapFor(askedKind))
				if err != nil {
					t.Fatalf("observe: %v", err)
				}

				if confirmed {
					t.Fatalf(
						"a resolver serving %s confirmed %s: %s",
						armedKind, askedKind, observable,
					)
				}
			})
		}
	}
}

// TestObserveRefutesWhenTheControlIsBroken proves the oracle is two-sided. A
// resolver that has stopped answering altogether looks exactly like a confirmed
// negative fault from one query, and reporting that as a finding would
// manufacture a defect out of khaos's own breakage.
func TestObserveRefutesWhenTheControlIsBroken(t *testing.T) {
	resolver, client := startResolver(t)

	mustArm(t, client, trapFor(NXDomain))

	if _, confirmed, err := client.Observe(trapFor(NXDomain)); err != nil ||
		!confirmed {
		t.Fatalf("precondition: NXDOMAIN should confirm first (err=%v)", err)
	}

	if err := resolver.Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	observable, confirmed, err := client.Observe(trapFor(NXDomain))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}

	if confirmed {
		t.Fatalf("confirmed a fault against a DEAD resolver: %s", observable)
	}
}

func TestObserveRefusesAMaskedFault(t *testing.T) {
	_, client := startResolver(t)

	for _, kind := range []Kind{Refused, Timeout} {
		t.Run(string(kind), func(t *testing.T) {
			_, _, err := client.Observe(Trap{Kind: kind, Host: testHost})
			if err == nil {
				t.Fatal("observed a fault khaos refuses to deliver")
			}

			if !is(err, ErrMasked) {
				t.Errorf("error %v, want %v", err, ErrMasked)
			}
		})
	}
}

// TestControlSurfaceRefusesTheWrongNonce matters because the resolver shares a
// network with the target. The nonce is the only thing stopping the target from
// disarming the fault being measured on it.
func TestControlSurfaceRefusesTheWrongNonce(t *testing.T) {
	resolver, client := startResolver(t)

	mustArm(t, client, trapFor(NXDomain))

	imposter := NewClient(
		resolver.Addr(),
		"http://"+resolver.ControlAddr(),
		"wrong-nonce",
		testControl,
	)

	if _, err := imposter.Disarm(t.Context()); err == nil {
		t.Fatal("a wrong nonce disarmed the fault")
	}

	if _, confirmed, err := client.Observe(trapFor(NXDomain)); err != nil ||
		!confirmed {
		t.Errorf("the fault did not survive the refused disarm (err=%v)", err)
	}

	if denied := resolver.Stats().Denied; denied == 0 {
		t.Error("a refused control request was not counted, so khaos has no " +
			"evidence it happened")
	}
}

// TestHealthNeedsNoNonce is deliberate: khaos has to be able to wait for the
// container to come up before it has read the nonce back out of it.
func TestHealthNeedsNoNonce(t *testing.T) {
	resolver, _ := startResolver(t)

	anonymous := NewClient(
		resolver.Addr(),
		"http://"+resolver.ControlAddr(),
		"",
		testControl,
	)

	if !anonymous.Healthy(t.Context()) {
		t.Fatal("health needed a nonce")
	}
}

// TestHealthLeaksNothingAboutTheFault checks the other side of that decision.
// The target can reach this surface, so an unauthenticated endpoint must not
// tell it which fault is armed.
func TestHealthLeaksNothingAboutTheFault(t *testing.T) {
	resolver, client := startResolver(t)

	mustArm(t, client, trapFor(WrongAddress))

	response, err := http.Get("http://" + resolver.ControlAddr() + PathHealthz)
	if err != nil {
		t.Fatalf("get health: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	body := make([]byte, controlBodyLimit)
	n, _ := response.Body.Read(body)
	text := string(body[:n])

	for _, leak := range []string{
		string(WrongAddress), DefaultWrongAddress, testNonce,
	} {
		if contains(text, leak) {
			t.Errorf("health leaked %q: %s", leak, text)
		}
	}
}

// TestDisarmRestoresTheHonestAnswer is the revert path. The recovery phase is
// measured through a WORKING resolver, so a disarm that left the fault in place
// would score the recovery window against a target still under fault.
func TestDisarmRestoresTheHonestAnswer(t *testing.T) {
	_, client := startResolver(t)

	mustArm(t, client, trapFor(NXDomain))

	if _, err := client.Disarm(t.Context()); err != nil {
		t.Fatalf("disarm: %v", err)
	}

	got := ask(t, client, testHost, udpNet)
	if !got.resolved() {
		t.Fatalf("%s did not resolve after disarm: rcode=%s err=%v",
			testHost, rcodeName(got.rcode), got.err)
	}
}

// TestSlowObservationIsADifferential is the proxy tier's lesson applied here. An
// absolute threshold confirms a delay for free against any resolver that is
// simply slow, so the observable has to be a DIFFERENCE from the same
// resolver's own control.
func TestSlowObservationIsADifferential(t *testing.T) {
	trap := Trap{Kind: SlowResponse, Host: testHost, Delay: time.Second}

	answered := func(elapsed time.Duration) answer {
		record, err := dns.NewRR("x.test. 600 IN A " + testAddress)
		if err != nil {
			t.Fatalf("build record: %v", err)
		}
		return answer{records: []dns.RR{record}, elapsed: elapsed}
	}

	bothSlow := answered(4 * time.Second)
	control := answered(4 * time.Second)

	if _, confirmed, _ := slowObservation(
		trap, bothSlow, control, testAddress,
	); confirmed {
		t.Error("confirmed a delay where the control was equally slow, which " +
			"is an absolute threshold wearing a differential's name")
	}

	fast := answered(10 * time.Millisecond)

	if _, confirmed, _ := slowObservation(
		trap, answered(4*time.Second), fast, testAddress,
	); !confirmed {
		t.Error("did not confirm a delay the control did not share")
	}
}

// TestSlowObservationRefusesAQueryItNeverGotAnAnswerTo is the control for the
// blocker this function shipped with.
//
// `ask` records a failure as an elapsed time plus an error, and probeTimeout is
// 10s, so a single dropped UDP datagram on khaos's own confirmation query looked
// exactly like a 10-second delay. The function returned CONFIRMED and worded it
// as "answering <name> after 10s" — khaos reporting a delay it never received,
// and then measuring a whole fault window on the strength of it.
func TestSlowObservationRefusesAQueryItNeverGotAnAnswerTo(t *testing.T) {
	trap := Trap{Kind: SlowResponse, Host: testHost, Delay: time.Second}
	fast := answer{elapsed: time.Millisecond}

	cases := []struct {
		name    string
		faulted answer
	}{
		{
			name: "a timed-out query",
			faulted: answer{
				elapsed: 10 * time.Second,
				err:     errors.New("i/o timeout"),
			},
		},
		{
			name: "a slow NXDOMAIN, which is a different fault",
			faulted: answer{
				elapsed: 4 * time.Second,
				rcode:   dns.RcodeNameError,
			},
		},
		{
			name:    "a slow empty answer",
			faulted: answer{elapsed: 4 * time.Second},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			observable, confirmed, err := slowObservation(
				trap, test.faulted, fast, testAddress,
			)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			if confirmed {
				t.Fatalf("confirmed a delay from something that was not an "+
					"answer: %s", observable)
			}
		})
	}
}

// TestSlowObservationRefusesAnAnswerThatAlsoMoved keeps the fault to ONE
// property. The kind promises the honest answer late, so a late redirect is two
// faults reported as one.
func TestSlowObservationRefusesAnAnswerThatAlsoMoved(t *testing.T) {
	record, err := dns.NewRR("x.test. 600 IN A 198.51.100.66")
	if err != nil {
		t.Fatalf("build record: %v", err)
	}

	moved := answer{records: []dns.RR{record}, elapsed: 4 * time.Second}

	observable, confirmed, _ := slowObservation(
		Trap{Kind: SlowResponse, Host: testHost},
		moved,
		answer{elapsed: time.Millisecond},
		testAddress,
	)

	if confirmed {
		t.Fatalf(
			"confirmed a delay on an answer that also changed: %s",
			observable,
		)
	}
}
