// ©AngelaMos | 2026
// trap_test.go

package dnsrv

import (
	"strings"
	"testing"
	"time"
)

func TestMaskedFaultsAreRefusedByName(t *testing.T) {
	for _, kind := range []Kind{Refused, Timeout} {
		t.Run(string(kind), func(t *testing.T) {
			err := Trap{Kind: kind, Host: testHost}.Validate()
			if err == nil {
				t.Fatal("accepted a fault khaos cannot deliver")
			}

			if !is(err, ErrMasked) {
				t.Fatalf("error %v, want %v", err, ErrMasked)
			}

			// A refusal that does not say what to do next is a dead end. Both
			// reasons name the mechanism and a fault to run instead, and the
			// gate asserts the same text, so this cannot decay into "refused".
			reason := MaskedReason(kind)
			for _, want := range []string{"embedded resolver", "dns."} {
				if !strings.Contains(reason, want) {
					t.Errorf("the refusal for %s never mentions %q: %s",
						kind, want, reason)
				}
			}
		})
	}
}

// TestEveryCatalogueKindIsEitherDeliverableOrExplained is the census. A kind
// that is neither servable nor refused-with-a-reason is one `khaos catalog`
// would advertise and `khaos run` could not do anything with.
func TestEveryCatalogueKindIsEitherDeliverableOrExplained(t *testing.T) {
	for _, name := range Kinds() {
		kind := Kind(name)

		if Deliverable(kind) {
			if reason := MaskedReason(kind); reason != "" {
				t.Errorf("%s is deliverable and also carries a refusal: %s",
					kind, reason)
			}
			continue
		}

		if MaskedReason(kind) == "" {
			t.Errorf("%s is refused with no reason, so an operator is told no "+
				"and not why", kind)
		}
	}
}

// TestEveryKindDescribesItself keeps `khaos catalog`, `khaos plan` and the run
// record from describing the same fault three different ways, and catches a new
// kind that forgets its wording and falls through to the generic string.
func TestEveryKindDescribesItself(t *testing.T) {
	for _, name := range Kinds() {
		kind := Kind(name)

		described := Trap{Kind: kind, Host: testHost}.Describe("the-target")

		if described == describeUnknown {
			t.Errorf("%s has no description of its own", kind)
		}

		if !strings.Contains(described, "the-target") {
			t.Errorf("%s describes itself without naming the target: %s",
				kind, described)
		}
	}
}

// TestDelayCeilingIsEnforced is the measured boundary, not a guessed one. At or
// above 4.000s Docker's embedded resolver answers SERVFAIL itself at 4.001s and
// the delay never reaches the client, so a larger magnitude would be the Timeout
// fault wearing SlowResponse's name.
func TestDelayCeilingIsEnforced(t *testing.T) {
	cases := []struct {
		delay  time.Duration
		accept bool
	}{
		{delay: 0, accept: true},
		{delay: time.Second, accept: true},
		{delay: 3900 * time.Millisecond, accept: true},
		{delay: MaxDelay, accept: true},
		{delay: 4 * time.Second, accept: false},
		{delay: 4100 * time.Millisecond, accept: false},
		{delay: 30 * time.Second, accept: false},
	}

	for _, test := range cases {
		t.Run(test.delay.String(), func(t *testing.T) {
			err := Trap{
				Kind:  SlowResponse,
				Host:  testHost,
				Delay: test.delay,
			}.Validate()

			if test.accept && err != nil {
				t.Fatalf("refused a deliverable delay: %v", err)
			}

			if !test.accept {
				if err == nil {
					t.Fatal("accepted a delay above the measured ceiling")
				}
				if !is(err, ErrDelayRange) {
					t.Errorf("error %v, want %v", err, ErrDelayRange)
				}
			}
		})
	}
}

func TestValidateRefusesWhatCannotBeArmed(t *testing.T) {
	cases := []struct {
		name string
		trap Trap
		want error
	}{
		{
			name: "unknown kind",
			trap: Trap{Kind: "not-a-fault", Host: testHost},
			want: ErrUnknownKind,
		},
		{
			name: "no host",
			trap: Trap{Kind: NXDomain},
			want: ErrNoHost,
		},
		{
			name: "redirect to something that is not an address",
			trap: Trap{
				Kind:    WrongAddress,
				Host:    testHost,
				Address: "not-an-address",
			},
			want: ErrBadAddress,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := test.trap.Validate()
			if err == nil {
				t.Fatal("accepted a trap that cannot be armed")
			}
			if !is(err, test.want) {
				t.Errorf("error %v, want %v", err, test.want)
			}
		})
	}
}

// TestTTLIsCarriedByEveryAnsweringKind catches the shape where a new kind
// forgets its TTL and serves zero by accident, which is indistinguishable from
// the TTLZero fault having been armed.
func TestTTLIsCarriedByEveryAnsweringKind(t *testing.T) {
	for _, name := range Kinds() {
		kind := Kind(name)

		if kind == TTLZero {
			continue
		}

		ttl := Trap{Kind: kind, Host: testHost}.ttl()

		if ttl == 0 {
			t.Errorf("%s serves a zero TTL, which reads exactly like %s",
				kind, TTLZero)
		}
	}
}
