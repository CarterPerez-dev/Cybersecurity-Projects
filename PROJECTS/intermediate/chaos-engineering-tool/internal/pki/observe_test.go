// ©AngelaMos | 2026
// observe_test.go

package pki

import (
	"context"
	"testing"
)

// The census, and the oracle's own negative control.
//
// Every trap khaos advertises has to be confirmable by its own observable. A
// trap that cannot be confirmed is a fault khaos would apply and then measure
// without knowing it landed, which is the one thing the engine refuses to do.
//
// And every trap has to be UNCONFIRMABLE when the authority was never actually
// armed. Without that half, an Observe gutted to `return true` passes the whole
// file, and the identity family learned that the expensive way: gutting its
// oracle left all seventeen packages and the Docker gate green.

func everyKindTrap(kind Kind, host string) Trap {
	return Trap{
		Kind:   kind,
		Host:   host,
		Window: DefaultWindow,
		Bits:   DefaultWeakBits,
		Days:   DefaultExcessiveDays,
	}
}

func TestEveryTrapIsConfirmedByItsOwnObservable(t *testing.T) {
	for _, name := range Kinds() {
		kind := Kind(name)

		t.Run(name, func(t *testing.T) {
			a := listening(t)

			if err := a.Arm(everyKindTrap(kind, a.Host())); err != nil {
				t.Fatalf("arm %s: %v", kind, err)
			}

			observable, confirmed, err := a.Observe(
				context.Background(),
				kind,
			)
			if err != nil {
				t.Fatalf("observe %s: %v", kind, err)
			}

			if !confirmed {
				t.Fatalf(
					"%s could not be confirmed, so khaos would apply this fault and then measure a target without knowing the fault landed",
					kind,
				)
			}

			if observable == "" {
				t.Fatalf(
					"%s confirmed with no observable, so the run would claim a fault landed without saying what khaos saw",
					kind,
				)
			}
		})
	}
}

// The negative control. The authority records the trap and builds nothing, so
// the oracle runs its real observable against HONEST material and has to say
// no.
func TestNoTrapIsConfirmedByAnInertAuthority(t *testing.T) {
	for _, name := range Kinds() {
		kind := Kind(name)

		t.Run(name, func(t *testing.T) {
			a := listening(t)

			a.Inert(true)

			if err := a.Arm(everyKindTrap(kind, a.Host())); err != nil {
				t.Fatalf("arm %s while inert: %v", kind, err)
			}

			_, confirmed, err := a.Observe(context.Background(), kind)
			if err != nil {
				// An error is a refusal to confirm, which is the right
				// direction, but it means the branch under test was never
				// reached and this control is weaker than it looks.
				t.Fatalf(
					"%s errored instead of declining (%v); the oracle short-circuited and its observable was never exercised",
					kind,
					err,
				)
			}

			if confirmed {
				t.Fatalf(
					"%s was confirmed against an authority that armed nothing, so this oracle cannot tell a landed fault from no fault at all",
					kind,
				)
			}
		})
	}
}

// Observe must refuse to confirm a DIFFERENT trap than the one armed. Without
// this, an experiment whose build and whose mutator disagreed would confirm the
// wrong fault and report a finding about something khaos never did.
func TestObserveRefusesATrapItDidNotArm(t *testing.T) {
	a := listening(t)

	if err := a.Arm(everyKindTrap(LeafExpired, a.Host())); err != nil {
		t.Fatalf("arm: %v", err)
	}

	if _, _, err := a.Observe(
		context.Background(),
		RevokedViaCRL,
	); err == nil {
		t.Fatal(
			"observing revoked-via-crl against an authority with leaf-expired armed returned no error",
		)
	}
}
