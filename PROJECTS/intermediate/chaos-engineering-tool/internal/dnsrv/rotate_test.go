// ©AngelaMos | 2026
// rotate_test.go

package dnsrv

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestARotationChangesWhatTheNameAnswersWith(t *testing.T) {
	resolver, _ := startResolver(t)

	const rotated = "10.244.244.77"

	previous, err := resolver.Rotate(testHost, rotated)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if previous != testAddress {
		t.Fatalf(
			"the rotation reported %q as the address it replaced, want %q: khaos's observable names what the zone USED to say",
			previous,
			testAddress,
		)
	}

	if got := resolver.Stats().Zone[dns.CanonicalName(testHost)]; got != rotated {
		t.Fatalf("after the rotation the zone says %q, want %q", got, rotated)
	}
}

// A rotation to the address a name already answers with is not a rotation, and
// accepting it would let khaos measure a change that never happened -- the same
// reason the credential tier's inert control must be REJECTED by confirmation.
func TestARotationThatChangesNothingIsRefused(t *testing.T) {
	resolver, _ := startResolver(t)

	if _, err := resolver.Rotate(
		testHost,
		testAddress,
	); !errors.Is(err, ErrSameAddress) {
		t.Fatalf("rotating to the current address returned %v", err)
	}
}

// And a name outside the zone, for the same reason arming one is refused: it
// would succeed, answer nothing, and report a survival against nothing.
func TestARotationOutsideTheZoneIsRefused(t *testing.T) {
	resolver, _ := startResolver(t)

	if _, err := resolver.Rotate(
		"not-in-this-zone.invalid.",
		"10.244.244.77",
	); !errors.Is(err, ErrOutsideZone) {
		t.Fatalf("rotating a name outside the zone returned %v", err)
	}
}

func TestARotationToAnUnusableAddressIsRefused(t *testing.T) {
	resolver, _ := startResolver(t)

	for _, address := range []string{"", "not-an-address", "::1"} {
		if _, err := resolver.Rotate(testHost, address); err == nil {
			t.Fatalf("rotating to %q was accepted", address)
		}
	}
}

// The control surface carries it, nonce-guarded like every other route, and a
// failure is an ERROR rather than a silent no-op: that is what lets a failed
// rotation void a run instead of leaving khaos measuring a name nobody moved.
func TestTheControlSurfaceRotatesAndRefusesWithoutTheNonce(t *testing.T) {
	_, client := startResolver(t)

	stats, err := client.Rotate(context.Background(), testHost, "10.244.244.78")
	if err != nil {
		t.Fatalf("rotate through the control surface: %v", err)
	}

	if stats.Rotated != testAddress {
		t.Fatalf(
			"the echo reports %q as the replaced address, want %q",
			stats.Rotated,
			testAddress,
		)
	}

	wrong := NewClient(client.DNS, client.Control, "not-the-nonce", testControl)

	if _, err := wrong.Rotate(
		context.Background(),
		testHost,
		"10.244.244.79",
	); err == nil {
		t.Fatal(
			"a rotation was accepted without the nonce, so anything that can reach the control surface can move the zone mid-run",
		)
	}
}
