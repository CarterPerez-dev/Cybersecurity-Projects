// ©AngelaMos | 2026
// trap_test.go

package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestWeakKeyRefusesASizeCryptoRSAWillNotGenerate(t *testing.T) {
	cases := []struct {
		bits   int
		accept bool
	}{
		{0, false},
		{512, false},
		{MinimumBits - 1, false},
		{MinimumBits, true},
		{DefaultWeakBits, true},
		{StrongBits - 1, true},
		{StrongBits, false},
		{StrongBits * 2, false},
	}

	for _, c := range cases {
		t.Run(strconv.Itoa(c.bits), func(t *testing.T) {
			// Host is set on EVERY case, including the refused ones. Validate
			// also refuses a missing host, so a trap without one is rejected
			// either way and the bits check would be alibied by it.
			err := Trap{
				Kind: WeakKey,
				Bits: c.bits,
				Host: DefaultHost,
			}.Validate()

			if c.accept && err != nil {
				t.Fatalf("%d bits was refused: %v", c.bits, err)
			}

			if !c.accept {
				if err == nil {
					t.Fatalf("%d bits was accepted", c.bits)
				}

				if !errors.Is(err, ErrInvalidTrap) {
					t.Fatalf(
						"%d bits refused without ErrInvalidTrap: %v",
						c.bits,
						err,
					)
				}
			}
		})
	}
}

// The differential that keeps MinimumBits honest. Validate restating a number
// proves nothing; what matters is that crypto/rsa agrees, so every size
// Validate ACCEPTS has to generate and every size it refuses for being too
// small has to fail. If Go moves its floor, this fails here rather than at arm
// time in front of an operator.
func TestValidateAgreesWithCryptoRSAAboutTheFloor(t *testing.T) {
	generates := func(bits int) bool {
		_, err := rsa.GenerateKey(rand.Reader, bits)

		return err == nil
	}

	if !generates(MinimumBits) {
		t.Fatalf(
			"MinimumBits=%d is above crypto/rsa's floor, so the weakest "+
				"key khaos advertises cannot be served",
			MinimumBits,
		)
	}

	if generates(MinimumBits - 1) {
		t.Fatalf(
			"crypto/rsa generates %d bits, so MinimumBits=%d refuses a "+
				"size khaos could actually serve",
			MinimumBits-1,
			MinimumBits,
		)
	}

	accepted := Trap{
		Kind: WeakKey,
		Bits: MinimumBits,
		Host: DefaultHost,
	}.Validate()
	if accepted != nil {
		t.Fatalf("Validate refuses the floor it defines: %v", accepted)
	}
}

func TestWeakKeyRefusalNamesBothBounds(t *testing.T) {
	err := Trap{Kind: WeakKey, Bits: 512, Host: DefaultHost}.Validate()
	if err == nil {
		t.Fatal("512 bits was accepted")
	}

	message := err.Error()

	for _, want := range []string{
		strconv.Itoa(MinimumBits),
		strconv.Itoa(StrongBits),
		"512",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("refusal does not name %q: %s", want, message)
		}
	}
}
