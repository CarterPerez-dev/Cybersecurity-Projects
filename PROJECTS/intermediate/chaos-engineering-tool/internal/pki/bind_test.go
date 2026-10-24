// ©AngelaMos | 2026
// bind_test.go

package pki

import (
	"errors"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/bindguard"
)

func TestBothListenersRefuseAnExposedBind(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:45999", ":45999", "[::]:45999"} {
		t.Run(addr, func(t *testing.T) {
			revocation := authority_t(t)

			err := revocation.Listen(addr)
			if err == nil {
				_ = revocation.Close()
				t.Fatalf(
					"the revocation endpoint bound %s, which is reachable from outside this host",
					addr,
				)
			}

			if !errors.Is(err, bindguard.ErrUnsafeBind) {
				t.Fatalf("Listen(%q) = %v, want ErrUnsafeBind", addr, err)
			}

			dependency := authority_t(t)

			err = dependency.ListenTLS(addr)
			if err == nil {
				_ = dependency.Close()
				t.Fatalf(
					"the dependency endpoint bound %s, which is reachable from outside this host",
					addr,
				)
			}

			if !errors.Is(err, bindguard.ErrUnsafeBind) {
				t.Fatalf("ListenTLS(%q) = %v, want ErrUnsafeBind", addr, err)
			}
		})
	}

	// And loopback MUST still be accepted on both, or the refusal is a broken
	// tier rather than a guard. `listening` binds both and fails the test if
	// either is refused.
	_ = listening(t)
}
