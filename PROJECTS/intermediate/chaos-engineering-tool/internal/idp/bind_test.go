// ©AngelaMos | 2026
// bind_test.go

package idp

import (
	"errors"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/bindguard"
)

func TestAnExposedBindIsRefused(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:45999", ":45999", "[::]:45999"} {
		provider, err := New(Config{})
		if err != nil {
			t.Fatalf("build a provider: %v", err)
		}

		err = provider.Listen(addr)
		if err == nil {
			bound, _ := provider.Addr()
			_ = provider.Close()
			t.Fatalf(
				"the provider bound %s, which is reachable from outside this host",
				bound,
			)
		}

		if !errors.Is(err, bindguard.ErrUnsafeBind) {
			t.Fatalf("%s: err = %v, want ErrUnsafeBind", addr, err)
		}
	}

	// And loopback MUST still be accepted, or the refusal is a broken listener
	// rather than a guard. `listening` binds loopback and fails the test if it
	// is refused, which is the positive half.
	_ = listening(t)
}
