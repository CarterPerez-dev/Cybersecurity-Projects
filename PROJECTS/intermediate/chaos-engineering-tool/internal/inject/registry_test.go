// ©AngelaMos | 2026
// registry_test.go

package inject

import (
	"slices"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
)

func TestEveryMutatorCanDescribeWithoutAPlan(t *testing.T) {
	for kind, mutator := range registry {
		t.Run(kind, func(t *testing.T) {
			got := mutator.Describe(Env{}, dockerx.Target{Name: "target"})
			if got == "" {
				t.Fatal("mutator has no description before planning")
			}
		})
	}
}

// An obligation kind is khaos's own bookkeeping: a reclaim has to be able to
// resolve it, and `khaos inject` must never offer it. Both halves matter --
// unresolvable means a target stays down after a failed restart, and offered
// means the CLI advertises a command that is not a fault anyone asked for.
func TestAnObligationKindIsResolvableButNeverOffered(t *testing.T) {
	if _, err := Lookup(KindRestart); err != nil {
		t.Fatalf(
			"%s does not resolve, so a reclaim cannot undo a restart khaos left half-done: %v",
			KindRestart,
			err,
		)
	}

	if slices.Contains(DirectKinds(), KindRestart) {
		t.Errorf(
			"`khaos inject` offers %s, which is khaos's own recovery bookkeeping rather than a fault",
			KindRestart,
		)
	}
}
