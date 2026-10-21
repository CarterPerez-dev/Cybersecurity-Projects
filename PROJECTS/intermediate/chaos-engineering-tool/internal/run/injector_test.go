// ©AngelaMos | 2026
// injector_test.go

package run

import (
	"context"
	"errors"
	"testing"
)

// The cold-start experiment restarts the container the fault was applied to.
// Asked before anything is applied, khaos has no container it can be SURE was
// meant, and guessing would restart something the operator never consented
// for. Mutating this guard to a nil return makes the whole phase a silent
// no-op, which is indistinguishable from a target that restarted cleanly.
func TestRestartingBeforeAnythingIsAppliedIsRefused(t *testing.T) {
	injector := &Injector{}

	err := injector.Restart(context.Background())

	if err == nil {
		t.Fatal(
			"khaos was asked to restart the target before any fault was applied and did not refuse",
		)
	}

	if !errors.Is(err, ErrNothingApplied) {
		t.Fatalf("the refusal is not ErrNothingApplied: %v", err)
	}
}
