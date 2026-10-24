// ©AngelaMos | 2026
// injector_test.go

package run

import (
	"context"
	"errors"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
)

type replacementResolver struct{}

func (replacementResolver) Accept(
	_ context.Context,
	_ string,
	_ dockerx.Filter,
	guard dockerx.Guard,
) (dockerx.Target, error) {
	target := dockerx.Target{
		ID: "replacement", Name: "same-name", Inspected: true, Running: true,
		Labels: map[string]string{dockerx.LabelConsent: dockerx.ConsentValue},
	}
	if refusal := dockerx.Refuse(target, guard); refusal != nil {
		return dockerx.Target{}, refusal
	}
	return target, nil
}

func TestInjectorPreservesTheBaselineTargetIdentity(t *testing.T) {
	injector := &Injector{
		Resolver: replacementResolver{},
		Guard:    dockerx.Guard{ExpectedID: "baseline-container"},
	}
	err := injector.Inject(t.Context(), "container-pause", "same-name")
	var refusal *dockerx.Refusal
	if !errors.As(err, &refusal) ||
		refusal.Predicate != dockerx.PredicateIdentityChanged {
		t.Fatalf("replacement was not refused before mutation: %v", err)
	}
}

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
