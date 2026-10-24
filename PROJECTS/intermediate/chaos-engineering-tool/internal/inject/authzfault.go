// ©AngelaMos | 2026
// authzfault.go

package inject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/authz"
	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const (
	KindAuthzPrefix = "authz-"

	errNoAuthz = "%w: %s needs khaos's own authorization dependency, and this run did not start one"

	describeAuthz = "%s. khaos serves that dependency itself, on the address the target already asks, because no correct authorization service will answer a deny on request"
)

var ErrNoAuthz = errors.New(
	"this mutation needs khaos's authorization dependency, which is not running",
)

func AuthzKind(kind authz.Kind) string {
	return KindAuthzPrefix + string(kind)
}

// authzMutator leaves the dependency REACHABLE and answering. That is the whole
// tier: a paused container and a severed path both produce an absent answer, so
// a caller's error branch is the only one they can ever reach, and the defect
// this hunts lives in the branch that reads a definitive refusal.
type authzMutator struct {
	kind authz.Kind
}

func init() {
	for _, name := range authz.Injectable() {
		kind := authz.Kind(name)
		registry[AuthzKind(kind)] = authzMutator{kind: kind}
	}
}

func (m authzMutator) Describe(env Env, _ dockerx.Target) string {
	trap := env.AuthzTrap
	if trap.Kind != m.kind {
		trap = authz.Trap{Kind: m.kind}
	}

	return fmt.Sprintf(describeAuthz, trap.Describe())
}

// Plan journals the SHAPE of the fault and never the credential. The credential
// belongs to the operator's target, a journal entry would leave it on disk, and
// the revert does not need it: khaos's dependency allows everything it has not
// been told to deny, so lifting the fault is a reset rather than an undo.
func (m authzMutator) Plan(
	_ context.Context,
	env Env,
	_ dockerx.Target,
) (json.RawMessage, error) {
	if env.Authz == nil {
		return nil, fmt.Errorf(errNoAuthz, ErrNoAuthz, AuthzKind(m.kind))
	}

	if env.AuthzTrap.Kind != m.kind {
		return nil, fmt.Errorf(
			errWrongTrapKind,
			ErrTrapMismatch,
			env.AuthzTrap.Kind,
			m.kind,
		)
	}

	if err := env.AuthzTrap.Validate(); err != nil {
		return nil, err
	}

	return journal.EncodePayload(env.AuthzTrap)
}

func (m authzMutator) Apply(
	_ context.Context,
	env Env,
	_ dockerx.Target,
	_ json.RawMessage,
) error {
	if env.Authz == nil {
		return fmt.Errorf(errNoAuthz, ErrNoAuthz, AuthzKind(m.kind))
	}

	return env.Authz.Arm(env.AuthzTrap)
}

// Confirm reads the dependency back through its own HTTP surface against a
// control credential, never the flag that was set: a dependency whose handler
// was wrong would otherwise confirm a fault it is not serving.
func (m authzMutator) Confirm(
	ctx context.Context,
	env Env,
	_ dockerx.Target,
) (string, bool, error) {
	if env.Authz == nil {
		return "", false, fmt.Errorf(
			errNoAuthz,
			ErrNoAuthz,
			AuthzKind(m.kind),
		)
	}

	return env.Authz.Observe(ctx)
}

// Revert is a cold start's no-op by construction. khaos's dependency lives in
// khaos's process, so a killed run takes the fault with it and there is nothing
// outstanding for a reclaim to undo.
func (m authzMutator) Revert(
	_ context.Context,
	env Env,
	_ journal.Record,
) error {
	if env.Authz == nil {
		return nil
	}

	env.Authz.Disarm()

	return nil
}

// NeedsAuthz tells the run to stand the dependency up before the baseline,
// derived from the registry rather than from the kind's spelling.
func NeedsAuthz(kind string) bool {
	mutator, ok := registry[kind]
	if !ok {
		return false
	}

	_, isAuthz := mutator.(authzMutator)

	return isAuthz
}

// Prefix declares this tier's kinds to the registry.
func (authzMutator) Prefix() string { return KindAuthzPrefix }
