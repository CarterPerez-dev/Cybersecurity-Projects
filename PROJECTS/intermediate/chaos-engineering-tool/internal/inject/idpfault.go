// ©AngelaMos | 2026
// idpfault.go

package inject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const (
	KindIdPPrefix = "idp-"

	errNoIdP         = "%w: %s needs khaos's own identity provider, and this run did not start one"
	errWrongTrapKind = "%w: this run armed %q but the mutation is %q"

	describeIdP = "%s, at khaos's own identity provider, which holds no capabilities and serves nothing but the target under test"
)

var ErrNoIdP = errors.New(
	"this mutation needs khaos's identity provider, which is not running",
)

var ErrTrapMismatch = errors.New(
	"the armed trap does not match the mutation being applied",
)

// IdPKind names the mutation that arms one trap on khaos's identity provider.
// The trap kinds and the mutation kinds are one-to-one, so `khaos catalog` names
// the actual defect being provoked rather than a generic "identity provider"
// entry.
func IdPKind(kind idp.Kind) string {
	return KindIdPPrefix + string(kind)
}

// idpMutator arms a trap on khaos's in-process identity provider. This is a
// THIRD injection tier alongside the Docker-native one and the fault proxy, and
// it exists because the other two cannot express the fault at all: pausing a
// provider or severing the path to it makes it unreachable, where every trap in
// this tier leaves it REACHABLE and wrong. A verifier's behaviour on an
// unreachable authority and its behaviour on a lying one are different code
// paths reached by different bugs.
type idpMutator struct {
	kind idp.Kind
}

func init() {
	for _, name := range idp.Kinds() {
		kind := idp.Kind(name)
		registry[IdPKind(kind)] = idpMutator{kind: kind}
	}
}

func (m idpMutator) Describe(env Env, target dockerx.Target) string {
	trap := env.IdPTrap
	if trap.Kind != m.kind {
		trap = idp.Trap{Kind: m.kind}
	}

	return fmt.Sprintf(describeIdP, trap.Describe(target.Name))
}

// Plan journals the trap that is about to be armed, and resolves the one piece
// of it that cannot be known at build time.
//
// The revocation's credential is issued by a PROBE, and no probe has fired when
// the experiment is built, so the trap travels without it and picks it up here.
// Inject runs after the baseline, by which time the credential exists and the
// target has been honouring it, which is exactly the state the finding needs.
func (m idpMutator) Plan(
	_ context.Context,
	env Env,
	_ dockerx.Target,
) (json.RawMessage, error) {
	if env.IdP == nil {
		return nil, fmt.Errorf(errNoIdP, ErrNoIdP, IdPKind(m.kind))
	}

	if env.IdPTrap.Kind != m.kind {
		return nil, fmt.Errorf(
			errWrongTrapKind,
			ErrTrapMismatch,
			env.IdPTrap.Kind,
			m.kind,
		)
	}

	trap := env.IdPTrap

	if trap.Kind == idp.Revoke && trap.Credential == "" {
		credential, err := env.IdP.RevocableCredential()
		if err != nil {
			return nil, err
		}
		trap.Credential = credential
	}

	if err := trap.Validate(); err != nil {
		return nil, err
	}

	return journal.EncodePayload(trap)
}

func (m idpMutator) Apply(
	_ context.Context,
	env Env,
	_ dockerx.Target,
	raw json.RawMessage,
) error {
	if env.IdP == nil {
		return fmt.Errorf(errNoIdP, ErrNoIdP, IdPKind(m.kind))
	}

	var trap idp.Trap
	if err := json.Unmarshal(raw, &trap); err != nil {
		return err
	}

	return env.IdP.Arm(trap)
}

// Revert disarms, which also restores any key material or grant the trap
// changed. A cold start has no provider to disarm and that is RESOLVED rather
// than failed: the provider died with the process that held it, so the fault
// provably went with it. Reporting that as a failure would wedge the journal
// record forever and, because `khaos reap` stops on a sweep error, would disable
// the dead man's switch for every other fault on the machine.
func (m idpMutator) Revert(_ context.Context, env Env, _ journal.Record) error {
	if env.IdP == nil {
		return nil
	}

	env.IdP.Disarm()

	return nil
}

// Confirm delegates to the provider's own read-back, which measures the trap
// through the provider's public surface against a control and returns the
// specific observable it saw. It deliberately does NOT read the flag that was
// set: a flag records which branch was chosen, not what a verifier would
// actually receive, and a provider whose minting broke would confirm a trap it
// is not producing.
func (m idpMutator) Confirm(
	ctx context.Context,
	env Env,
	_ dockerx.Target,
) (string, bool, error) {
	if env.IdP == nil {
		return "", false, fmt.Errorf(errNoIdP, ErrNoIdP, IdPKind(m.kind))
	}

	return env.IdP.Observe(ctx, m.kind)
}
