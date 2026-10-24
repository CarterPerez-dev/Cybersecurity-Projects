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

// IdPKind is one-to-one with the trap kinds, so the catalogue names the actual
// defect rather than a generic "identity provider" entry.
func IdPKind(kind idp.Kind) string {
	return KindIdPPrefix + string(kind)
}

// idpMutator leaves the provider REACHABLE and wrong, where pausing it or
// severing the path would only make it unreachable, which is a different code
// path in the verifier.
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

// Plan resolves the one piece not knowable at build time: the revocation's
// credential is issued by a PROBE, so the trap picks it up here, after the
// baseline, once the target has been honouring it.
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

// Revert also restores any key material or grant the trap changed. A cold
// start has nothing to disarm and is RESOLVED rather than failed: the provider
// died with the process, so the fault went with it.
func (m idpMutator) Revert(_ context.Context, env Env, _ journal.Record) error {
	if env.IdP == nil {
		return nil
	}

	env.IdP.Disarm()

	return nil
}

// Confirm measures through the provider's public surface against a control,
// never the flag that was set: a provider whose minting broke would otherwise
// confirm a trap it is not producing.
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

// Prefix declares this tier's kinds to the registry.
func (idpMutator) Prefix() string { return KindIdPPrefix }
