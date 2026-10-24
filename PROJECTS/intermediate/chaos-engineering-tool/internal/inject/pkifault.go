// ©AngelaMos | 2026
// pkifault.go

package inject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/pki"
)

const (
	KindPKIPrefix = "pki-"

	errNoAuthority = "%w: %s needs khaos's own certificate authority, and this run did not start one"

	describePKI = "%s, at khaos's own certificate authority, which holds no capabilities and serves nothing but the target under test"
)

var ErrNoAuthority = errors.New(
	"this mutation needs khaos's certificate authority, which is not running",
)

// PKIKind is one-to-one with the trap kinds, so the catalogue names the actual
// defect rather than a generic "certificate" entry.
func PKIKind(kind pki.Kind) string {
	return KindPKIPrefix + string(kind)
}

// pkiMutator leaves the dependency REACHABLE and presenting a certificate
// wrong in one specific way, which is the only shape that is a TLS finding. No
// correct CA mints an expired or revoked certificate, so khaos has to be the CA.
type pkiMutator struct {
	kind pki.Kind
}

func init() {
	for _, name := range pki.Kinds() {
		kind := pki.Kind(name)
		registry[PKIKind(kind)] = pkiMutator{kind: kind}
	}
}

func (m pkiMutator) Describe(env Env, target dockerx.Target) string {
	trap := env.PKITrap
	if trap.Kind != m.kind {
		trap = pki.Trap{Kind: m.kind, Host: target.Name}
	}

	return fmt.Sprintf(describePKI, trap.Describe(target.Name))
}

// Plan validates before journaling, because a record that cannot be armed is
// one `khaos reclaim` would retry forever.
func (m pkiMutator) Plan(
	_ context.Context,
	env Env,
	_ dockerx.Target,
) (json.RawMessage, error) {
	if env.Authority == nil {
		return nil, fmt.Errorf(
			errNoAuthority,
			ErrNoAuthority,
			PKIKind(m.kind),
		)
	}

	if env.PKITrap.Kind != m.kind {
		return nil, fmt.Errorf(
			errWrongTrapKind,
			ErrTrapMismatch,
			env.PKITrap.Kind,
			m.kind,
		)
	}

	trap := env.PKITrap

	if err := trap.Validate(); err != nil {
		return nil, err
	}

	return journal.EncodePayload(trap)
}

func (m pkiMutator) Apply(
	_ context.Context,
	env Env,
	_ dockerx.Target,
	raw json.RawMessage,
) error {
	if env.Authority == nil {
		return fmt.Errorf(errNoAuthority, ErrNoAuthority, PKIKind(m.kind))
	}

	var trap pki.Trap
	if err := json.Unmarshal(raw, &trap); err != nil {
		return err
	}

	return env.Authority.Arm(trap)
}

// Revert re-mints an honest chain, so recovery is measured through a WORKING
// authority. A cold start has nothing to disarm and is RESOLVED rather than
// failed: the authority died with the process, so the fault went with it.
func (m pkiMutator) Revert(_ context.Context, env Env, _ journal.Record) error {
	if env.Authority == nil {
		return nil
	}

	return env.Authority.Disarm()
}

// Confirm compares what the authority SERVES against an honest chain from it,
// never the flag that was set: a flag records which branch was chosen, so an
// authority whose minting broke would confirm a trap it is not producing.
func (m pkiMutator) Confirm(
	ctx context.Context,
	env Env,
	_ dockerx.Target,
) (string, bool, error) {
	if env.Authority == nil {
		return "", false, fmt.Errorf(
			errNoAuthority,
			ErrNoAuthority,
			PKIKind(m.kind),
		)
	}

	return env.Authority.Observe(ctx, m.kind)
}

// Prefix declares this tier's kinds to the registry, which keeps `khaos inject`
// from offering them: the authority is a goroutine inside a run.
func (pkiMutator) Prefix() string { return KindPKIPrefix }
