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

// PKIKind names the mutation that arms one trap on khaos's certificate
// authority. The trap kinds and the mutation kinds are one-to-one, so `khaos
// catalog` names the actual defect being provoked rather than a generic
// "certificate" entry.
func PKIKind(kind pki.Kind) string {
	return KindPKIPrefix + string(kind)
}

// pkiMutator arms a trap on khaos's in-process certificate authority.
//
// This is a FOURTH tier, and it exists for the same reason the identity
// provider does: the other three cannot express the fault. Pausing a dependency
// or severing the path to it makes it unreachable, where every trap here leaves
// it REACHABLE and presenting a certificate that is wrong in one specific way.
// A client's behaviour on an unreachable dependency and its behaviour on one
// whose identity it cannot verify are different code paths reached by different
// bugs, and only the second is a TLS finding.
//
// No correct CA will mint an expired, revoked or wrongly-named certificate at
// any price, which is why khaos has to be the CA.
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

// Plan journals the trap that is about to be armed. Everything this tier needs
// is known at build time, so unlike the identity tier's revocation there is
// nothing to resolve here -- but the trap is still validated before it reaches
// the journal, because a record that cannot be armed is a record `khaos
// reclaim` would retry forever.
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

// Revert disarms, which re-mints an honest chain so the recovery window is
// measured through a WORKING authority rather than through no authority at all.
//
// A cold start has no authority to disarm and that is RESOLVED rather than
// failed: the authority died with the process that held it, so the fault
// provably went with it. Reporting that as a failure would wedge the journal
// record forever and, because `khaos reap` stops on a sweep error, would
// disable the dead man's switch for every other fault on the machine.
func (m pkiMutator) Revert(_ context.Context, env Env, _ journal.Record) error {
	if env.Authority == nil {
		return nil
	}

	return env.Authority.Disarm()
}

// Confirm delegates to the authority's own read-back, which compares what it
// SERVES against an honest chain from the same authority and returns the
// specific observable it saw.
//
// It deliberately does not read the flag that was set. A flag records which
// branch was chosen, not what a target would receive, and an authority whose
// minting broke would confirm a trap it is not producing. The oracle's negative
// control found fifteen traps that could be confirmed against an authority
// which had armed nothing at all, every one of them because something was
// derived from the trap record instead of from the served material.
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
