// ©AngelaMos | 2026
// pkifault_test.go

package inject

import (
	"context"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/pki"
)

const pkiHost = "dependency.khaos.invalid"

func authority(t *testing.T) *pki.Authority {
	t.Helper()

	a, err := pki.New(pki.Config{Host: pkiHost})
	if err != nil {
		t.Fatalf("build an authority: %v", err)
	}

	t.Cleanup(func() { _ = a.Close() })

	// Both listeners, because the revocation traps are confirmed by reading
	// khaos's own endpoints over HTTP exactly as a target would.
	if err := a.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("bind revocation: %v", err)
	}

	if err := a.ListenTLS("127.0.0.1:0"); err != nil {
		t.Fatalf("bind the dependency: %v", err)
	}

	if err := a.Disarm(); err != nil {
		t.Fatalf("mint the honest chain: %v", err)
	}

	return a
}

func pkiTraps() []pki.Trap {
	all := make([]pki.Trap, 0, len(pki.Kinds()))

	for _, name := range pki.Kinds() {
		all = append(all, pki.Trap{
			Kind:   pki.Kind(name),
			Host:   pkiHost,
			Window: pki.DefaultWindow,
			Bits:   pki.DefaultWeakBits,
			Days:   pki.DefaultExcessiveDays,
		})
	}

	return all
}

// The whole mutation, end to end, for every registered certificate trap:
// journal it, arm it, confirm it by read-back against an honest chain from the
// same authority, revert it, and prove the authority is correct again
// afterwards.
//
// The census counts the PKI prefix specifically. Counting "not direct" would
// let the identity and proxy tiers' registrations satisfy it, and this test
// would then pass with no certificate traps registered at all.
func TestEveryCertificateTrapAppliesConfirmsAndReverts(t *testing.T) {
	a := authority(t)
	all := pkiTraps()

	registered := 0

	for _, kind := range Kinds() {
		if strings.HasPrefix(kind, KindPKIPrefix) {
			registered++
		}
	}

	if registered != len(all) {
		t.Fatalf(
			"this test covers %d certificate traps but %d are registered",
			len(all),
			registered,
		)
	}

	ctx := context.Background()
	target := dockerx.Target{ID: "abc", Name: "a-tls-client"}

	for _, trap := range all {
		t.Run(string(trap.Kind), func(t *testing.T) {
			env := Env{Authority: a, PKITrap: trap}

			mutator, err := Lookup(PKIKind(trap.Kind))
			if err != nil {
				t.Fatalf("lookup: %v", err)
			}

			if describe := mutator.Describe(env, target); !strings.Contains(
				describe,
				target.Name,
			) {
				t.Errorf("the plan line does not name the target: %s", describe)
			}

			payload, err := mutator.Plan(ctx, env, target)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}

			if err := mutator.Apply(ctx, env, target, payload); err != nil {
				t.Fatalf("apply: %v", err)
			}

			observable, confirmed, err := mutator.Confirm(ctx, env, target)
			if err != nil || !confirmed {
				t.Fatalf(
					"confirm said %v (%v) with %s armed",
					confirmed,
					err,
					trap.Kind,
				)
			}

			if observable == "" {
				t.Fatal(
					"confirmed with no observable, so the run record would carry no evidence",
				)
			}

			if err := mutator.Revert(ctx, env, journal.Record{}); err != nil {
				t.Fatalf("revert: %v", err)
			}

			if _, confirmed, _ := mutator.Confirm(ctx, env, target); confirmed {
				t.Fatal("the trap still confirms itself after being reverted")
			}
		})
	}
}

// A mutation that needs khaos's authority has to refuse when no authority is
// running, and refuse at PLAN time. Discovering it at Apply would mean the
// journal already carried a record for a fault that was never applied, which
// `khaos reclaim` would then try to revert forever.
func TestACertificateTrapRefusesWithoutAnAuthority(t *testing.T) {
	ctx := context.Background()
	target := dockerx.Target{ID: "abc", Name: "a-tls-client"}

	mutator, err := Lookup(PKIKind(pki.LeafExpired))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if _, err := mutator.Plan(ctx, Env{}, target); err == nil {
		t.Fatal(
			"planning a certificate trap with no authority running returned no error",
		)
	}
}

// Reverting with no authority is RESOLVED, not failed. The authority died with
// the process that held it, so the fault provably went with it, and reporting a
// failure would wedge the journal record forever. `khaos reap` stops on a sweep
// error, so one wedged record disables the dead man's switch for every other
// fault on the machine.
func TestRevertingACertificateTrapAfterAColdStartSucceeds(t *testing.T) {
	mutator, err := Lookup(PKIKind(pki.RevokedViaCRL))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if err := mutator.Revert(
		context.Background(),
		Env{},
		journal.Record{},
	); err != nil {
		t.Fatalf(
			"reverting with no authority failed (%v), which wedges the record and disables the reaper for everything else",
			err,
		)
	}
}

// A mutator whose trap does not match the one the run armed must refuse. An
// experiment whose build and whose mutator disagree would otherwise arm one
// fault and report a finding about another.
func TestACertificateMutatorRefusesAMismatchedTrap(t *testing.T) {
	a := authority(t)

	mutator, err := Lookup(PKIKind(pki.LeafExpired))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	env := Env{
		Authority: a,
		PKITrap:   pki.Trap{Kind: pki.RevokedViaCRL, Host: pkiHost},
	}

	if _, err := mutator.Plan(
		context.Background(),
		env,
		dockerx.Target{ID: "abc", Name: "a-tls-client"},
	); err == nil {
		t.Fatal(
			"a leaf-expired mutator planned a run that armed revoked-via-crl",
		)
	}
}
