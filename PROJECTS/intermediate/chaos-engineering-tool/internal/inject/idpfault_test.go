// ©AngelaMos | 2026
// idpfault_test.go

package inject

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const idpTestDelay = 300 * time.Millisecond

func traps(p *idp.Provider) []idp.Trap {
	return []idp.Trap{
		{Kind: idp.AlgNone},
		{Kind: idp.AlgConfusion, KeyForm: idp.SPKIPEM},
		{Kind: idp.EmbeddedJWK},
		{Kind: idp.ClaimExpired, Delay: time.Hour},
		{Kind: idp.ClaimNotYetValid, Delay: time.Hour},
		{Kind: idp.ClaimWrongAudience},
		{Kind: idp.ClaimForeignIssuer},
		{Kind: idp.SignatureTruncated},
		{Kind: idp.SignatureZero},
		{Kind: idp.SignatureWeakKey},
		{Kind: idp.JWKSUnreachable},
		{Kind: idp.KidRollover},
		{Kind: idp.KeyRotation},
		{Kind: idp.IntrospectionError},
		{Kind: idp.IntrospectionMalformed},
		{Kind: idp.IntrospectionSlow, Delay: idpTestDelay},
		{Kind: idp.Revoke, Credential: p.Revocable()},
	}
}

// The whole mutation, end to end, for every registered identity trap: journal
// it, arm it, confirm it by read-back on the provider's own surface, revert it,
// and prove the provider is correct again afterwards.
//
// The census is counted by the identity prefix specifically, because counting
// "not direct" would let the proxy tier's registrations satisfy it.
func TestEveryIdentityTrapAppliesConfirmsAndReverts(t *testing.T) {
	provider := provider(t)
	all := traps(provider)

	registered := 0
	for _, kind := range Kinds() {
		if strings.HasPrefix(kind, KindIdPPrefix) {
			registered++
		}
	}

	if registered != len(all) {
		t.Fatalf(
			"this test covers %d identity traps but %d are registered",
			len(all),
			registered,
		)
	}

	ctx := context.Background()
	target := dockerx.Target{ID: "abc", Name: "a-verifier"}

	for _, trap := range all {
		t.Run(string(trap.Kind), func(t *testing.T) {
			env := Env{IdP: provider, IdPTrap: trap}

			mutator, err := Lookup(IdPKind(trap.Kind))
			if err != nil {
				t.Fatalf("lookup: %v", err)
			}

			if describe := mutator.Describe(
				env,
				target,
			); !strings.Contains(
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

// The journal is the only durable account of what an identity run did, because
// the provider dies with the process. A payload that does not round-trip means a
// process killed mid-apply leaves a record that cannot describe the fault.
func TestTheJournalledTrapRoundTrips(t *testing.T) {
	provider := provider(t)

	for _, trap := range traps(provider) {
		env := Env{IdP: provider, IdPTrap: trap}

		mutator, err := Lookup(IdPKind(trap.Kind))
		if err != nil {
			t.Fatalf("lookup %s: %v", trap.Kind, err)
		}

		payload, err := mutator.Plan(
			context.Background(),
			env,
			dockerx.Target{},
		)
		if err != nil {
			t.Fatalf("plan %s: %v", trap.Kind, err)
		}

		record := journal.Record{Payload: payload}

		var back idp.Trap
		if err := record.DecodePayload(&back); err != nil {
			t.Fatalf("decode %s: %v", trap.Kind, err)
		}

		if back.Kind != trap.Kind || back.Delay != trap.Delay ||
			back.KeyForm != trap.KeyForm {
			t.Errorf(
				"%s did not round-trip: got %+v want %+v",
				trap.Kind,
				back,
				trap,
			)
		}
	}
}

// A mutation whose run never started a provider has to refuse by name rather
// than arm nothing and report success.
func TestApplyingAnIdentityTrapWithNoProviderIsRefused(t *testing.T) {
	mutator, err := Lookup(IdPKind(idp.AlgNone))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if _, err := mutator.Plan(
		context.Background(),
		Env{},
		dockerx.Target{},
	); err == nil {
		t.Fatal("planning an identity trap with no provider succeeded")
	}

	if err := mutator.Apply(
		context.Background(),
		Env{},
		dockerx.Target{},
		nil,
	); err == nil {
		t.Fatal("applying an identity trap with no provider succeeded")
	}

	if _, confirmed, err := mutator.Confirm(
		context.Background(),
		Env{},
		dockerx.Target{},
	); confirmed ||
		err == nil {
		t.Fatal("confirming an identity trap with no provider succeeded")
	}
}

// Reverting on a cold start must RESOLVE. The provider died with the process
// that held it, so the fault provably went with it, and reporting a failure
// would wedge the journal record forever and stop `khaos reap` sweeping anything
// else on the machine.
func TestRevertingWithoutAProviderIsResolvedRatherThanFailed(t *testing.T) {
	mutator, err := Lookup(IdPKind(idp.AlgNone))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if err := mutator.Revert(
		context.Background(),
		Env{},
		journal.Record{},
	); err != nil {
		t.Fatalf("revert on a cold start returned %v; it must resolve", err)
	}
}

// A run that armed one trap must not be able to apply a different one. Without
// this, the trap an operator consented to on the plan line and the trap that
// actually lands can differ.
func TestAMutationRefusesATrapTheRunDidNotArm(t *testing.T) {
	provider := provider(t)

	mutator, err := Lookup(IdPKind(idp.AlgNone))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	env := Env{IdP: provider, IdPTrap: idp.Trap{Kind: idp.SignatureTruncated}}

	if _, err := mutator.Plan(
		context.Background(),
		env,
		dockerx.Target{},
	); err == nil {
		t.Fatal(
			"a run holding signature-truncated planned an alg-none mutation",
		)
	}
}

// The revocation's credential cannot be known when the experiment is built, so
// the trap travels without it. A run whose probe never issued one has nothing to
// revoke, and that must be a refusal rather than a revocation of nothing.
func TestRevokeResolvesItsCredentialAtInjectTime(t *testing.T) {
	fresh, err := idp.New(idp.Config{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	mutator, err := Lookup(IdPKind(idp.Revoke))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	bare := Env{IdP: fresh, IdPTrap: idp.Trap{Kind: idp.Revoke}}

	if _, err := mutator.Plan(
		context.Background(),
		bare,
		dockerx.Target{},
	); err == nil {
		t.Fatal(
			"planning a revocation succeeded before any credential was issued",
		)
	}

	credential := fresh.Revocable()

	payload, err := mutator.Plan(context.Background(), bare, dockerx.Target{})
	if err != nil {
		t.Fatalf("plan after issuing: %v", err)
	}

	var resolved idp.Trap
	if err := (journal.Record{Payload: payload}).DecodePayload(
		&resolved,
	); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resolved.Credential != credential {
		t.Fatalf(
			"the journalled trap revokes %q, want the credential the probe issued, %q",
			resolved.Credential,
			credential,
		)
	}
}

func provider(t *testing.T) *idp.Provider {
	t.Helper()

	p, err := idp.New(idp.Config{})
	if err != nil {
		t.Fatalf("build a provider: %v", err)
	}

	if err := p.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("bind a provider: %v", err)
	}

	t.Cleanup(func() { _ = p.Close() })

	return p
}
