// ©AngelaMos | 2026
// authzfault_test.go

package inject

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/authz"
	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const authzCredential = "the-credential-the-dependency-will-deny"

func dependency(t *testing.T) *authz.Dependency {
	t.Helper()

	served := authz.New()

	if err := served.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("listen: %v", err)
	}

	t.Cleanup(func() { _ = served.Close() })

	return served
}

// The census. A fault the catalogue can advertise and the engine cannot apply
// is the shape that shipped thirty-six unusable `pki-*` kinds.
func TestEveryAuthorizationFaultIsRegistered(t *testing.T) {
	registered := 0
	for _, kind := range Kinds() {
		if strings.HasPrefix(kind, KindAuthzPrefix) {
			registered++
		}
	}

	if registered != len(authz.Injectable()) {
		t.Fatalf(
			"%d authorization faults are registered and %d are injectable",
			registered,
			len(authz.Injectable()),
		)
	}

	for _, name := range authz.Injectable() {
		kind := AuthzKind(authz.Kind(name))

		if _, err := Lookup(kind); err != nil {
			t.Errorf("the engine cannot resolve %s: %v", kind, err)
		}

		if !NeedsAuthz(kind) {
			t.Errorf("%s does not ask the run for a dependency", kind)
		}

		if IsDirect(kind) {
			t.Errorf(
				"`khaos inject` offers %s, which needs a dependency it never starts",
				kind,
			)
		}
	}
}

// The whole mutation, end to end: journal it, arm it, confirm it by read-back
// on the dependency's own surface, revert it, and prove the dependency allows
// again afterwards, because the recovery window measures exactly that.
func TestTheAuthorizationFaultAppliesConfirmsAndReverts(t *testing.T) {
	served := dependency(t)

	trap := authz.Trap{Kind: authz.Deny, Credential: authzCredential}
	env := Env{Authz: served, AuthzTrap: trap}

	mutator, err := Lookup(AuthzKind(authz.Deny))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	payload, err := mutator.Plan(context.Background(), env, dockerx.Target{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	if _, confirmed, err := mutator.Confirm(
		context.Background(),
		env,
		dockerx.Target{},
	); err != nil || confirmed {
		t.Fatalf(
			"the fault confirmed BEFORE it was applied (%v, %v), so the confirmation is not reading the dependency",
			confirmed,
			err,
		)
	}

	if err := mutator.Apply(
		context.Background(),
		env,
		dockerx.Target{},
		payload,
	); err != nil {
		t.Fatalf("apply: %v", err)
	}

	detail, confirmed, err := mutator.Confirm(
		context.Background(),
		env,
		dockerx.Target{},
	)
	if err != nil || !confirmed {
		t.Fatalf("the applied fault did not confirm: %v, %v", confirmed, err)
	}

	if detail == "" {
		t.Fatal("the confirmation reported no observable")
	}

	if err := mutator.Revert(
		context.Background(),
		env,
		journal.Record{Payload: payload},
	); err != nil {
		t.Fatalf("revert: %v", err)
	}

	if _, confirmed, err := mutator.Confirm(
		context.Background(),
		env,
		dockerx.Target{},
	); err != nil || confirmed {
		t.Fatalf(
			"the fault still confirms after the revert (%v, %v)",
			confirmed,
			err,
		)
	}
}

// The credential belongs to the OPERATOR's target. A journal entry would leave
// it on disk after the run, and the revert does not need it: khaos's dependency
// allows everything it was not told to deny, so lifting the fault is a reset.
func TestTheJournalledFaultCarriesNoCredential(t *testing.T) {
	served := dependency(t)

	trap := authz.Trap{Kind: authz.Deny, Credential: authzCredential}
	env := Env{Authz: served, AuthzTrap: trap}

	mutator, err := Lookup(AuthzKind(authz.Deny))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	payload, err := mutator.Plan(context.Background(), env, dockerx.Target{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	if strings.Contains(string(payload), authzCredential) {
		t.Fatalf(
			"the journalled fault carries the credential, which would leave it on disk after the run: %s",
			payload,
		)
	}

	record := journal.Record{Payload: payload}

	var back authz.Trap
	if err := record.DecodePayload(&back); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if back.Kind != authz.Deny {
		t.Fatalf("the journalled kind is %q, want %q", back.Kind, authz.Deny)
	}
}

// A mutation whose run never started a dependency refuses by name rather than
// arming nothing and reporting success.
func TestApplyingAnAuthorizationFaultWithNoDependencyIsRefused(t *testing.T) {
	mutator, err := Lookup(AuthzKind(authz.Deny))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if _, err := mutator.Plan(
		context.Background(),
		Env{},
		dockerx.Target{},
	); !errors.Is(err, ErrNoAuthz) {
		t.Fatalf("plan without a dependency returned %v, want ErrNoAuthz", err)
	}

	if err := mutator.Apply(
		context.Background(),
		Env{},
		dockerx.Target{},
		nil,
	); !errors.Is(err, ErrNoAuthz) {
		t.Fatalf("apply without a dependency returned %v, want ErrNoAuthz", err)
	}

	if _, _, err := mutator.Confirm(
		context.Background(),
		Env{},
		dockerx.Target{},
	); !errors.Is(err, ErrNoAuthz) {
		t.Fatalf(
			"confirm without a dependency returned %v, want ErrNoAuthz",
			err,
		)
	}
}

// A cold start has nothing to disarm: the dependency lived in the process that
// died, so the fault went with it. Reporting a failure there would leave a
// reclaim retrying something that cannot exist.
func TestRevertingWithoutADependencyIsResolvedRatherThanFailed(t *testing.T) {
	mutator, err := Lookup(AuthzKind(authz.Deny))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if err := mutator.Revert(
		context.Background(),
		Env{},
		journal.Record{},
	); err != nil {
		t.Fatalf("revert after a cold start returned %v, want nil", err)
	}
}

func TestTheAuthorizationMutatorRefusesATrapTheRunDidNotArm(t *testing.T) {
	served := dependency(t)

	mutator, err := Lookup(AuthzKind(authz.Deny))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	env := Env{
		Authz:     served,
		AuthzTrap: authz.Trap{Kind: authz.Outage},
	}

	if _, err := mutator.Plan(
		context.Background(),
		env,
		dockerx.Target{},
	); !errors.Is(err, ErrTrapMismatch) {
		t.Fatalf("plan with a mismatched trap returned %v", err)
	}
}

// Keyed off the registry rather than the kind's spelling, which is the shape
// that gave the proxy and identity tiers their own bugs: a predicate reading
// the name agrees with itself about a kind that does not exist.
func TestNeedsAuthzIsDerivedFromTheRegistry(t *testing.T) {
	if NeedsAuthz(KindAuthzPrefix + "not-a-real-fault") {
		t.Error(
			"NeedsAuthz answered yes for a kind no mutation is registered under",
		)
	}

	for _, kind := range Kinds() {
		if strings.HasPrefix(kind, KindAuthzPrefix) != NeedsAuthz(kind) {
			t.Errorf("%s: NeedsAuthz reports %v", kind, NeedsAuthz(kind))
		}
	}
}

func TestTheAuthorizationFaultDescribesItself(t *testing.T) {
	for _, name := range authz.Injectable() {
		mutator, err := Lookup(AuthzKind(authz.Kind(name)))
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}

		described := mutator.Describe(Env{}, dockerx.Target{Name: "caller"})

		if described == "" {
			t.Fatalf("%s describes itself as nothing", name)
		}

		// The operator has to be told that khaos is standing in for their
		// dependency, because for the length of the run it allows every
		// credential it was not told to deny.
		if !strings.Contains(described, "khaos serves that dependency itself") {
			t.Fatalf(
				"%s does not say khaos is playing the dependency: %q",
				name,
				described,
			)
		}
	}
}
