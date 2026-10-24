// ©AngelaMos | 2026
// verifier_test.go

package verifier_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/verifier"
)

// RFC 8725 rule 2, exercised directly, because no forged token can isolate it.
//
// The matrix proves alg-confusion is refused by Correct mode, but deleting this
// check leaves the matrix green: the allowlist refuses HS256 first. And a token
// that trips the cross-check any OTHER way, such as ES256 against an RSA kid,
// also carries a signature that cannot verify, so the cross-check is never the
// only thing standing between the token and acceptance.
//
// It stays in the reference implementation anyway, because it is normative and
// because this is the file readers copy. This test is what stops it being a
// branch nothing runs.
func TestKeyAlgorithmCrossCheckRefusesAHeaderThatDisagreesWithTheKey(
	t *testing.T,
) {
	provider, v := pair(t, verifier.Correct)

	honest, err := provider.HonestToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if decision := v.Decide(honest); !decision.Allow {
		t.Fatalf("the honest token was refused: %s", decision.Reason)
	}

	token, err := idp.Parse(honest)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// The EC key khaos publishes is bound to ES256. Naming it from an RS256
	// header is the mismatch the rule forbids.
	ec, ok := signingKidFor(provider, string(idp.ES256))
	if !ok {
		t.Fatal(
			"khaos's provider publishes no ES256 key, so this mismatch is not expressible",
		)
	}

	mismatched := idp.Retarget(token, ec)

	decision := v.Decide(mismatched)

	if decision.Allow {
		t.Fatal("an RS256 header naming a key bound to ES256 was accepted")
	}

	if !containsText(decision.Reason, "is bound to") {
		t.Fatalf("the refusal was not the cross-check: %s", decision.Reason)
	}
}

// A key published for encryption must not verify signatures. It is cheap, it is
// normative, and a verifier that ignores `use` will happily check a signature
// with a key its provider never intended for signing.
//
// This needs a DOCTORED key set, and that is the whole point. An earlier version
// of this test asserted only that every key khaos publishes carries `use: sig` —
// which is true, and which is why the branch was statically unreachable from the
// entire suite. Measured: gutting the `use` check left every package green.
// khaos's provider hard-codes `use: sig` in PublicJWK, so nothing khaos serves
// can ever reach that branch; only a key set khaos did not mint can.
func TestAKeyNotMarkedForSigningIsRefused(t *testing.T) {
	provider, _ := pair(t, verifier.Correct)

	honest, err := provider.HonestToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	token, err := idp.Parse(honest)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// The real key set, with `use` rewritten to encryption. Everything else
	// about the token and the key is correct, so `use` is the only thing that
	// can refuse it.
	doctored := provider.PublishedSet()
	for i := range doctored.Keys {
		if doctored.Keys[i].Kid == token.Header.Kid {
			doctored.Keys[i].Use = "enc"
		}
	}

	served := serveSet(t, doctored)

	strict := verifier.New(verifier.Config{
		Issuer:   provider.Issuer(),
		Audience: idp.DefaultAudience,
		JWKSURI:  served,
		Mode:     verifier.Correct,
		KeyTTL:   keyTTL,
	})

	decision := strict.Decide(honest)

	if decision.Allow {
		t.Fatal("a signature was verified with a key published for encryption")
	}

	if !containsText(decision.Reason, "not a signing key") {
		t.Fatalf("the refusal was not the `use` check: %s", decision.Reason)
	}

	// The control: the same verifier against the UNDOCTORED set accepts. Without
	// it, a verifier that refused everything would pass the assertion above.
	loose := verifier.New(verifier.Config{
		Issuer:   provider.Issuer(),
		Audience: idp.DefaultAudience,
		JWKSURI:  serveSet(t, provider.PublishedSet()),
		Mode:     verifier.Correct,
		KeyTTL:   keyTTL,
	})

	if decision := loose.Decide(honest); !decision.Allow {
		t.Fatalf(
			"the same token was refused against the real key set, so the test above proves "+
				"nothing about `use`: %s",
			decision.Reason,
		)
	}
}

// One `--fail-mode` drives the whole range, and most of its values are meant for
// a different gateway. An unrecognised value has to leave this verifier CORRECT,
// or `khaos range up --fail-mode stale-rearm` would silently also break the
// verifier and every forgery experiment would report a finding it did not cause.
func TestAnUnrecognisedModeLeavesTheVerifierCorrect(t *testing.T) {
	for _, mode := range []string{"stale-rearm", "open", "", "nonsense", "ALG-ANY"} {
		if got := verifier.Resolve(mode); got != verifier.Correct {
			t.Errorf("Resolve(%q) = %q, want %q", mode, got, verifier.Correct)
		}
	}

	for _, mode := range verifier.Modes() {
		if got := verifier.Resolve(mode); string(got) != mode {
			t.Errorf("Resolve(%q) = %q, want it unchanged", mode, got)
		}
	}
}

// The decision cache has to expire, or Correct mode is DecisionCacheForever
// wearing a different name and the revocation experiment would find the same
// bug in both.
func TestTheDecisionCacheExpiresInCorrectMode(t *testing.T) {
	provider, v := pair(t, verifier.Correct)

	credential := provider.Opaque()

	if decision := v.Decide(credential); !decision.Allow {
		t.Fatalf("an active credential was refused: %s", decision.Reason)
	}

	if err := provider.Arm(
		idp.Trap{Kind: idp.Revoke, Credential: credential},
	); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	time.Sleep(decisionTTL * 3)

	if decision := v.Decide(credential); decision.Allow {
		t.Fatalf(
			"a revoked credential was still honoured after the cache lifetime: %s",
			decision.Reason,
		)
	}
}

func TestAnUnknownKidTriggersARefetch(t *testing.T) {
	provider, v := pair(t, verifier.Correct)

	honest, err := provider.HonestToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if decision := v.Decide(honest); !decision.Allow {
		t.Fatalf("warm-up refused: %s", decision.Reason)
	}

	before := provider.JWKSFetches()

	if err := provider.Arm(idp.Trap{Kind: idp.KeyRotation}); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	rotated, err := provider.TrappedToken()
	if err != nil {
		t.Fatalf("mint under the new key: %v", err)
	}

	if decision := v.Decide(rotated); !decision.Allow {
		t.Fatalf(
			"a correctly signed token under a published new key was refused: %s",
			decision.Reason,
		)
	}

	if provider.JWKSFetches() <= before {
		t.Fatal(
			"the verifier accepted a token under an unseen kid without refetching the key set",
		)
	}
}

func signingKidFor(provider *idp.Provider, alg string) (string, bool) {
	for _, key := range provider.PublishedSet().Keys {
		if key.Alg == alg {
			return key.Kid, true
		}
	}
	return "", false
}

func containsText(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// A token with no `exp` must be refused, and the branch was unreachable from the
// suite: khaos's provider always sets one. Measured — flipping that refusal to
// an allow left every package green.
//
// `exp` is the ONLY revocation mechanism a locally validating verifier has, so a
// token without one is a credential that can never be taken away.
func TestATokenWithNoExpiryIsRefused(t *testing.T) {
	provider, v := pair(t, verifier.Correct)

	honest, err := provider.HonestToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if decision := v.Decide(honest); !decision.Allow {
		t.Fatalf("the honest token was refused: %s", decision.Reason)
	}

	// The signature will not verify once `exp` is removed, so this asserts the
	// CLAIM check specifically rather than the signature check: the claim branch
	// runs after the signature one, so a token stripped of `exp` has to reach it
	// another way.
	stripped := idp.WithoutExpiry(provider)

	decision := v.Decide(stripped)

	if decision.Allow {
		t.Fatal(
			"a token carrying no `exp` was accepted, so nothing can ever revoke it",
		)
	}

	if !containsText(decision.Reason, "no `exp`") {
		t.Fatalf("the refusal was not the expiry check: %s", decision.Reason)
	}
}

// RFC 8725 section 3.11 explicit typing, and RFC 9068's `at+jwt`. Section 3.12
// is why it matters: without it this verifier cannot refuse an ID token
// presented where an access token belongs.
//
// The check did not exist, and `internal/idp/mint.go` cited it to justify every
// forged token carrying `at+jwt`. Measured before it was implemented: `typ` of
// `id_token`, `JWT`, `""` and `anything-at-all` were all accepted.
func TestATokenOfTheWrongTypeIsRefused(t *testing.T) {
	provider, v := pair(t, verifier.Correct)

	for _, typ := range []string{"JWT", "id_token", "dpop+jwt", ""} {
		retyped := idp.Retyped(provider, typ)

		decision := v.Decide(retyped)

		if decision.Allow {
			t.Errorf(
				"a token with typ %q was accepted where an access token belongs",
				typ,
			)
			continue
		}

		if !containsText(decision.Reason, "typ") {
			t.Errorf(
				"typ %q was refused for the wrong reason: %s",
				typ,
				decision.Reason,
			)
		}
	}

	// The control. Every forged token khaos mints carries `at+jwt` precisely so
	// this check does not pre-empt the one each trap probes.
	honest, err := provider.HonestToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if decision := v.Decide(honest); !decision.Allow {
		t.Fatalf(
			"the explicit-typing check refuses khaos's own correct token: %s",
			decision.Reason,
		)
	}
}

func TestUnknownKidsDoNotAmplifyIntoOneFetchEach(t *testing.T) {
	provider, v := pair(t, verifier.Correct)

	honest, err := provider.HonestToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if decision := v.Decide(honest); !decision.Allow {
		t.Fatalf("warm-up refused: %s", decision.Reason)
	}

	token, err := idp.Parse(honest)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	const attempts = 200

	before := provider.JWKSFetches()

	for i := range attempts {
		_ = v.Decide(
			idp.Retarget(token, "attacker-chosen-kid-"+strconv.Itoa(i)),
		)
	}

	fetches := provider.JWKSFetches() - before

	if fetches >= attempts {
		t.Fatalf(
			"%d requests carrying unknown kids caused %d upstream fetches; an "+
				"attacker-controlled header field must not be a one-to-one amplifier",
			attempts,
			fetches,
		)
	}

	if err := provider.Arm(idp.Trap{Kind: idp.KeyRotation}); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	rotated, err := provider.TrappedToken()
	if err != nil {
		t.Fatalf("mint under the new key: %v", err)
	}

	deadline := time.Now().Add(rotationPickupBudget)
	var last string

	for time.Now().Before(deadline) {
		decision := v.Decide(rotated)
		if decision.Allow {
			return
		}
		last = decision.Reason
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf(
		"a correctly signed token under a newly published key was still refused after %s, "+
			"so the amplifier fix turned a routine rotation into an outage: %s",
		rotationPickupBudget,
		last,
	)
}

// How long a legitimate rotation may take to be picked up after an unknown-kid
// burst has tripped the refetch cooldown. It is comfortably above both the
// cooldown and the key lifetime these tests use, so a failure here means the
// rotation is never picked up rather than merely delayed.
const rotationPickupBudget = 2 * time.Second
