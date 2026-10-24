// ©AngelaMos | 2026
// observe_test.go

package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

const (
	testDelay  = 300 * time.Millisecond
	testIssuer = "http://khaos.test:1234"
)

// armable is one trap plus whatever has to be true before it can be armed. The
// two traps that need a subject supply it here, because a trap armed without one
// is refused by Validate and would never reach the oracle.
type armable struct {
	kind    Kind
	prepare func(*Provider) Trap
}

func everyTrap() []armable {
	return []armable{
		{kind: AlgNone},
		{kind: AlgConfusion, prepare: func(*Provider) Trap {
			return Trap{Kind: AlgConfusion, KeyForm: SPKIPEM}
		}},
		{kind: EmbeddedJWK},
		{kind: ClaimExpired, prepare: func(*Provider) Trap {
			return Trap{Kind: ClaimExpired, Delay: time.Hour}
		}},
		{kind: ClaimNotYetValid, prepare: func(*Provider) Trap {
			return Trap{Kind: ClaimNotYetValid, Delay: time.Hour}
		}},
		{kind: ClaimWrongAudience},
		{kind: ClaimForeignIssuer},
		{kind: SignatureTruncated},
		{kind: SignatureZero},
		{kind: SignatureWeakKey},
		{kind: JWKSUnreachable},
		{kind: KidRollover},
		{kind: KeyRotation},
		{kind: IntrospectionError},
		{kind: IntrospectionMalformed},
		{kind: IntrospectionSlow, prepare: func(*Provider) Trap {
			return Trap{Kind: IntrospectionSlow, Delay: testDelay}
		}},
		{kind: Revoke, prepare: func(p *Provider) Trap {
			return Trap{Kind: Revoke, Credential: p.Revocable()}
		}},
	}
}

func (a armable) trap(p *Provider) Trap {
	if a.prepare != nil {
		return a.prepare(p)
	}
	return Trap{Kind: a.kind}
}

// The census: every trap khaos advertises has to be armable and confirmable.
// A trap that cannot be confirmed is a fault khaos would apply and then measure
// without knowing it landed, which is the one thing the engine refuses to do.
func TestEveryTrapIsConfirmedByItsOwnObservable(t *testing.T) {
	cases := everyTrap()

	if len(cases) != len(Kinds()) {
		t.Fatalf(
			"this test covers %d traps and khaos advertises %d; a new trap needs a case here",
			len(cases),
			len(Kinds()),
		)
	}

	for _, each := range cases {
		t.Run(string(each.kind), func(t *testing.T) {
			p := listening(t)

			trap := each.trap(p)

			if err := p.Arm(trap); err != nil {
				t.Fatalf("arm %s: %v", each.kind, err)
			}

			observable, confirmed, err := p.Observe(
				context.Background(),
				each.kind,
			)
			if err != nil {
				t.Fatalf("observe %s: %v", each.kind, err)
			}

			if !confirmed {
				t.Fatalf(
					"%s was armed and its own observable did not appear",
					each.kind,
				)
			}

			if observable == "" {
				t.Fatalf(
					"%s confirmed with no observable; the run record would carry no evidence",
					each.kind,
				)
			}
		})
	}
}

// The negative control, and the reason Inert exists at all. Without a way to arm
// a trap that does NOT happen, every assertion above is satisfied by an oracle
// gutted to `return true`. Measured on the fault proxy: exactly that gut left
// every package and the Docker gate green.
func TestEveryTrapRefusesConfirmationWhenItDidNotHappen(t *testing.T) {
	for _, each := range everyTrap() {
		t.Run(string(each.kind), func(t *testing.T) {
			p := listening(t)

			// Inert BEFORE arming, so the state-changing traps never perform
			// their change and the oracle has a real nothing to look at.
			p.Inert(true)

			trap := each.trap(p)

			if err := p.Arm(trap); err != nil {
				t.Fatalf("arm %s inert: %v", each.kind, err)
			}

			_, confirmed, _ := p.Observe(context.Background(), each.kind)

			if confirmed {
				t.Fatalf(
					"%s confirmed itself while inert, so its oracle cannot tell a landed trap from one that did nothing",
					each.kind,
				)
			}
		})
	}
}

func TestObserveRefusesWhenNothingIsArmed(t *testing.T) {
	p := listening(t)

	if _, confirmed, err := p.Observe(
		context.Background(),
		AlgNone,
	); confirmed ||
		err == nil {
		t.Fatalf(
			"an unarmed provider confirmed a trap: confirmed=%v err=%v",
			confirmed,
			err,
		)
	}
}

func TestObserveRefusesADifferentTrapThanTheOneArmed(t *testing.T) {
	p := listening(t)

	if err := p.Arm(Trap{Kind: AlgNone}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	if _, confirmed, err := p.Observe(
		context.Background(),
		SignatureTruncated,
	); confirmed ||
		err == nil {
		t.Fatalf(
			"the provider confirmed %s while holding %s",
			SignatureTruncated,
			AlgNone,
		)
	}
}

// Disarm has to put the key material back, or the recovery phase measures a
// provider the fault permanently changed and no rotation experiment can ever
// report that the target came back.
func TestDisarmRestoresTheSigningKeyARotationReplaced(t *testing.T) {
	p := listening(t)

	before := p.SigningKid()

	if err := p.Arm(Trap{Kind: KidRollover}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	during := p.SigningKid()
	if during == before {
		t.Fatal("arming a rollover did not change the signing key")
	}

	if p.PublishedSet().Has(before) {
		t.Fatal("the retired key is still published, so nothing was withdrawn")
	}

	p.Disarm()

	if p.SigningKid() != before {
		t.Fatalf(
			"after disarm the signing key is %q, want the original %q",
			p.SigningKid(),
			before,
		)
	}

	if !p.PublishedSet().Has(before) {
		t.Fatal("after disarm the original key is still not published")
	}
}

func TestDisarmRestoresARevokedGrant(t *testing.T) {
	p := listening(t)

	credential := p.Revocable()

	if err := p.Arm(Trap{Kind: Revoke, Credential: credential}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	if active := p.active(t, credential); active {
		t.Fatal("the credential is still active after being revoked")
	}

	p.Disarm()

	if active := p.active(t, credential); !active {
		t.Fatal(
			"disarm did not restore the revoked grant, so recovery cannot be measured",
		)
	}
}

// A rotation with overlap must keep the old key published. Without this the
// availability-preserving rotation is indistinguishable from the withdrawing
// one, and the two experiments built on them would measure the same thing.
func TestRotationWithOverlapKeepsBothKeysPublished(t *testing.T) {
	p := listening(t)

	before := p.SigningKid()

	if err := p.Arm(Trap{Kind: KeyRotation}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	set := p.PublishedSet()

	if !set.Has(before) {
		t.Fatal("an overlapping rotation withdrew the old key")
	}

	if !set.Has(p.SigningKid()) {
		t.Fatal("an overlapping rotation did not publish the new key")
	}

	if p.SigningKid() == before {
		t.Fatal("an overlapping rotation did not change the signing key")
	}
}

// Revoking something the provider never issued has to fail. A revocation that
// quietly succeeded would make every later acceptance correct behaviour while
// khaos reported it as a finding.
func TestArmRefusesToRevokeACredentialItNeverIssued(t *testing.T) {
	p := listening(t)

	if err := p.Arm(
		Trap{Kind: Revoke, Credential: "khaos-opaque-never-issued"},
	); err == nil {
		t.Fatal("the provider revoked a credential it never issued")
	}
}

// The provider has to be indistinguishable from a correct one when nothing is
// armed, because every experiment's baseline is measured against it.
func TestAnUnarmedProviderMintsOnlyCorrectTokens(t *testing.T) {
	p := listening(t)
	p.SetIssuer(testIssuer)

	for _, mint := range []func() (string, error){p.HonestToken, p.TrappedToken} {
		raw, err := mint()
		if err != nil {
			t.Fatalf("mint: %v", err)
		}

		token, err := Parse(raw)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}

		if token.Header.Alg != string(RS256) {
			t.Errorf("alg is %q, want %q", token.Header.Alg, RS256)
		}

		if token.Header.JWK != nil {
			t.Error("an unarmed provider embedded a key in the header")
		}

		if token.Claims.Issuer != testIssuer {
			t.Errorf("iss is %q, want %q", token.Claims.Issuer, testIssuer)
		}

		if !token.Claims.Audience.Contains(DefaultAudience) {
			t.Errorf(
				"aud is %q, want %q",
				token.Claims.Audience,
				DefaultAudience,
			)
		}

		if !verifiesUnderSet(p.PublishedSet(), token) {
			t.Error(
				"an unarmed provider minted a token that does not verify under its own published keys",
			)
		}

		if token.Claims.Expires == nil ||
			time.Unix(*token.Claims.Expires, 0).Before(time.Now()) {
			t.Error("an unarmed provider minted an already-expired token")
		}
	}
}

// The valid stream carries HonestToken and must keep carrying a usable
// credential whatever is armed. A stream that drifted into forged tokens would
// make every verdict read as the target having crashed.
func TestHonestTokenIgnoresEveryArmedForgery(t *testing.T) {
	p := listening(t)
	p.SetIssuer(testIssuer)

	for _, each := range everyTrap() {
		trap := each.trap(p)
		if !trap.Forgery() {
			continue
		}

		if err := p.Arm(trap); err != nil {
			t.Fatalf("arm %s: %v", each.kind, err)
		}

		raw, err := p.HonestToken()
		if err != nil {
			t.Fatalf("honest mint under %s: %v", each.kind, err)
		}

		token, err := Parse(raw)
		if err != nil {
			t.Fatalf("parse under %s: %v", each.kind, err)
		}

		if token.Header.Alg != string(RS256) ||
			token.Claims.Issuer != testIssuer {
			t.Errorf(
				"%s leaked into the honest token: alg=%q iss=%q",
				each.kind,
				token.Header.Alg,
				token.Claims.Issuer,
			)
		}

		if !verifiesUnderSet(p.PublishedSet(), token) {
			t.Errorf("%s left the honest token unverifiable", each.kind)
		}

		p.Disarm()
	}
}

// The attacker key is the one key the provider must never advertise. If it were
// published, a verifier resolving it would be doing the correct thing and the
// trap would report a finding that is not one.
func TestTheAttackerKeyIsNeverPublished(t *testing.T) {
	p := listening(t)

	if err := p.Arm(Trap{Kind: EmbeddedJWK}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	raw, err := p.TrappedToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if token.Header.JWK == nil {
		t.Fatal("the embedded-key trap minted a token with no `jwk` header")
	}

	if p.PublishedSet().Has(token.Header.JWK.Kid) {
		t.Fatal(
			"khaos published the attacker key, so resolving it would be correct behaviour",
		)
	}

	if !verifiesUnder(*token.Header.JWK, token) {
		t.Fatal(
			"the embedded key does not verify the token it is embedded in, so no verifier could accept it for the reason the trap claims",
		)
	}
}

func TestJWKSFetchesAreCounted(t *testing.T) {
	p := listening(t)

	addr, err := p.Addr()
	if err != nil {
		t.Fatalf("addr: %v", err)
	}

	before := p.JWKSFetches()

	for range 3 {
		if _, _, err := probeRoute(
			context.Background(),
			httpClient(),
			"http://"+addr+RouteJWKS,
		); err != nil {
			t.Fatalf("fetch: %v", err)
		}
	}

	if got := p.JWKSFetches() - before; got != 3 {
		t.Fatalf("counted %d JWK Set fetches, want 3", got)
	}
}

// The health route is the control for every endpoint trap, so it must never
// participate in one. If it did, khaos could not tell its own provider being
// gone from its own provider lying.
func TestHealthIsNeverFaulted(t *testing.T) {
	for _, kind := range []Kind{JWKSUnreachable, IntrospectionError, IntrospectionMalformed} {
		p := listening(t)

		if err := p.Arm(Trap{Kind: kind}); err != nil {
			t.Fatalf("arm %s: %v", kind, err)
		}

		addr, err := p.Addr()
		if err != nil {
			t.Fatalf("addr: %v", err)
		}

		status, _, err := probeRoute(
			context.Background(),
			httpClient(),
			"http://"+addr+RouteHealth,
		)
		if err != nil || status != 200 {
			t.Fatalf("health answered %d (%v) with %s armed", status, err, kind)
		}

		_ = p.Close()
	}
}

// The production ordering: pin the issuer, THEN bind. khaos always does it that
// way round, because it learns the issuer from the target's own environment
// before it knows where it will be listening.
//
// Listen used to overwrite the pinned issuer with its own listener address, so
// every token khaos minted was refused by the target on the issuer check and the
// run reported `baseline-not-met / "the valid credential was never accepted"` —
// a true statement that blamed the target for khaos sending the wrong thing.
//
// No existing test saw it: a test that reads Issuer() after Listen() agrees with
// itself whatever Listen did. This one states the expected string up front.
func TestListenDoesNotOverwriteAPinnedIssuer(t *testing.T) {
	p, err := New(Config{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	p.SetIssuer(testIssuer)

	if err := p.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("bind: %v", err)
	}

	addr, err := p.Addr()
	if err != nil {
		t.Fatalf("addr: %v", err)
	}

	if p.Issuer() != testIssuer {
		t.Fatalf(
			"after binding on %s the issuer is %q, want the pinned %q",
			addr,
			p.Issuer(),
			testIssuer,
		)
	}

	raw, err := p.HonestToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if token.Claims.Issuer != testIssuer {
		t.Fatalf(
			"the minted token says iss %q, want the pinned %q; a target configured for "+
				"the pinned issuer refuses this and the run blames the target",
			token.Claims.Issuer,
			testIssuer,
		)
	}
}

// The other half: a provider nobody pinned still names itself, so it is usable
// without the range and `khaos plan` can describe it.
func TestAnUnpinnedProviderNamesItselfAfterBinding(t *testing.T) {
	p, err := New(Config{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	if p.Issuer() != "" {
		t.Fatalf(
			"an unbound, unpinned provider claims the issuer %q",
			p.Issuer(),
		)
	}

	if err := p.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("bind: %v", err)
	}

	addr, err := p.Addr()
	if err != nil {
		t.Fatalf("addr: %v", err)
	}

	if want := "http://" + addr; p.Issuer() != want {
		t.Fatalf("issuer = %q, want %q", p.Issuer(), want)
	}
}

func TestKhaosOwnConfirmationDoesNotInflateTheFetchCount(t *testing.T) {
	for _, kind := range []Kind{JWKSUnreachable, KidRollover, KeyRotation} {
		t.Run(string(kind), func(t *testing.T) {
			p := listening(t)

			before := p.JWKSFetches()

			if err := p.Arm(Trap{Kind: kind}); err != nil {
				t.Fatalf("arm: %v", err)
			}

			if _, confirmed, err := p.Observe(
				context.Background(),
				kind,
			); err != nil ||
				!confirmed {
				t.Fatalf("confirm said %v (%v)", confirmed, err)
			}

			if after := p.JWKSFetches(); after != before {
				t.Fatalf(
					"confirming %s moved the reported fetch count from %d to %d; the number has "+
						"to describe the TARGET's refetch behaviour, not khaos's own probing",
					kind,
					before,
					after,
				)
			}
		})
	}
}

// And the correction must not hide a real fetch.
func TestATargetsFetchIsStillCounted(t *testing.T) {
	p := listening(t)

	addr, err := p.Addr()
	if err != nil {
		t.Fatalf("addr: %v", err)
	}

	if err := p.Arm(Trap{Kind: KidRollover}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	if _, confirmed, err := p.Observe(
		context.Background(),
		KidRollover,
	); err != nil ||
		!confirmed {
		t.Fatalf("confirm said %v (%v)", confirmed, err)
	}

	before := p.JWKSFetches()

	for range 4 {
		if _, _, err := probeRoute(
			context.Background(),
			httpClient(),
			"http://"+addr+RouteJWKS,
		); err != nil {
			t.Fatalf("fetch: %v", err)
		}
	}

	if got := p.JWKSFetches() - before; got != 4 {
		t.Fatalf(
			"counted %d target fetches, want 4; the correction is swallowing real ones",
			got,
		)
	}
}

// A conforming RFC 7662 client has to work. khaos read the token only from the
// query string and its own client sent it only that way, so the two agreed with
// each other and with nothing else: an external client following the
// specification got `active: false` for a perfectly valid credential.
//
// This is a REQUEST-level contract test on purpose. Going through khaos's own
// helper would exercise the same private convention on both sides and prove
// nothing about interoperability.
func TestIntrospectionAnswersTheWireFormatTheRFCSpecifies(t *testing.T) {
	p := listening(t)

	addr, err := p.Addr()
	if err != nil {
		t.Fatalf("addr: %v", err)
	}

	credential := p.Revocable()
	endpoint := "http://" + addr + RouteIntrospect

	post := func() Introspection {
		t.Helper()

		response, err := httpClient().PostForm(endpoint, url.Values{ParamToken: {credential}})
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer func() { _ = response.Body.Close() }()

		if response.StatusCode != http.StatusOK {
			t.Fatalf("introspection answered %d", response.StatusCode)
		}

		var body Introspection
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}

		return body
	}

	if body := post(); !body.Active {
		t.Fatal(
			"a form-encoded POST for an active credential reported it inactive; no conforming " +
				"client can establish a baseline against this provider",
		)
	}

	if err := p.Arm(Trap{Kind: Revoke, Credential: credential}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if body := post(); body.Active {
		t.Fatal("a form-encoded POST reported a revoked credential active")
	}
}

// Revocation takes the same wire format, per RFC 7009 section 2.1.
func TestRevocationAcceptsTheFormEncodedPost(t *testing.T) {
	p := listening(t)

	addr, err := p.Addr()
	if err != nil {
		t.Fatalf("addr: %v", err)
	}

	credential := p.Opaque()

	response, err := httpClient().PostForm("http://"+addr+RouteRevoke, url.Values{ParamToken: {credential}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		t.Fatalf(
			"a form-encoded revocation answered %d, so a conforming client cannot revoke",
			response.StatusCode,
		)
	}

	if p.active(t, credential) {
		t.Fatal("the credential is still active after a conforming revocation")
	}
}
