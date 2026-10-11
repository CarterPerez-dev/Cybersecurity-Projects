// ©AngelaMos | 2026
// verifier.go

// Package verifier is the RANGE's reference token verifier: the thing under
// test, not part of khaos's own machinery. It lives under internal/ rather than
// inside cmd/khaos-range so that khaos's test suite can import it and pin every
// forgery trap against it, which is the only way to know a trap is detectable at
// all before pointing it at somebody's real service.
//
// Mode Correct is a genuinely correct verifier and it has to stay that way. A
// teaching repo's "correct" side is what readers copy, and the range has already
// shipped a reference gateway with two defects of its own. Every other mode is
// exactly one line different from Correct, and each of those lines is a named,
// CVE-anchored bug from research 07 section 1.5.
package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/idp"
)

// Mode is which bug the range's verifier is carrying. Each one is a single
// structural defect, and several traps are caught by one mode because they share
// a root cause: that sharing is the research's own framing, not a shortcut.
type Mode string

const (
	// Correct follows RFC 8725. It is the control for every other mode.
	Correct Mode = "closed"

	// AlgAny resolves the key and THEN dispatches on the header's algorithm,
	// with no server-side allowlist and no key-to-algorithm cross-check. That
	// one inversion is the root cause of both `alg: none` acceptance and
	// HS256/RS256 confusion, which is why one mode catches both.
	AlgAny Mode = "alg-any"

	// TrustEmbeddedKey resolves the signing key from the token's own `jwk`
	// header. RFC 8725 rule 4 is the single sentence that forbids it.
	TrustEmbeddedKey Mode = "trust-embedded-key"

	// SkipClaims verifies the signature and then validates nothing: not `exp`,
	// not `nbf`, not `aud`, not `iss`, not `typ`.
	SkipClaims Mode = "skip-claims"

	// WeakSignature treats an absent, all-zero or short-of-the-algorithm
	// signature as a pass rather than as a failure.
	WeakSignature Mode = "weak-sig"

	// AnyKeySize drops the minimum modulus check and verifies with raw modular
	// exponentiation, so Go's own 1024-bit floor never applies either.
	AnyKeySize Mode = "any-key-size"

	// JWKSFailOpen decodes the claims without verifying the signature when the
	// JWK Set cannot be fetched. Research 07 calls this the highest-value trap
	// in its archive: unit tests pass, integration tests pass, and the branch is
	// reachable only while the provider is down.
	JWKSFailOpen Mode = "jwks-fail-open"

	// JWKSCacheForever never expires the key set and never refetches. It is the
	// mirror of JWKSFailOpen: not permissive, stale, which means a key the
	// provider rotated out is still a valid signing key here.
	JWKSCacheForever Mode = "jwks-cache-forever"

	// JWKSRefetchOnKidOnly refetches when it meets an unknown `kid` and never on
	// a timer. It is the most realistic of the three key-cache modes and the one
	// research 07 section 2.3 says carries "the whole finding": the eviction of a
	// retired key is a SIDE EFFECT of the refetch a new-key token triggers, so a
	// target with no new-key traffic keeps honouring the retired key for an
	// unbounded time.
	//
	// It exists because without it nothing in the range demonstrates that case,
	// and khaos's own `identity.kid_rollover` was silently supplying the new-key
	// traffic that hides it.
	JWKSRefetchOnKidOnly Mode = "jwks-kid-only"

	// IntrospectFailOpen treats a non-200, an unparseable body or a timeout as
	// `active: true`, which is a value RFC 7662 never provides.
	IntrospectFailOpen Mode = "introspect-fail-open"

	// DecisionCacheForever caches an authorization decision with no expiry, so a
	// credential revoked at a fully reachable provider is honoured forever.
	DecisionCacheForever Mode = "decision-cache-forever"
)

const (
	// The allowlist. It is a property of the verifier's configuration and the
	// token never selects from it, which is RFC 8725 section 3.1.
	allowedRS = string(idp.RS256)
	allowedES = string(idp.ES256)

	// Real verifiers tolerate a little clock skew and so does this one, because
	// a reference implementation with zero tolerance is one readers will copy
	// and then work around. The claim traps move their claim by far more than
	// this.
	clockSkew = 60 * time.Second

	// Short on purpose. A key set cached for longer than a khaos run would never
	// be refetched during one, so the fetch-failure branch every JWKS trap
	// exists to probe would be unreachable and the experiment would measure
	// nothing.
	DefaultKeyTTL = time.Second

	// DefaultDecisionTTL is the authorization-decision cache lifetime for opaque
	// credentials.
	DefaultDecisionTTL = 2 * time.Second

	upstreamTimeout = 500 * time.Millisecond

	// RFC 9068's media type for an OAuth 2.0 access token.
	typAccessToken = "at+jwt"

	minimumModulusBits = 1024

	// DefaultNegativeTTL and DefaultForcedCooldown bound the unknown-kid refetch.
	// The cooldown is short on purpose: see the note in keySet.
	DefaultNegativeTTL    = time.Second
	DefaultForcedCooldown = 100 * time.Millisecond

	p256SignatureBytes = 64

	paramToken = "token"

	errNoKeys = "the key set could not be fetched"
)

// Decision is what the verifier concluded and why. The reason is for the
// fixture's own tests: an experiment must never depend on it, because khaos
// judges a target from the outside and a real target volunteers nothing.
type Decision struct {
	Allow  bool
	Reason string
}

type cachedDecision struct {
	allow   bool
	expires time.Time
	forever bool
}

type Verifier struct {
	issuer        string
	audience      string
	jwksURI       string
	introspectURI string
	mode          Mode
	keyTTL        time.Duration
	decisionTTL   time.Duration

	client *http.Client
	now    func() time.Time

	// negativeTTL is how long an unknown kid is refused without another fetch,
	// and forcedCooldown caps the forced-fetch rate. Both bound the amplifier
	// that an attacker-controlled `kid` otherwise is.
	negativeTTL    time.Duration
	forcedCooldown time.Duration

	// fetching serialises the upstream fetch itself, so concurrent requests
	// carrying the same unknown kid cause one fetch rather than one each. It is
	// a separate mutex from mu because mu guards the cache and must not be held
	// across a network call.
	fetching sync.Mutex

	mu          sync.Mutex
	keys        idp.JWKSet
	keysAt      time.Time
	haveKeys    bool
	lastForced  time.Time
	unknownKids map[string]time.Time
	decisions   map[string]cachedDecision
}

type Config struct {
	Issuer        string
	Audience      string
	JWKSURI       string
	IntrospectURI string
	Mode          Mode
	KeyTTL        time.Duration
	DecisionTTL   time.Duration
	Now           func() time.Time
	Client        *http.Client

	// NegativeTTL and ForcedCooldown bound the unknown-kid refetch.
	NegativeTTL    time.Duration
	ForcedCooldown time.Duration
}

func New(config Config) *Verifier {
	if config.Mode == "" {
		config.Mode = Correct
	}
	if config.KeyTTL <= 0 {
		config.KeyTTL = DefaultKeyTTL
	}
	if config.DecisionTTL <= 0 {
		config.DecisionTTL = DefaultDecisionTTL
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.Client == nil {
		config.Client = &http.Client{Timeout: upstreamTimeout}
	}
	if config.Audience == "" {
		config.Audience = idp.DefaultAudience
	}

	if config.NegativeTTL <= 0 {
		config.NegativeTTL = DefaultNegativeTTL
	}
	if config.ForcedCooldown <= 0 {
		config.ForcedCooldown = DefaultForcedCooldown
	}

	return &Verifier{
		issuer:         config.Issuer,
		audience:       config.Audience,
		jwksURI:        config.JWKSURI,
		introspectURI:  config.IntrospectURI,
		mode:           config.Mode,
		keyTTL:         config.KeyTTL,
		decisionTTL:    config.DecisionTTL,
		client:         config.Client,
		now:            config.Now,
		negativeTTL:    config.NegativeTTL,
		forcedCooldown: config.ForcedCooldown,
		unknownKids:    map[string]time.Time{},
		decisions:      map[string]cachedDecision{},
	}
}

func Modes() []string {
	return []string{
		string(Correct),
		string(AlgAny),
		string(TrustEmbeddedKey),
		string(SkipClaims),
		string(WeakSignature),
		string(AnyKeySize),
		string(JWKSFailOpen),
		string(JWKSCacheForever),
		string(JWKSRefetchOnKidOnly),
		string(IntrospectFailOpen),
		string(DecisionCacheForever),
	}
}

func Known(mode string) bool {
	return slices.Contains(Modes(), mode)
}

// Decide is the whole verifier. A credential that parses as a JWS is validated
// locally; anything else is introspected. Real gateways do exactly this, and the
// two strategies have genuinely different outage shapes, which is why the range
// has to demonstrate both.
func (v *Verifier) Decide(credential string) Decision {
	if credential == "" {
		return Decision{Reason: "no credential was presented"}
	}

	// Dispatch on the credential's SHAPE, not on whether khaos's parser happens
	// to accept it. Keying on a parse failure silently rerouted legal JWTs to
	// introspection: a token with `"aud": ["a","b"]`, which RFC 7519 section
	// 4.1.3 explicitly permits, failed to unmarshal and was introspected as if
	// it were an opaque credential. Under a fail-open introspection mode with no
	// endpoint configured, that token would have been allowed.
	if !idp.LooksLikeJWS(credential) {
		return v.introspect(credential)
	}

	token, err := idp.Parse(credential)
	if err != nil {
		return Decision{Reason: "the credential is shaped like a JWS and does not parse as one"}
	}

	return v.validate(token)
}

func (v *Verifier) validate(token idp.Token) Decision {
	keys, keysErr := v.keySet(token.Header.Kid)

	if keysErr != nil {
		// The highest-value trap in the archive, and it is this one branch. The
		// developer wanted availability; the reviewer read it as graceful
		// degradation. It is an unauthenticated-request-accepted path gated on
		// an outage.
		if v.mode == JWKSFailOpen {
			return Decision{Allow: true, Reason: "the key set was unavailable, so the signature was not checked"}
		}
		return Decision{Reason: errNoKeys}
	}

	alg, ok := v.algorithm(token.Header.Alg)
	if !ok {
		return Decision{Reason: fmt.Sprintf("algorithm %q is not acceptable", token.Header.Alg)}
	}

	// `alg: none` only ever reaches here under AlgAny, because the allowlist
	// above refuses it otherwise. RFC 7515 registers it as "no digital signature
	// or MAC performed", and a verifier that routes on it has agreed.
	if alg == string(idp.None) {
		return v.claims(token, "the token declared no signature and it was believed")
	}

	key, found := v.resolve(keys, token)
	if !found {
		return Decision{Reason: fmt.Sprintf("no key matches kid %q", token.Header.Kid)}
	}

	// RFC 8725 rule 2: "Each key MUST be used with exactly one algorithm, and
	// this MUST be checked when the cryptographic operation is performed." This
	// single line is what kills algorithm confusion, and AlgAny is what happens
	// without it.
	if v.mode != AlgAny && key.Alg != "" && key.Alg != alg {
		return Decision{Reason: fmt.Sprintf("kid %q is bound to %q and the token asked for %q", key.Kid, key.Alg, alg)}
	}

	if key.Use != "" && key.Use != idp.UseSignature {
		return Decision{Reason: fmt.Sprintf("kid %q is not a signing key", key.Kid)}
	}

	if reason, ok := v.signature(key, token, alg); !ok {
		return Decision{Reason: reason}
	}

	return v.claims(token, "the signature verified")
}

// algorithm is the allowlist, and under AlgAny it is the token's own choice.
// The whole difference between the two is whether the server or the attacker
// picks.
func (v *Verifier) algorithm(declared string) (string, bool) {
	if v.mode == AlgAny {
		return declared, declared != ""
	}

	if declared == allowedRS || declared == allowedES {
		return declared, true
	}

	return "", false
}

// resolve finds the key. Correct mode resolves ONLY from the fetched key set;
// TrustEmbeddedKey prefers the one the token brought with it, which is RFC 8725
// rule 4 violated and CVE-2018-0114 in the wild.
func (v *Verifier) resolve(keys idp.JWKSet, token idp.Token) (idp.JWK, bool) {
	if v.mode == TrustEmbeddedKey && token.Header.JWK != nil {
		return *token.Header.JWK, true
	}

	key, err := keys.Lookup(token.Header.Kid)
	if err != nil {
		return idp.JWK{}, false
	}

	return key, true
}

func (v *Verifier) signature(key idp.JWK, token idp.Token, alg string) (string, bool) {
	// A signature that is absent, all zero, or shorter than THIS KEY produces is
	// treated as a pass. CVE-2020-28042 is the no-minimum-length shape and
	// CVE-2022-21449 is the all-zero shape; measured on go1.26.5, ecdsa.Verify
	// rejects r = s = 0, so a Go verifier only falls for the second one by
	// skipping the check, which is precisely what this does.
	//
	// The length is measured against the resolved key rather than against a
	// constant, which is what the CVE actually describes: "a valid minimum
	// length for a signature" is a property of the key, not of the algorithm
	// name. A constant floor also made this mode accept the weak-key token,
	// whose signature is legitimately short because its modulus is, and that
	// overlap would have let one mode alibi another in the matrix below.
	if v.mode == WeakSignature && weakSignature(key, token.Signature, alg) {
		return "", true
	}

	digest := sha256.Sum256(token.SigningInput)

	switch alg {
	case allowedRS:
		pub, err := key.RSAPublicKey()
		if err != nil {
			return "the key is not usable as RSA", false
		}

		// An explicit floor, rather than relying on crypto/rsa to have one. The
		// standard library does enforce 1024 bits, but a reference
		// implementation that depends on that is correct by luck, and the floor
		// is a GODEBUG away from being gone.
		if v.mode != AnyKeySize && pub.N.BitLen() < minimumModulusBits {
			return fmt.Sprintf("kid %q has a %d-bit modulus", key.Kid, pub.N.BitLen()), false
		}

		if v.mode == AnyKeySize {
			if !verifyRaw(pub, digest[:], token.Signature) {
				return "the signature does not verify", false
			}
			return "", true
		}

		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], token.Signature); err != nil {
			return "the signature does not verify", false
		}

		return "", true

	case allowedES:
		pub, err := key.ECPublicKey()
		if err != nil || len(token.Signature) != p256SignatureBytes {
			return "the signature is not a P-256 signature", false
		}

		r := new(big.Int).SetBytes(token.Signature[:p256SignatureBytes/2])
		s := new(big.Int).SetBytes(token.Signature[p256SignatureBytes/2:])

		if !ecdsa.Verify(pub, digest[:], r, s) {
			return "the signature does not verify", false
		}

		return "", true

	case string(idp.HS256):
		// Reachable only under AlgAny. The verifier is configured with an RSA
		// public key and has just been told to use it as an HMAC secret, which
		// it can do, because the bytes are bytes. The attacker had those bytes
		// all along: they are public.
		secret, err := publicBytes(key)
		if err != nil {
			return "the key cannot be used as a MAC secret", false
		}

		mac := hmac.New(sha256.New, secret)
		mac.Write(token.SigningInput)

		if !hmac.Equal(mac.Sum(nil), token.Signature) {
			return "the MAC does not verify", false
		}

		return "", true

	default:
		return fmt.Sprintf("algorithm %q cannot be verified", alg), false
	}
}

func weakSignature(key idp.JWK, signature []byte, alg string) bool {
	if len(signature) == 0 || allZero(signature) {
		return true
	}

	switch alg {
	case allowedES:
		return len(signature) < p256SignatureBytes
	case allowedRS:
		pub, err := key.RSAPublicKey()
		if err != nil {
			return false
		}
		return len(signature) < (pub.N.BitLen()+7)/8
	default:
		return false
	}
}

// claims is the four checks a stateless verifier has, and SkipClaims is all four
// missing at once. `exp` is the one that matters most: it is the ONLY revocation
// mechanism a locally validating verifier has, so a verifier that ignores it has
// no revocation at all.
func (v *Verifier) claims(token idp.Token, reason string) Decision {
	if v.mode == SkipClaims {
		return Decision{Allow: true, Reason: reason + ", and no claim was checked"}
	}

	// RFC 8725 section 3.11, Use Explicit Typing, and RFC 9068 which requires
	// `at+jwt` on an OAuth 2.0 access token. Section 3.12 is the reason it
	// matters: without it this verifier cannot refuse an ID token presented
	// where an access token belongs, and research 07 section 1.2 calls that
	// substitution "cheap to build and catches real bugs".
	//
	// This check was MISSING, and `internal/idp/mint.go` cited it to justify a
	// design decision — the comment claimed the three header traps had been
	// refused by it. Nothing in the repository implemented it, so the comment
	// described a refusal that never happened and the property it defends (every
	// forged token carrying `at+jwt`) was inert against this fixture.
	if token.Header.Typ != typAccessToken {
		return Decision{Reason: fmt.Sprintf("typ %q is not %q", token.Header.Typ, typAccessToken)}
	}

	now := v.now()

	if token.Claims.Expires == nil {
		return Decision{Reason: "the token carries no `exp`"}
	}

	if time.Unix(*token.Claims.Expires, 0).Add(clockSkew).Before(now) {
		return Decision{Reason: "the token has expired"}
	}

	if token.Claims.NotBefore != nil && time.Unix(*token.Claims.NotBefore, 0).Add(-clockSkew).After(now) {
		return Decision{Reason: "the token is not valid yet"}
	}

	if v.issuer != "" && token.Claims.Issuer != v.issuer {
		return Decision{Reason: fmt.Sprintf("issuer %q is not %q", token.Claims.Issuer, v.issuer)}
	}

	// RFC 9700: "every resource server is obliged to verify, for every request,
	// whether the access token sent with that request was meant to be used for
	// that particular resource server."
	// Membership, not equality. A token legitimately addressed to several
	// resource servers carries all of them, and RFC 9700's obligation is that
	// this one "was meant to be used for that particular resource server".
	if !token.Claims.Audience.Contains(v.audience) {
		return Decision{Reason: fmt.Sprintf("audience %q does not include %q", token.Claims.Audience, v.audience)}
	}

	return Decision{Allow: true, Reason: reason}
}

// keySet returns the trusted keys, refetching when the cache is cold, stale, or
// does not hold the kid the token names. The unknown-kid refetch is convention
// rather than specification: research 07 established that OIDC Discovery says
// nothing about rotation, nothing about `kid` and nothing about refetching, which
// is exactly why it is implemented inconsistently and worth a chaos fault.
func (v *Verifier) keySet(kid string) (idp.JWKSet, error) {
	v.mu.Lock()
	cached := v.keys
	have := v.haveKeys
	fresh := v.now().Sub(v.keysAt) < v.keyTTL
	v.mu.Unlock()

	// Not permissive, stale. Key rotation is the control that bounds the damage
	// of a leaked signing key, and a verifier that never expires its cache has
	// turned rotation into something that is not a revocation mechanism.
	if v.mode == JWKSCacheForever && have {
		return cached, nil
	}

	// Freshness is ignored while the kid is known, so the only thing that ever
	// triggers a fetch is meeting a kid this verifier has not seen. That is one
	// line different from correct and it is the difference between a bounded
	// stale window and an unbounded one.
	if v.mode == JWKSRefetchOnKidOnly && have && cached.Has(kid) {
		return cached, nil
	}

	if have && fresh && cached.Has(kid) {
		return cached, nil
	}

	// A kid this verifier already looked for and did not find is refused without
	// another fetch. Research 07 section 2.3's own recovery trace ends on exactly
	// this line: "refetch already attempted, negative cached -> 401".
	if have && fresh && v.negativelyCached(kid) {
		return cached, nil
	}

	// Single-flight. The fetch happens under its own mutex and the cache is
	// re-checked after acquiring it, so N concurrent requests carrying the same
	// unknown kid cause ONE upstream fetch rather than N. Measured before this
	// existed: 200 requests carrying 200 attacker-chosen kids produced 200
	// upstream fetches, a ratio of 1.00, which research 07 section 1.4 calls
	// verbatim "a denial-of-service amplifier if unbounded".
	//
	// `kid` is an attacker-controlled header field. A reference implementation
	// that readers copy cannot leave this unbounded, least of all in the one file
	// whose job is to be the correct side of the comparison.
	v.fetching.Lock()
	defer v.fetching.Unlock()

	if set, ok := v.freshWith(kid); ok {
		return set, nil
	}

	// A rate cap on the FORCED path only. The periodic staleness refresh above is
	// untouched, so a rotation is still picked up within one key lifetime even
	// when a burst of unknown kids has the forced path on cooldown.
	//
	// The cap is deliberately short relative to a probe interval: a cooldown long
	// enough to be a real brake also delays a legitimate rotation, and a verifier
	// that refuses correctly signed new-key tokens for a second is the
	// availability failure research 07 section 2.2 counts as `wrongly_rejected`.
	// The residual amplification is inherent to the unknown-kid convention, which
	// is why section 2.4 treats it as a fault worth measuring rather than a bug
	// to be eliminated.
	if have && fresh && !v.forcedFetchAllowed() {
		return cached, nil
	}

	fetched, err := v.fetchKeys()
	if err != nil {
		if have && fresh {
			return cached, nil
		}
		return idp.JWKSet{}, err
	}

	v.mu.Lock()
	v.keys = fetched
	v.keysAt = v.now()
	v.haveKeys = true
	v.lastForced = v.now()
	if !fetched.Has(kid) && kid != "" {
		v.unknownKids[kid] = v.now()
	}
	v.mu.Unlock()

	return fetched, nil
}

// freshWith is the post-lock re-check that makes the fetch single-flight: a
// waiter that blocked while another goroutine fetched finds the answer already
// in the cache and does not fetch again.
func (v *Verifier) freshWith(kid string) (idp.JWKSet, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.haveKeys || v.now().Sub(v.keysAt) >= v.keyTTL {
		return idp.JWKSet{}, false
	}

	return v.keys, v.keys.Has(kid)
}

func (v *Verifier) negativelyCached(kid string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	at, known := v.unknownKids[kid]
	if !known {
		return false
	}

	if v.now().Sub(at) >= v.negativeTTL {
		delete(v.unknownKids, kid)
		return false
	}

	return true
}

func (v *Verifier) forcedFetchAllowed() bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	return v.now().Sub(v.lastForced) >= v.forcedCooldown
}

func (v *Verifier) fetchKeys() (idp.JWKSet, error) {
	if v.jwksURI == "" {
		return idp.JWKSet{}, errors.New("no key set is configured")
	}

	response, err := v.client.Get(v.jwksURI)
	if err != nil {
		return idp.JWKSet{}, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return idp.JWKSet{}, fmt.Errorf("the key set answered %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return idp.JWKSet{}, err
	}

	return idp.ParseJWKSet(body)
}

// introspect is the opaque-credential path. RFC 7662 is explicit that the
// ABSENCE of a response is not `active: false`, and a caller that invents one
// from a timeout, a 503 or an unparseable body has made up a value the provider
// never gave it.
func (v *Verifier) introspect(credential string) Decision {
	if decision, ok := v.cachedDecision(credential); ok {
		return Decision{Allow: decision, Reason: "a cached decision answered"}
	}

	active, answered := v.ask(credential)

	if !answered {
		if v.mode == IntrospectFailOpen {
			return Decision{Allow: true, Reason: "introspection did not answer usefully, so the credential was allowed"}
		}
		return Decision{Reason: "introspection did not answer"}
	}

	v.remember(credential, active)

	return Decision{Allow: active, Reason: "introspection answered"}
}

func (v *Verifier) ask(credential string) (bool, bool) {
	if v.introspectURI == "" {
		return false, false
	}

	// RFC 7662 section 2.1: a POST with an `application/x-www-form-urlencoded`
	// body. This used to send the token as a query parameter, which is khaos's
	// own private convention and not the specification — so the fixture and the
	// provider agreed with each other and neither would interoperate with
	// anything real.
	response, err := v.client.PostForm(v.introspectURI, url.Values{paramToken: {credential}})
	if err != nil {
		return false, false
	}
	defer func() { _ = response.Body.Close() }()

	// A 401 from an introspection endpoint is a verdict on the CALLER, not on
	// the token. RFC 7662 section 2.3 defines it as the response when the
	// protected resource's own credentials to the authorization server are
	// invalid, and the RFC defines no 403 at all.
	//
	// This used to be folded into "the provider answered, the token is inactive",
	// which is a conflation and the opposite of what the cited RFC says: it turns
	// "my credentials to the authority are wrong" into a flood of token denials
	// with no distinguishable signal. Both paths deny under this mode, so nothing
	// about the range's behaviour changes; what changes is that the file readers
	// copy no longer teaches the conflation.
	if response.StatusCode != http.StatusOK {
		return false, false
	}

	var body idp.Introspection
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return false, false
	}

	return body.Active, true
}

func (v *Verifier) cachedDecision(credential string) (bool, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()

	held, ok := v.decisions[credential]
	if !ok {
		return false, false
	}

	if held.forever {
		return held.allow, true
	}

	if v.now().After(held.expires) {
		return false, false
	}

	return held.allow, true
}

func (v *Verifier) remember(credential string, allow bool) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.decisions[credential] = cachedDecision{
		allow:   allow,
		expires: v.now().Add(v.decisionTTL),
		forever: v.mode == DecisionCacheForever && allow,
	}
}

func publicBytes(key idp.JWK) ([]byte, error) {
	pub, err := key.RSAPublicKey()
	if err != nil {
		return nil, err
	}

	return idp.SPKIPEMBytes(pub)
}

func verifyRaw(pub *rsa.PublicKey, digest, signature []byte) bool {
	return idp.VerifyPKCS1v15Raw(pub, digest, signature)
}

func allZero(raw []byte) bool {
	for _, b := range raw {
		if b != 0 {
			return false
		}
	}
	return true
}

// Resolve maps an operator's string onto a mode, and falls back to Correct for
// anything it does not recognise. That fallback is deliberate: one `--fail-mode`
// drives the whole range, and a mode meant for a different gateway must leave
// this one behaving correctly rather than refusing to start.
func Resolve(mode string) Mode {
	trimmed := strings.TrimSpace(mode)

	if Known(trimmed) {
		return Mode(trimmed)
	}

	return Correct
}
