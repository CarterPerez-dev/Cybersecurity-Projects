// ©AngelaMos | 2026
// verifier.go

// Package verifier is the range's reference token verifier: the thing under
// test. Mode Correct is the control; every other mode is one line from it.
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

// Mode is which defect the verifier carries. Traps can share a mode.
type Mode string

const (
	// Correct follows RFC 8725 and is the control for every other mode.
	Correct Mode = "closed"

	// AlgAny trusts the header's alg: no allowlist, no key-to-alg check.
	AlgAny Mode = "alg-any"

	// TrustEmbeddedKey resolves the key from the token's own `jwk` header.
	TrustEmbeddedKey Mode = "trust-embedded-key"

	// SkipClaims checks no claim at all: not `exp`, `nbf`, `aud`, `iss`, `typ`.
	SkipClaims Mode = "skip-claims"

	// WeakSignature passes an absent, all-zero or too-short signature.
	WeakSignature Mode = "weak-sig"

	// AnyKeySize drops the modulus floor and verifies by raw exponentiation.
	AnyKeySize Mode = "any-key-size"

	// JWKSFailOpen skips the signature check when the key set will not fetch.
	JWKSFailOpen Mode = "jwks-fail-open"

	// JWKSCacheForever never expires the key set, so rotation revokes nothing.
	JWKSCacheForever Mode = "jwks-cache-forever"

	// JWKSRefetchOnKidOnly refetches on an unknown `kid`, never on a timer.
	JWKSRefetchOnKidOnly Mode = "jwks-kid-only"

	// IntrospectFailOpen reads a non-200, a bad body or a timeout as active.
	IntrospectFailOpen Mode = "introspect-fail-open"

	// DecisionCacheForever caches an authorization decision with no expiry.
	DecisionCacheForever Mode = "decision-cache-forever"
)

const (
	// RFC 8725 section 3.1: the token never selects from the allowlist.
	allowedRS = string(idp.RS256)
	allowedES = string(idp.ES256)

	clockSkew = 60 * time.Second

	// Shorter than a run, so the fetch-failure branch is reachable in one.
	DefaultKeyTTL = time.Second

	DefaultDecisionTTL = 2 * time.Second

	upstreamTimeout = 500 * time.Millisecond

	typAccessToken = "at+jwt"

	reasonBadSignature = "the signature does not verify"

	minimumModulusBits = 1024

	DefaultNegativeTTL    = time.Second
	DefaultForcedCooldown = 100 * time.Millisecond

	p256SignatureBytes = 64

	paramToken = "token"

	errNoKeys = "the key set could not be fetched"
)

// Decision is the verdict. Nothing outside this fixture may depend on Reason.
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

	negativeTTL    time.Duration
	forcedCooldown time.Duration

	// Separate from mu, which must not be held across a network call.
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

// Decide validates a JWS-shaped credential locally and introspects the rest.
func (v *Verifier) Decide(credential string) Decision {
	if credential == "" {
		return Decision{Reason: "no credential was presented"}
	}

	// Dispatch on SHAPE, not on whether the parser accepts it: RFC 7519 permits
	// an array `aud`, and a legal JWT routed to introspection can be an accept.
	if !idp.LooksLikeJWS(credential) {
		return v.introspect(credential)
	}

	token, err := idp.Parse(credential)
	if err != nil {
		return Decision{
			Reason: "the credential is shaped like a JWS and does not parse as one",
		}
	}

	return v.validate(token)
}

func (v *Verifier) validate(token idp.Token) Decision {
	keys, keysErr := v.keySet(token.Header.Kid)

	if keysErr != nil {
		if v.mode == JWKSFailOpen {
			return Decision{
				Allow:  true,
				Reason: "the key set was unavailable, so the signature was not checked",
			}
		}
		return Decision{Reason: errNoKeys}
	}

	alg, ok := v.algorithm(token.Header.Alg)
	if !ok {
		return Decision{
			Reason: fmt.Sprintf(
				"algorithm %q is not acceptable",
				token.Header.Alg,
			),
		}
	}

	// RFC 7518 registers `none` as "No digital signature or MAC performed".
	if alg == string(idp.None) {
		return v.claims(
			token,
			"the token declared no signature and it was believed",
		)
	}

	key, found := v.resolve(keys, token)
	if !found {
		return Decision{
			Reason: fmt.Sprintf("no key matches kid %q", token.Header.Kid),
		}
	}

	// RFC 8725 rule 2: each key MUST be used with exactly one algorithm.
	if v.mode != AlgAny && key.Alg != "" && key.Alg != alg {
		return Decision{
			Reason: fmt.Sprintf(
				"kid %q is bound to %q and the token asked for %q",
				key.Kid,
				key.Alg,
				alg,
			),
		}
	}

	if key.Use != "" && key.Use != idp.UseSignature {
		return Decision{
			Reason: fmt.Sprintf("kid %q is not a signing key", key.Kid),
		}
	}

	if reason, ok := v.signature(key, token, alg); !ok {
		return Decision{Reason: reason}
	}

	return v.claims(token, "the signature verified")
}

func (v *Verifier) algorithm(declared string) (string, bool) {
	if v.mode == AlgAny {
		return declared, declared != ""
	}

	if declared == allowedRS || declared == allowedES {
		return declared, true
	}

	return "", false
}

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

func (v *Verifier) signature(
	key idp.JWK,
	token idp.Token,
	alg string,
) (string, bool) {
	// Compared against the RESOLVED KEY, not a constant: a minimum length is a
	// property of the key, and a constant floor also passes the weak-key token.
	if v.mode == WeakSignature && weakSignature(key, token.Signature, alg) {
		return "", true
	}

	digest := sha256.Sum256(token.SigningInput)

	switch alg {
	case allowedRS:
		return v.verifyRSA(key, token, digest)

	case allowedES:
		pub, err := key.ECPublicKey()
		if err != nil || len(token.Signature) != p256SignatureBytes {
			return "the signature is not a P-256 signature", false
		}

		r := new(big.Int).SetBytes(token.Signature[:p256SignatureBytes/2])
		s := new(big.Int).SetBytes(token.Signature[p256SignatureBytes/2:])

		if !ecdsa.Verify(pub, digest[:], r, s) {
			return reasonBadSignature, false
		}

		return "", true

	case string(idp.HS256):
		// An RSA public key used as an HMAC secret, and it is public.
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

func (v *Verifier) verifyRSA(
	key idp.JWK,
	token idp.Token,
	digest [sha256.Size]byte,
) (string, bool) {
	pub, err := key.RSAPublicKey()
	if err != nil {
		return "the key is not usable as RSA", false
	}

	// Explicit, rather than trusting crypto/rsa's 1024-bit minimum to stay.
	if v.mode != AnyKeySize && pub.N.BitLen() < minimumModulusBits {
		return fmt.Sprintf(
			"kid %q has a %d-bit modulus",
			key.Kid,
			pub.N.BitLen(),
		), false
	}

	if v.mode == AnyKeySize {
		if !verifyRaw(pub, digest[:], token.Signature) {
			return reasonBadSignature, false
		}
		return "", true
	}

	if err := rsa.VerifyPKCS1v15(
		pub,
		crypto.SHA256,
		digest[:],
		token.Signature,
	); err != nil {
		return reasonBadSignature, false
	}

	return "", true
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

// claims is every check a stateless verifier has; `exp` is its only revocation.
func (v *Verifier) claims(token idp.Token, reason string) Decision {
	if v.mode == SkipClaims {
		return Decision{
			Allow:  true,
			Reason: reason + ", and no claim was checked",
		}
	}

	// RFC 9068 requires `at+jwt`; without it an ID token passes here.
	if token.Header.Typ != typAccessToken {
		return Decision{
			Reason: fmt.Sprintf(
				"typ %q is not %q",
				token.Header.Typ,
				typAccessToken,
			),
		}
	}

	now := v.now()

	if token.Claims.Expires == nil {
		return Decision{Reason: "the token carries no `exp`"}
	}

	if time.Unix(*token.Claims.Expires, 0).Add(clockSkew).Before(now) {
		return Decision{Reason: "the token has expired"}
	}

	if token.Claims.NotBefore != nil &&
		time.Unix(*token.Claims.NotBefore, 0).Add(-clockSkew).After(now) {
		return Decision{Reason: "the token is not valid yet"}
	}

	if v.issuer != "" && token.Claims.Issuer != v.issuer {
		return Decision{
			Reason: fmt.Sprintf(
				"issuer %q is not %q",
				token.Claims.Issuer,
				v.issuer,
			),
		}
	}

	// RFC 9700: membership, not equality -- a token may address several.
	if !token.Claims.Audience.Contains(v.audience) {
		return Decision{
			Reason: fmt.Sprintf(
				"audience %q does not include %q",
				token.Claims.Audience,
				v.audience,
			),
		}
	}

	return Decision{Allow: true, Reason: reason}
}

// The unknown-kid refetch is convention, not specification: OIDC is silent.
func (v *Verifier) keySet(kid string) (idp.JWKSet, error) {
	v.mu.Lock()
	cached := v.keys
	have := v.haveKeys
	fresh := v.now().Sub(v.keysAt) < v.keyTTL
	v.mu.Unlock()

	if v.mode == JWKSCacheForever && have {
		return cached, nil
	}

	if v.mode == JWKSRefetchOnKidOnly && have && cached.Has(kid) {
		return cached, nil
	}

	if have && fresh && cached.Has(kid) {
		return cached, nil
	}

	if have && fresh && v.negativelyCached(kid) {
		return cached, nil
	}

	// `kid` is attacker-controlled, so the fetch is single-flighted.
	v.fetching.Lock()
	defer v.fetching.Unlock()

	if set, ok := v.freshWith(kid); ok {
		return set, nil
	}

	// A rate cap on the FORCED path only; a longer one delays a real rotation.
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
		return idp.JWKSet{}, fmt.Errorf(
			"the key set answered %d",
			response.StatusCode,
		)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return idp.JWKSet{}, err
	}

	return idp.ParseJWKSet(body)
}

// RFC 7662 is explicit that the ABSENCE of a response is not `active: false`.
func (v *Verifier) introspect(credential string) Decision {
	if decision, ok := v.cachedDecision(credential); ok {
		return Decision{Allow: decision, Reason: "a cached decision answered"}
	}

	active, answered := v.ask(credential)

	if !answered {
		if v.mode == IntrospectFailOpen {
			return Decision{
				Allow:  true,
				Reason: "introspection did not answer usefully, so the credential was allowed",
			}
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

	response, err := v.client.PostForm(
		v.introspectURI,
		url.Values{paramToken: {credential}},
	)
	if err != nil {
		return false, false
	}
	defer func() { _ = response.Body.Close() }()

	// A 401 here is a verdict on the CALLER, not on the token: RFC 7662 section
	// 2.3 defines it for invalid client credentials, and defines no 403 at all.
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

// Resolve falls back to Correct on purpose: one `--fail-mode` drives the whole
// range, so a mode meant for another gateway must leave this one correct.
func Resolve(mode string) Mode {
	trimmed := strings.TrimSpace(mode)

	if Known(trimmed) {
		return Mode(trimmed)
	}

	return Correct
}
