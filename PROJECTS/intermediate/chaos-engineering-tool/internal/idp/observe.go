// ©AngelaMos | 2026
// observe.go

package idp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	observeTimeout = 5 * time.Second
	observeBudget  = 4

	// Slack on a measured hold, for the same reason the fault proxy carries it:
	// the threshold is a lower bound with no tolerance otherwise, and on a host
	// that also serves real traffic CPU contention routinely shaves a few
	// percent off a sleep.
	slackNumerator   = 9
	slackDenominator = 10

	observedAlgNone      = "khaos's provider mints a token whose header declares alg %q with an empty signature, where its honest token carries %q"
	observedAlgConfusion = "khaos's provider mints an HS256 token whose MAC verifies under its own published RSA public key as %s bytes"
	observedEmbeddedJWK  = "khaos's provider mints a token signed by kid %q, which it carries in its own `jwk` header and does NOT publish"
	observedExpired      = "khaos's provider mints a correctly signed token that expired %s ago"
	observedNotYetValid  = "khaos's provider mints a correctly signed token not valid for another %s"
	observedWrongAud     = "khaos's provider mints a correctly signed token addressed to %q rather than %q"
	observedForeignIss   = "khaos's provider mints a token from issuer %q, signed by a key it publishes, where its honest token says %q"
	observedTruncated    = "khaos's provider mints a token whose signature is %d byte where its honest token signs %d"
	observedZero         = "khaos's provider mints an %s token whose %d-byte signature is entirely zero"
	observedWeakKey      = "khaos's provider mints a token under a %d-bit modulus that crypto/rsa refuses to verify and khaos's own PKCS#1 v1.5 path accepts"
	observedJWKSGone     = "khaos's provider answers %d on its health route and %d on its JWK Set"
	observedRollover     = "kid %q is gone from khaos's published JWK Set and %q is signing in its place"
	observedRotation     = "khaos publishes both %q and %q, and mints under %q"
	observedIntroError   = "khaos's provider answers %d on its health route and %d on introspection"
	observedIntroBad     = "khaos's provider answers introspection with %d and a body that is not JSON"
	observedIntroSlow    = "introspection takes %s where the health route answers in %s"
	observedRevoked      = "khaos's provider reports the credential it revoked inactive and a second credential still active"

	errNothingArmed  = "%w: nothing is armed on khaos's identity provider, so there is nothing to confirm"
	errWrongExpected = "%w: the provider holds %q but %q was expected"
	errNoListener    = "%w: this trap is confirmed over the provider's own HTTP surface, and it is not listening"
	errProviderDown  = "%w: khaos cannot reach its own identity provider's health route (%v), so nothing it sees there can be attributed to the armed trap"
	errHonestToken   = "%w: khaos's own provider cannot mint an honest token (%v), so nothing it mints under a trap can be compared with one"
)

// Observe confirms the armed trap through the provider's OWN public surface and
// against a control, never by reading the flag that was set.
//
// The discipline is the fault proxy's, and it was expensive to learn: a
// confirmation that can only succeed is not an oracle. Gutting the proxy's
// equivalent to `return true` left every package and the Docker gate green, and
// the fix was a way to arm a fault that does not happen. Every branch below
// therefore has a control that must disagree with the fault, and `Inert` makes
// the fault not happen so a test can prove the branch says NO.
func (p *Provider) Observe(ctx context.Context, expected Kind) (string, bool, error) {
	select {
	case <-p.closed:
		return "", false, ErrClosed
	default:
	}

	trap := p.Trap()

	if trap.Kind == PassThrough {
		return "", false, fmt.Errorf(errNothingArmed, ErrTrapNotObserved)
	}

	if expected != "" && trap.Kind != expected {
		return "", false, fmt.Errorf(errWrongExpected, ErrTrapNotObserved, trap.Kind, expected)
	}

	if trap.Forgery() {
		return p.observeForgery(trap)
	}

	return p.observeEndpoint(ctx, trap)
}

// observeForgery mints on BOTH paths and requires them to differ. The honest
// token is the control: if khaos's own provider cannot produce a correct token,
// nothing it produces under a trap can be attributed to the trap.
func (p *Provider) observeForgery(trap Trap) (string, bool, error) {
	honest, err := p.mintHonestForControl()
	if err != nil {
		return "", false, fmt.Errorf(errHonestToken, ErrTrapNotObserved, err)
	}

	forged, err := p.mintTrappedForControl()
	if err != nil {
		return "", false, err
	}

	published := p.PublishedSet()
	now := p.clock()

	switch trap.Kind {
	case AlgNone:
		if forged.Header.Alg == string(None) && len(forged.Signature) == 0 && honest.Header.Alg != string(None) {
			return sprintf(observedAlgNone, forged.Header.Alg, honest.Header.Alg), true, nil
		}

	case AlgConfusion:
		// Both halves. The header has to say HS256, and the MAC has to actually
		// verify under the bytes a verifier would be holding, or khaos is
		// sending a token no target could accept and an acceptance would mean
		// something else entirely.
		if forged.Header.Alg != string(HS256) {
			return "", false, nil
		}
		secret, err := p.confusionSecret(trap.KeyForm)
		if err != nil {
			return "", false, err
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(forged.SigningInput)
		if hmac.Equal(mac.Sum(nil), forged.Signature) {
			return sprintf(observedAlgConfusion, trap.KeyForm), true, nil
		}

	case EmbeddedJWK:
		if forged.Header.JWK == nil || published.Has(forged.Header.JWK.Kid) {
			return "", false, nil
		}
		if verifiesUnder(*forged.Header.JWK, forged) {
			return sprintf(observedEmbeddedJWK, forged.Header.JWK.Kid), true, nil
		}

	case ClaimExpired:
		if forged.Claims.Expires == nil || !verifiesUnderSet(published, forged) {
			return "", false, nil
		}
		expiry := time.Unix(*forged.Claims.Expires, 0)
		if expiry.Before(now) {
			return sprintf(observedExpired, now.Sub(expiry).Round(time.Second)), true, nil
		}

	case ClaimNotYetValid:
		if forged.Claims.NotBefore == nil || !verifiesUnderSet(published, forged) {
			return "", false, nil
		}
		start := time.Unix(*forged.Claims.NotBefore, 0)
		if start.After(now) {
			return sprintf(observedNotYetValid, start.Sub(now).Round(time.Second)), true, nil
		}

	case ClaimWrongAudience:
		if !verifiesUnderSet(published, forged) {
			return "", false, nil
		}
		if !forged.Claims.Audience.Contains(p.audience) && len(forged.Claims.Audience) > 0 {
			return sprintf(observedWrongAud, forged.Claims.Audience, honest.Claims.Audience), true, nil
		}

	case ClaimForeignIssuer:
		// The key IS published, deliberately. That is the multi-tenant shape and
		// the teaching point: the key set is not the trust boundary, so the
		// signature verifies and only the `iss` check can refuse it.
		if !verifiesUnderSet(published, forged) {
			return "", false, nil
		}
		if forged.Claims.Issuer != honest.Claims.Issuer && forged.Claims.Issuer != "" {
			return sprintf(observedForeignIss, forged.Claims.Issuer, honest.Claims.Issuer), true, nil
		}

	case SignatureTruncated:
		if len(forged.Signature) == truncatedLength && len(honest.Signature) > truncatedLength {
			return sprintf(observedTruncated, len(forged.Signature), len(honest.Signature)), true, nil
		}

	case SignatureZero:
		if forged.Header.Alg == string(ES256) && len(forged.Signature) > 0 && allZero(forged.Signature) {
			return sprintf(observedZero, forged.Header.Alg, len(forged.Signature)), true, nil
		}

	case SignatureWeakKey:
		// Three assertions, and none of them is redundant. The modulus has to be
		// below the library floor, khaos's own arithmetic has to ACCEPT the
		// signature, or khaos is sending an unverifiable token and an acceptance
		// means something else, and the standard library has to REFUSE it.
		//
		// That last one looks implied by the first and is not: the floor is a
		// GODEBUG. Under `rsa1024min=0` crypto/rsa verifies below it, so khaos's
		// claim that a correct verifier cannot accept this token would be false
		// in that environment, and the trap declines to confirm rather than
		// asserting it anyway.
		key, err := published.Lookup(forged.Header.Kid)
		if err != nil {
			return "", false, nil
		}
		pub, err := key.RSAPublicKey()
		if err != nil {
			return "", false, nil
		}
		if pub.N.BitLen() >= libraryFloorBits {
			return "", false, nil
		}
		digest := sha256.Sum256(forged.SigningInput)
		libraryRefuses := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], forged.Signature) != nil
		khaosAccepts := verifyPKCS1v15Raw(pub, digest[:], forged.Signature)
		if libraryRefuses && khaosAccepts {
			return sprintf(observedWeakKey, pub.N.BitLen()), true, nil
		}
	}

	return "", false, nil
}

// mintHonestForControl and mintTrappedForControl mint WITHOUT counting, because
// the mint counter is a measurement and khaos's own confirmation must not move
// the thing it is confirming.
//
// Both are needed. An earlier version had only the honest one and then called
// the counting TrappedToken on the next line, so the comment on this function
// described a property the function beside it broke.
func (p *Provider) mintHonestForControl() (Token, error) {
	return p.parseMint(Trap{})
}

func (p *Provider) mintTrappedForControl() (Token, error) {
	return p.parseMint(p.effective())
}

func (p *Provider) parseMint(trap Trap) (Token, error) {
	raw, err := p.mintToken(trap, grantRequest{subject: DefaultSubject, lifetime: p.lifetime})
	if err != nil {
		return Token{}, err
	}
	return Parse(raw)
}

// confusionSecret reads the TRAP's key form, and so does mintToken. They used to
// read two different fields that Arm copied one into the other, which agreed
// only by that copy and which Disarm never cleared.
func (p *Provider) confusionSecret(form KeyForm) ([]byte, error) {
	p.mu.RLock()
	signing := p.signing
	p.mu.RUnlock()

	return publicKeyBytes(signing, form)
}

// observeEndpoint confirms the traps that change what the provider SERVES rather
// than what it mints. Every one of them is measured over the provider's own HTTP
// surface, with the health route as the control: it is never faulted, so an
// unhealthy control means khaos's provider is broken rather than lying and
// nothing seen elsewhere can be attributed to the trap.
func (p *Provider) observeEndpoint(ctx context.Context, trap Trap) (string, bool, error) {
	base, err := p.Addr()
	if err != nil {
		return "", false, fmt.Errorf(errNoListener, ErrTrapNotObserved)
	}

	root := "http://" + base
	client := &http.Client{Timeout: observeTimeout + trap.Delay*observeBudget}

	healthStatus, healthTook, err := probeRoute(ctx, client, root+RouteHealth)
	if err != nil || healthStatus != http.StatusOK {
		return "", false, fmt.Errorf(errProviderDown, ErrTrapNotObserved, orStatus(err, healthStatus))
	}

	switch trap.Kind {
	case JWKSUnreachable:
		p.ownFetches.Add(1)
		status, _, err := probeRoute(ctx, client, root+RouteJWKS)
		if err == nil && status != http.StatusOK {
			return sprintf(observedJWKSGone, healthStatus, status), true, nil
		}

	case KidRollover:
		retired, ok := p.RetiredKid()
		if !ok {
			return "", false, nil
		}
		set, err := p.fetchSet(ctx, client, root+RouteJWKS)
		if err != nil {
			return "", false, err
		}
		// `retired != p.SigningKid()` used to be a third conjunct here and it was
		// INERT: it is implied by the other two, because `!Has(retired)` and
		// `Has(SigningKid)` cannot both hold when the two are the same kid.
		//
		// Worse, it ALIBIED the live one. Measured: with it present, replacing
		// `!set.Has(retired)` with `true` left both the positive and the inert
		// case green and the whole suite passing, because the implied conjunct
		// was carrying the negative control on its own. Withdrawing the retired
		// key is the entire claim this branch makes, so that assertion has to be
		// the one the control exercises.
		if !set.Has(retired) && set.Has(p.SigningKid()) {
			return sprintf(observedRollover, retired, p.SigningKid()), true, nil
		}

	case KeyRotation:
		retired, ok := p.RetiredKid()
		if !ok {
			return "", false, nil
		}
		set, err := p.fetchSet(ctx, client, root+RouteJWKS)
		if err != nil {
			return "", false, err
		}
		if retired == p.SigningKid() || !set.Has(retired) || !set.Has(p.SigningKid()) {
			return "", false, nil
		}
		// The three assertions above are the live ones, and the first carries the
		// negative control: an inert arm never rotates, so retired and signing
		// are the same kid.
		//
		// A fourth, `minted.Header.Kid == p.SigningKid()`, used to follow and was
		// unconditionally true: mintToken's default branch always stamps the
		// current signing kid and KeyRotation is not a forgery trap. It is gone
		// rather than kept for symmetry, because an assertion that cannot fail
		// reads in a review as evidence and is not.
		minted, err := p.mintTrappedForControl()
		if err != nil {
			return "", false, err
		}

		return sprintf(observedRotation, retired, p.SigningKid(), minted.Header.Kid), true, nil

	case IntrospectionError:
		status, _, err := probeRoute(ctx, client, p.introspectURL(root, p.Opaque()))
		if err == nil && status != http.StatusOK {
			return sprintf(observedIntroError, healthStatus, status), true, nil
		}

	case IntrospectionMalformed:
		status, body, err := readRoute(ctx, client, p.introspectURL(root, p.Opaque()))
		if err != nil {
			return "", false, err
		}
		if status == http.StatusOK && !json.Valid(body) {
			return sprintf(observedIntroBad, status), true, nil
		}

	case IntrospectionSlow:
		status, took, err := probeRoute(ctx, client, p.introspectURL(root, p.Opaque()))
		if err != nil || status != http.StatusOK {
			return "", false, nil
		}
		// A differential, not a threshold. The health route is the control and it
		// is never faulted, so the comparison separates khaos's own hold from a
		// generally slow machine.
		if took-healthTook >= slack(trap.Delay) {
			return sprintf(observedIntroSlow, took.Round(time.Millisecond), healthTook.Round(time.Millisecond)), true, nil
		}

	case Revoke:
		// A control credential, issued now and never revoked. Without it,
		// "inactive" is also what a provider that lost every grant would say, and
		// the finding would be khaos's own bug reported as the target's.
		control := p.Opaque()

		revoked, err := fetchIntrospection(ctx, client, p.introspectURL(root, trap.Credential))
		if err != nil {
			return "", false, err
		}

		alive, err := fetchIntrospection(ctx, client, p.introspectURL(root, control))
		if err != nil {
			return "", false, err
		}

		if !revoked.Active && alive.Active {
			return observedRevoked, true, nil
		}
	}

	return "", false, nil
}

// introspectURL records the call as khaos's own, so the exported count stays a
// measurement of the TARGET's behaviour. Every caller of this is a confirmation
// probe.
// introspectURL is khaos's own read-back path. It keeps the query form on
// purpose: these probes exist to observe the endpoint's BEHAVIOUR, and reading
// the token the same way a conforming client does is the fixture's job to prove,
// not the oracle's. The contract test covers the specified wire format directly.
func (p *Provider) introspectURL(root, credential string) string {
	p.ownIntrospects.Add(1)
	return root + RouteIntrospect + "?" + ParamToken + "=" + credential
}

func probeRoute(ctx context.Context, client *http.Client, url string) (int, time.Duration, error) {
	started := time.Now()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}

	response, err := client.Do(request)
	if err != nil {
		return 0, time.Since(started), err
	}
	defer func() { _ = response.Body.Close() }()

	_, _ = io.Copy(io.Discard, response.Body)

	return response.StatusCode, time.Since(started), nil
}

func readRoute(ctx context.Context, client *http.Client, url string) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}

	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, err
	}

	return response.StatusCode, body, nil
}

// fetchSet is khaos's own read-back of the key set, so it records the fetch as
// khaos's and the exported count stays a measurement of the TARGET's behaviour.
func (p *Provider) fetchSet(ctx context.Context, client *http.Client, url string) (JWKSet, error) {
	p.ownFetches.Add(1)
	return fetchSet(ctx, client, url)
}

func fetchSet(ctx context.Context, client *http.Client, url string) (JWKSet, error) {
	status, body, err := readRoute(ctx, client, url)
	if err != nil {
		return JWKSet{}, err
	}

	if status != http.StatusOK {
		return JWKSet{}, fmt.Errorf(errProviderDown, ErrTrapNotObserved, status)
	}

	return ParseJWKSet(body)
}

func fetchIntrospection(ctx context.Context, client *http.Client, url string) (Introspection, error) {
	status, body, err := readRoute(ctx, client, url)
	if err != nil {
		return Introspection{}, err
	}

	if status != http.StatusOK {
		return Introspection{}, fmt.Errorf(errProviderDown, ErrTrapNotObserved, status)
	}

	var out Introspection
	if err := json.Unmarshal(body, &out); err != nil {
		return Introspection{}, err
	}

	return out, nil
}

// verifiesUnderSet is the control half of every claim trap. A claim trap's whole
// claim is that the SIGNATURE is correct and exactly one claim is not, so a
// token whose signature does not verify is not the token the trap describes.
func verifiesUnderSet(set JWKSet, token Token) bool {
	key, err := set.Lookup(token.Header.Kid)
	if err != nil {
		return false
	}
	return verifiesUnder(key, token)
}

func verifiesUnder(key JWK, token Token) bool {
	digest := sha256.Sum256(token.SigningInput)

	switch Algorithm(token.Header.Alg) {
	case RS256:
		pub, err := key.RSAPublicKey()
		if err != nil {
			return false
		}
		if pub.N.BitLen() < libraryFloorBits {
			return verifyPKCS1v15Raw(pub, digest[:], token.Signature)
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], token.Signature) == nil

	case ES256:
		pub, err := key.ECPublicKey()
		if err != nil || len(token.Signature) != 2*p256CoordinateBytes {
			return false
		}
		return ecdsa.Verify(pub,
			digest[:],
			bigFromBytes(token.Signature[:p256CoordinateBytes]),
			bigFromBytes(token.Signature[p256CoordinateBytes:]))

	default:
		return false
	}
}

func allZero(raw []byte) bool {
	for _, b := range raw {
		if b != 0 {
			return false
		}
	}
	return true
}

func slack(delay time.Duration) time.Duration {
	return delay * slackNumerator / slackDenominator
}

func orStatus(err error, status int) any {
	if err != nil {
		return err
	}
	return status
}

func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
