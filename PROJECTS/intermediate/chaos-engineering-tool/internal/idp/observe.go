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

	// Slack: contention routinely shaves a few percent off a measured sleep.
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

// Observe confirms the armed trap through the provider's OWN public surface
// and against a control, never by reading the flag that was set.
func (p *Provider) Observe(
	ctx context.Context,
	expected Kind,
) (string, bool, error) {
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
		return "", false, fmt.Errorf(
			errWrongExpected,
			ErrTrapNotObserved,
			trap.Kind,
			expected,
		)
	}

	if trap.Forgery() {
		return p.observeForgery(trap)
	}

	return p.observeEndpoint(ctx, trap)
}

// observeForgery mints on BOTH paths. The honest token is the control: khaos
// has to be able to mint a correct one for the forgery to mean anything, and
// the kinds whose fault IS a divergence also require the two to differ.
func (p *Provider) observeForgery(trap Trap) (string, bool, error) {
	honest, err := p.mintHonestForControl()
	if err != nil {
		return "", false, fmt.Errorf(errHonestToken, ErrTrapNotObserved, err)
	}

	forged, err := p.mintTrappedForControl()
	if err != nil {
		return "", false, err
	}

	switch trap.Kind {
	case AlgNone, AlgConfusion, EmbeddedJWK:
		return p.observeHeader(trap, honest, forged)

	case ClaimExpired, ClaimNotYetValid, ClaimWrongAudience,
		ClaimForeignIssuer:
		return p.observeClaims(trap, honest, forged)

	case SignatureTruncated, SignatureZero, SignatureWeakKey:
		return p.observeSignature(trap, honest, forged)

	default:
		return "", false, nil
	}
}

func (p *Provider) observeHeader(
	trap Trap,
	honest, forged Token,
) (string, bool, error) {
	switch trap.Kind {
	case AlgNone:
		if forged.Header.Alg == string(None) && len(forged.Signature) == 0 &&
			honest.Header.Alg != string(None) {
			return sprintf(
				observedAlgNone,
				forged.Header.Alg,
				honest.Header.Alg,
			), true, nil
		}

	case AlgConfusion:
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
		if forged.Header.JWK == nil ||
			p.PublishedSet().Has(forged.Header.JWK.Kid) {
			return "", false, nil
		}
		if verifiesUnder(*forged.Header.JWK, forged) {
			return sprintf(
				observedEmbeddedJWK,
				forged.Header.JWK.Kid,
			), true, nil
		}

	default:
		// Kinds from the other groups reach their own observer.
	}

	return "", false, nil
}

// observeClaims requires the signature to still VERIFY: a claim trap whose
// token also failed that check would be confirmed by the wrong evidence.
func (p *Provider) observeClaims(
	trap Trap,
	honest, forged Token,
) (string, bool, error) {
	if !verifiesUnderSet(p.PublishedSet(), forged) {
		return "", false, nil
	}

	now := p.clock()

	switch trap.Kind {
	case ClaimExpired:
		if forged.Claims.Expires == nil {
			return "", false, nil
		}
		expiry := time.Unix(*forged.Claims.Expires, 0)
		if expiry.Before(now) {
			return sprintf(
				observedExpired,
				now.Sub(expiry).Round(time.Second),
			), true, nil
		}

	case ClaimNotYetValid:
		if forged.Claims.NotBefore == nil {
			return "", false, nil
		}
		start := time.Unix(*forged.Claims.NotBefore, 0)
		if start.After(now) {
			return sprintf(
				observedNotYetValid,
				start.Sub(now).Round(time.Second),
			), true, nil
		}

	case ClaimWrongAudience:
		if !forged.Claims.Audience.Contains(p.audience) &&
			len(forged.Claims.Audience) > 0 {
			return sprintf(
				observedWrongAud,
				forged.Claims.Audience,
				honest.Claims.Audience,
			), true, nil
		}

	case ClaimForeignIssuer:
		if forged.Claims.Issuer != honest.Claims.Issuer &&
			forged.Claims.Issuer != "" {
			return sprintf(
				observedForeignIss,
				forged.Claims.Issuer,
				honest.Claims.Issuer,
			), true, nil
		}

	default:
		// Kinds from the other groups reach their own observer.
	}

	return "", false, nil
}

func (p *Provider) observeSignature(
	trap Trap,
	honest, forged Token,
) (string, bool, error) {
	switch trap.Kind {
	case SignatureTruncated:
		if len(forged.Signature) == truncatedLength &&
			len(honest.Signature) > truncatedLength {
			return sprintf(
				observedTruncated,
				len(forged.Signature),
				len(honest.Signature),
			), true, nil
		}

	case SignatureZero:
		if forged.Header.Alg == string(ES256) && len(forged.Signature) > 0 &&
			allZero(forged.Signature) {
			return sprintf(
				observedZero,
				forged.Header.Alg,
				len(forged.Signature),
			), true, nil
		}

	case SignatureWeakKey:
		// The library REFUSING this is not implied by the bit length: the floor
		// is a GODEBUG, so under `rsa1024min=0` crypto/rsa verifies below it.
		key, err := p.PublishedSet().Lookup(forged.Header.Kid)
		if err != nil {
			return "", false, nil //nolint:nilerr // not confirmed, not an error
		}
		pub, err := key.RSAPublicKey()
		if err != nil {
			return "", false, nil //nolint:nilerr // not confirmed, not an error
		}
		if pub.N.BitLen() >= libraryFloorBits {
			return "", false, nil
		}
		digest := sha256.Sum256(forged.SigningInput)
		libraryRefuses := rsa.VerifyPKCS1v15(
			pub,
			crypto.SHA256,
			digest[:],
			forged.Signature,
		) != nil
		khaosAccepts := verifyPKCS1v15Raw(pub, digest[:], forged.Signature)
		if libraryRefuses && khaosAccepts {
			return sprintf(observedWeakKey, pub.N.BitLen()), true, nil
		}

	default:
		// Kinds from the other groups reach their own observer.
	}

	return "", false, nil
}

// These mint WITHOUT counting, because the mint counter is a measurement and
// khaos's own confirmation must not move the thing it is confirming.
func (p *Provider) mintHonestForControl() (Token, error) {
	return p.parseMint(Trap{})
}

func (p *Provider) mintTrappedForControl() (Token, error) {
	return p.parseMint(p.effective())
}

func (p *Provider) parseMint(trap Trap) (Token, error) {
	raw, err := p.mintToken(
		trap,
		grantRequest{subject: DefaultSubject, lifetime: p.lifetime},
	)
	if err != nil {
		return Token{}, err
	}
	return Parse(raw)
}

func (p *Provider) confusionSecret(form KeyForm) ([]byte, error) {
	p.mu.RLock()
	signing := p.signing
	p.mu.RUnlock()

	return publicKeyBytes(signing, form)
}

// observeEndpoint confirms what the provider SERVES. The health route is the
// control: it is never faulted, so an unhealthy one means khaos is broken.
func (p *Provider) observeEndpoint(
	ctx context.Context,
	trap Trap,
) (string, bool, error) {
	base, err := p.Addr()
	if err != nil {
		return "", false, fmt.Errorf(errNoListener, ErrTrapNotObserved)
	}

	root := "http://" + base
	client := &http.Client{Timeout: observeTimeout + trap.Delay*observeBudget}

	healthStatus, healthTook, err := probeRoute(ctx, client, root+RouteHealth)
	if err != nil || healthStatus != http.StatusOK {
		return "", false, fmt.Errorf(
			errProviderDown,
			ErrTrapNotObserved,
			orStatus(err, healthStatus),
		)
	}

	at := probeAt{
		client:       client,
		root:         root,
		healthStatus: healthStatus,
		healthTook:   healthTook,
	}

	switch trap.Kind {
	case JWKSUnreachable, KidRollover, KeyRotation:
		return p.observeKeySet(ctx, trap, at)

	case IntrospectionError, IntrospectionMalformed, IntrospectionSlow,
		Revoke:
		return p.observeIntrospection(ctx, trap, at)

	default:
		return "", false, nil
	}
}

type probeAt struct {
	client       *http.Client
	root         string
	healthStatus int
	healthTook   time.Duration
}

func (p *Provider) observeKeySet(
	ctx context.Context,
	trap Trap,
	at probeAt,
) (string, bool, error) {
	switch trap.Kind {
	case JWKSUnreachable:
		p.ownFetches.Add(1)
		status, _, err := probeRoute(ctx, at.client, at.root+RouteJWKS)
		if err == nil && status != http.StatusOK {
			return sprintf(observedJWKSGone, at.healthStatus, status), true, nil
		}

	case KidRollover:
		retired, ok := p.RetiredKid()
		if !ok {
			return "", false, nil
		}
		set, err := p.fetchSet(ctx, at.client, at.root+RouteJWKS)
		if err != nil {
			return "", false, err
		}
		if !set.Has(retired) && set.Has(p.SigningKid()) {
			return sprintf(observedRollover, retired, p.SigningKid()), true, nil
		}

	case KeyRotation:
		retired, ok := p.RetiredKid()
		if !ok {
			return "", false, nil
		}
		set, err := p.fetchSet(ctx, at.client, at.root+RouteJWKS)
		if err != nil {
			return "", false, err
		}
		// An unchanged kid is no rotation at all, not a confirmed one.
		if retired == p.SigningKid() || !set.Has(retired) ||
			!set.Has(p.SigningKid()) {
			return "", false, nil
		}
		minted, err := p.mintTrappedForControl()
		if err != nil {
			return "", false, err
		}

		return sprintf(
			observedRotation,
			retired,
			p.SigningKid(),
			minted.Header.Kid,
		), true, nil

	default:
		// Kinds from the other groups reach their own observer.
	}

	return "", false, nil
}

// observeIntrospection needs a control per trap: "inactive" and "no answer"
// are also what a provider khaos had broken by accident would say.
func (p *Provider) observeIntrospection(
	ctx context.Context,
	trap Trap,
	at probeAt,
) (string, bool, error) {
	switch trap.Kind {
	case IntrospectionError:
		status, _, err := probeRoute(
			ctx,
			at.client,
			p.introspectURL(at.root, p.Opaque()),
		)
		if err == nil && status != http.StatusOK {
			return sprintf(
				observedIntroError,
				at.healthStatus,
				status,
			), true, nil
		}

	case IntrospectionMalformed:
		status, body, err := readRoute(
			ctx,
			at.client,
			p.introspectURL(at.root, p.Opaque()),
		)
		if err != nil {
			return "", false, err
		}
		if status == http.StatusOK && !json.Valid(body) {
			return sprintf(observedIntroBad, status), true, nil
		}

	case IntrospectionSlow:
		status, took, err := probeRoute(
			ctx,
			at.client,
			p.introspectURL(at.root, p.Opaque()),
		)
		if err != nil || status != http.StatusOK {
			return "", false, nil //nolint:nilerr // not confirmed, not an error
		}
		// A differential, not a threshold: the health route is never faulted.
		if took-at.healthTook >= slack(trap.Delay) {
			return sprintf(
				observedIntroSlow,
				took.Round(time.Millisecond),
				at.healthTook.Round(time.Millisecond),
			), true, nil
		}

	case Revoke:
		return p.observeRevocation(ctx, trap, at)

	default:
		// Kinds from the other groups reach their own observer.
	}

	return "", false, nil
}

// Two reads, so a revoked credential differs from a provider that lost all.
func (p *Provider) observeRevocation(
	ctx context.Context,
	trap Trap,
	at probeAt,
) (string, bool, error) {
	control := p.Opaque()

	revoked, err := fetchIntrospection(
		ctx,
		at.client,
		p.introspectURL(at.root, trap.Credential),
	)
	if err != nil {
		return "", false, err
	}

	alive, err := fetchIntrospection(
		ctx,
		at.client,
		p.introspectURL(at.root, control),
	)
	if err != nil {
		return "", false, err
	}

	if !revoked.Active && alive.Active {
		return observedRevoked, true, nil
	}

	return "", false, nil
}

// Counted as khaos's own, so the exported count measures the TARGET only.
func (p *Provider) introspectURL(root, credential string) string {
	p.ownIntrospects.Add(1)
	return root + RouteIntrospect + "?" + ParamToken + "=" + credential
}

func probeRoute(
	ctx context.Context,
	client *http.Client,
	url string,
) (int, time.Duration, error) {
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

func readRoute(
	ctx context.Context,
	client *http.Client,
	url string,
) (int, []byte, error) {
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

// Recorded as khaos's own fetch, keeping the exported count the target's.
func (p *Provider) fetchSet(
	ctx context.Context,
	client *http.Client,
	url string,
) (JWKSet, error) {
	p.ownFetches.Add(1)
	return fetchSet(ctx, client, url)
}

func fetchSet(
	ctx context.Context,
	client *http.Client,
	url string,
) (JWKSet, error) {
	status, body, err := readRoute(ctx, client, url)
	if err != nil {
		return JWKSet{}, err
	}

	if status != http.StatusOK {
		return JWKSet{}, fmt.Errorf(errProviderDown, ErrTrapNotObserved, status)
	}

	return ParseJWKSet(body)
}

func fetchIntrospection(
	ctx context.Context,
	client *http.Client,
	url string,
) (Introspection, error) {
	status, body, err := readRoute(ctx, client, url)
	if err != nil {
		return Introspection{}, err
	}

	if status != http.StatusOK {
		return Introspection{}, fmt.Errorf(
			errProviderDown,
			ErrTrapNotObserved,
			status,
		)
	}

	var out Introspection
	if err := json.Unmarshal(body, &out); err != nil {
		return Introspection{}, err
	}

	return out, nil
}

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
		return rsa.VerifyPKCS1v15(
			pub,
			crypto.SHA256,
			digest[:],
			token.Signature,
		) == nil

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
