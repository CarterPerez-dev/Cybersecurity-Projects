// ©AngelaMos | 2026
// trap.go

package idp

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Kind names one way khaos makes its own identity provider wrong. Every kind
// maps to a verifier defect with a traceable anchor in research 07, and the
// mapping is one-to-one with the experiments so `khaos catalog` names the actual
// trap rather than a generic entry.
type Kind string

const (
	// PassThrough is the zero value: the provider behaves correctly. A provider
	// with nothing armed must be indistinguishable from a real one, because every
	// experiment's baseline is measured against it.
	PassThrough Kind = ""

	// AlgNone emits `{"alg":"none"}` with an empty signature. Trap T1,
	// CVE-2022-23540.
	AlgNone Kind = "alg-none"

	// AlgConfusion emits HS256 keyed on the bytes of the published RSA public
	// key. Trap T2, CVE-2015-9235 and three others.
	AlgConfusion Kind = "alg-confusion"

	// EmbeddedJWK emits a token carrying its own signing key in the `jwk` header,
	// signed by a key khaos never publishes. Trap T2b, CVE-2018-0114.
	EmbeddedJWK Kind = "embedded-jwk"

	// ClaimExpired through ClaimForeignIssuer each emit a CORRECTLY SIGNED token
	// with exactly one wrong claim. Research 07 calls this the cleanest
	// experiment design in the tool: a 2xx isolates precisely which check is
	// missing, with no ambiguity about the signature.
	ClaimExpired       Kind = "claim-expired"
	ClaimNotYetValid   Kind = "claim-not-yet-valid"
	ClaimWrongAudience Kind = "claim-wrong-audience"
	ClaimForeignIssuer Kind = "claim-foreign-issuer"

	// SignatureTruncated cuts a valid signature to one byte. Trap T6b,
	// CVE-2020-28042.
	SignatureTruncated Kind = "signature-truncated"

	// SignatureZero emits ES256 with an all-zero signature. Trap T6c, the shape
	// of CVE-2022-21449. Measured on go1.26.5: ecdsa.Verify rejects r = s = 0, so
	// a Go verifier is only vulnerable if it skips the check, which is what the
	// range fixture does on purpose.
	SignatureZero Kind = "signature-zero"

	// SignatureWeakKey signs with a modulus below the size crypto/rsa accepts.
	// Trap T6a's class, CVE-2022-23539: a key type or size not validated against
	// the algorithm.
	SignatureWeakKey Kind = "signature-weak-key"

	// JWKSUnreachable stops serving the JWK Set. Trap T3 and taxonomy row F2,
	// and research 07 calls it the highest-value trap in the archive because the
	// code path is reachable only while the provider is down.
	JWKSUnreachable Kind = "jwks-unreachable"

	// KidRollover rotates the signing key and REMOVES the retired one from the
	// JWK Set, so a token signed by it is no longer verifiable by anyone who
	// refetches. Trap T4 and taxonomy row F3.
	KidRollover Kind = "kid-rollover"

	// KeyRotation rotates WITH an overlap window: both keys stay published and
	// new tokens carry the new one. This is the availability mirror of
	// KidRollover, and it is the one trap in the family where DENIED is the
	// defect, because refusing a correctly signed current token is the failure.
	KeyRotation Kind = "key-rotation"

	// IntrospectionError answers introspection with a 503. It is deliberately not
	// an outage: the provider is reachable and answering, so a caller's
	// `err != nil` branch is never taken and only its status handling decides.
	// Taxonomy row F20, where collapsing deny into unknown is the defect.
	IntrospectionError Kind = "introspection-error"

	// IntrospectionMalformed answers 200 with a body that is not JSON, so the
	// caller's decode-error branch decides. RFC 7662 is explicit that the absence
	// of a usable response is not `active: true`.
	IntrospectionMalformed Kind = "introspection-malformed"

	// IntrospectionSlow holds introspection past the caller's timeout while
	// answering everything else promptly. A slow authority is not an unreachable
	// one and a caller's code tells them apart.
	IntrospectionSlow Kind = "introspection-slow"

	// Revoke revokes a credential at a provider the target can still reach. The
	// contrast with `identity.idp_outage` is the whole point: there the authority
	// is unreachable, here it is answering `active: false` and the target is
	// simply not asking.
	Revoke Kind = "revoke"
)

const (
	describeAlgNone            = "make khaos's identity provider mint %s an unsigned token that declares `alg: none`"
	describeAlgConfusion       = "make khaos's identity provider mint %s an HS256 token keyed on its own published RSA public key, as %s bytes"
	describeEmbeddedJWK        = "make khaos's identity provider mint %s a token carrying its own signing key in the `jwk` header"
	describeClaimExpired       = "make khaos's identity provider mint %s a correctly signed token that expired %s ago"
	describeClaimNotYetValid   = "make khaos's identity provider mint %s a correctly signed token that is not valid for another %s"
	describeClaimWrongAudience = "make khaos's identity provider mint %s a correctly signed token addressed to a different service"
	describeClaimForeignIssuer = "make khaos's identity provider mint %s a correctly signed token from a second issuer it also publishes keys for"
	describeSignatureTruncated = "make khaos's identity provider mint %s a token whose valid signature is cut to one byte"
	describeSignatureZero      = "make khaos's identity provider mint %s an ES256 token whose signature is all zero bytes"
	describeSignatureWeakKey   = "make khaos's identity provider mint %s a token signed with a modulus below the size crypto/rsa will accept"
	describeJWKSUnreachable    = "stop khaos's identity provider from serving its JWK Set to %s, leaving every other endpoint up"
	describeKidRollover        = "rotate khaos's identity provider's signing key and withdraw the retired one from the JWK Set %s reads"
	describeKeyRotation        = "rotate khaos's identity provider's signing key with both keys published, so %s has to pick up the new one"
	describeIntrospectionError = "make khaos's identity provider answer %s's introspection calls with a 503 while staying reachable"
	describeIntrospectionBad   = "make khaos's identity provider answer %s's introspection calls with a 200 and a body that is not JSON"
	describeIntrospectionSlow  = "hold %s's introspection calls for %s while answering everything else promptly"
	describeRevoke             = "revoke a credential at khaos's identity provider while %s can still reach it"

	errNeedsDelay      = "%w: %s has no magnitude, and a hold of zero is indistinguishable from no hold at all"
	errNeedsCredential = "%w: %s has to name the credential it revokes"
	errUnknownTrap     = "%w: %q (known traps: %s)"
	trapSep            = ", "
)

var ErrInvalidTrap = errors.New("that trap cannot be armed as specified")

var ErrUnknownTrap = errors.New("khaos's identity provider has no such trap")

// Trap is one armed misbehaviour and its magnitude. It is a value rather than a
// closure so it can be journaled: the provider dies with the process, so the
// journal record is the only durable account of what a run actually did.
type Trap struct {
	Kind Kind `json:"kind"`

	// Delay is how long IntrospectionSlow holds a call, and how far ClaimExpired
	// and ClaimNotYetValid move the claim they corrupt.
	Delay time.Duration `json:"delay,omitempty"`

	// Credential is the opaque token Revoke acts on.
	Credential string `json:"credential,omitempty"`

	// KeyForm is the serialization AlgConfusion keys its HMAC on. It is a
	// parameter rather than a fixed choice because research 07 is explicit that
	// the same verifier bug is unreachable under the wrong form: the attack has
	// to use the exact bytes the target loaded its public key from.
	KeyForm KeyForm `json:"key_form,omitempty"`
}

func (t Trap) Validate() error {
	switch t.Kind {
	case IntrospectionSlow, ClaimExpired, ClaimNotYetValid:
		if t.Delay <= 0 {
			return fmt.Errorf(errNeedsDelay, ErrInvalidTrap, t.Kind)
		}
	case Revoke:
		if t.Credential == "" {
			return fmt.Errorf(errNeedsCredential, ErrInvalidTrap, t.Kind)
		}
	case AlgConfusion:
		if !slices.Contains(KeyForms(), string(t.KeyForm)) {
			return fmt.Errorf(errUnknownKeyForm, ErrUnknownKeyForm,
				t.KeyForm, SPKIPEM, SPKIDER, PKCS1PEM, Modulus)
		}
	default:
		// The remaining traps carry no parameter to validate.
	}

	if t.Kind != PassThrough && !slices.Contains(Kinds(), string(t.Kind)) {
		return fmt.Errorf(errUnknownTrap, ErrUnknownTrap, t.Kind, joinKinds())
	}

	return nil
}

// Describe states the trap with its actual magnitude. The proxy tier paid for
// this lesson: reading the kind alone and leaving the parameters at zero printed
// a plan line that understated the fault it was asking consent for.
func (t Trap) Describe(target string) string {
	switch t.Kind {
	case AlgNone:
		return fmt.Sprintf(describeAlgNone, target)
	case AlgConfusion:
		return fmt.Sprintf(describeAlgConfusion, target, t.KeyForm)
	case EmbeddedJWK:
		return fmt.Sprintf(describeEmbeddedJWK, target)
	case ClaimExpired:
		return fmt.Sprintf(describeClaimExpired, target, t.Delay)
	case ClaimNotYetValid:
		return fmt.Sprintf(describeClaimNotYetValid, target, t.Delay)
	case ClaimWrongAudience:
		return fmt.Sprintf(describeClaimWrongAudience, target)
	case ClaimForeignIssuer:
		return fmt.Sprintf(describeClaimForeignIssuer, target)
	case SignatureTruncated:
		return fmt.Sprintf(describeSignatureTruncated, target)
	case SignatureZero:
		return fmt.Sprintf(describeSignatureZero, target)
	case SignatureWeakKey:
		return fmt.Sprintf(describeSignatureWeakKey, target)
	case JWKSUnreachable:
		return fmt.Sprintf(describeJWKSUnreachable, target)
	case KidRollover:
		return fmt.Sprintf(describeKidRollover, target)
	case KeyRotation:
		return fmt.Sprintf(describeKeyRotation, target)
	case IntrospectionError:
		return fmt.Sprintf(describeIntrospectionError, target)
	case IntrospectionMalformed:
		return fmt.Sprintf(describeIntrospectionBad, target)
	case IntrospectionSlow:
		return fmt.Sprintf(describeIntrospectionSlow, target, t.Delay)
	case Revoke:
		return fmt.Sprintf(describeRevoke, target)
	default:
		return string(t.Kind)
	}
}

// Forgery reports whether the trap corrupts what the provider MINTS, as opposed
// to what it serves or how it answers. It decides which probe stream an
// experiment needs, and it is derived here so an experiment cannot disagree with
// the trap about its own shape.
func (t Trap) Forgery() bool {
	switch t.Kind {
	case AlgNone, AlgConfusion, EmbeddedJWK,
		ClaimExpired, ClaimNotYetValid, ClaimWrongAudience, ClaimForeignIssuer,
		SignatureTruncated, SignatureZero, SignatureWeakKey:
		return true
	default:
		return false
	}
}

// Kinds is every trap an operator can arm, in a stable order.
func Kinds() []string {
	return []string{
		string(AlgNone),
		string(AlgConfusion),
		string(EmbeddedJWK),
		string(ClaimExpired),
		string(ClaimNotYetValid),
		string(ClaimWrongAudience),
		string(ClaimForeignIssuer),
		string(SignatureTruncated),
		string(SignatureZero),
		string(SignatureWeakKey),
		string(JWKSUnreachable),
		string(KidRollover),
		string(KeyRotation),
		string(IntrospectionError),
		string(IntrospectionMalformed),
		string(IntrospectionSlow),
		string(Revoke),
	}
}

func joinKinds() string {
	kinds := Kinds()
	out := kinds[0]
	for _, kind := range kinds[1:] {
		out += trapSep + kind
	}
	return out
}
