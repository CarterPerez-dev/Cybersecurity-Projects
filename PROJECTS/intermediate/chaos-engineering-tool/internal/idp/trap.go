// ©AngelaMos | 2026
// trap.go

package idp

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Kind names one way khaos makes its own identity provider wrong.
type Kind string

const (
	// PassThrough is the zero value, and every experiment's baseline.
	PassThrough Kind = ""

	// AlgNone emits `{"alg":"none"}` with an empty signature. CVE-2022-23540.
	AlgNone Kind = "alg-none"

	// AlgConfusion emits HS256 keyed on the published RSA key. CVE-2015-9235.
	AlgConfusion Kind = "alg-confusion"

	// EmbeddedJWK carries its own unpublished signing key. CVE-2018-0114.
	EmbeddedJWK Kind = "embedded-jwk"

	// Each of these is CORRECTLY SIGNED with exactly one wrong claim.
	ClaimExpired       Kind = "claim-expired"
	ClaimNotYetValid   Kind = "claim-not-yet-valid"
	ClaimWrongAudience Kind = "claim-wrong-audience"
	ClaimForeignIssuer Kind = "claim-foreign-issuer"

	// SignatureTruncated cuts a valid signature to one byte. CVE-2020-28042.
	SignatureTruncated Kind = "signature-truncated"

	// SignatureZero emits ES256 all-zero, the shape of CVE-2022-21449.
	// ecdsa.Verify rejects r = s = 0, so Go is only vulnerable if it skips it.
	SignatureZero Kind = "signature-zero"

	// SignatureWeakKey signs below crypto/rsa's floor. CVE-2022-23539's class.
	SignatureWeakKey Kind = "signature-weak-key"

	// JWKSUnreachable stops serving the JWK Set, and nothing else.
	JWKSUnreachable Kind = "jwks-unreachable"

	// KidRollover rotates and REMOVES the retired key from the JWK Set.
	KidRollover Kind = "kid-rollover"

	// KeyRotation rotates with both keys published, and is the one trap where
	// DENIED is the defect: refusing a correctly signed current token.
	KeyRotation Kind = "key-rotation"

	// IntrospectionError answers 503 while staying REACHABLE and answering.
	IntrospectionError Kind = "introspection-error"

	// IntrospectionMalformed answers 200 with a body that is not JSON.
	IntrospectionMalformed Kind = "introspection-malformed"

	// IntrospectionSlow holds that one route past the caller's timeout.
	IntrospectionSlow Kind = "introspection-slow"

	// Revoke revokes at a provider the target can still reach, and is not asking.
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

// Trap is a value rather than a closure so that it can be journaled.
type Trap struct {
	Kind Kind `json:"kind"`

	Delay time.Duration `json:"delay,omitempty"`

	Credential string `json:"credential,omitempty"`

	// KeyForm has to be the exact bytes the target loaded its key from.
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
		// The remaining traps carry no magnitude to validate.
	}

	if t.Kind != PassThrough && !slices.Contains(Kinds(), string(t.Kind)) {
		return fmt.Errorf(errUnknownTrap, ErrUnknownTrap, t.Kind, joinKinds())
	}

	return nil
}

// Describe states the trap WITH its magnitude, or it understates the fault.
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
