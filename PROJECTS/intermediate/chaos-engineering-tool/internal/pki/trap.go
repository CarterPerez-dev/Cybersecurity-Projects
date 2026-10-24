// ©AngelaMos | 2026
// trap.go

package pki

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Kind names one way khaos makes its own certificate authority wrong.
type Kind string

const (
	// The zero value: the authority behaves correctly.
	PassThrough Kind = ""

	// Both are Reason 1; only the Detail wording separates them.
	LeafExpired     Kind = "leaf-expired"
	LeafNotYetValid Kind = "leaf-not-yet-valid"

	IntermediateExpired Kind = "intermediate-expired"

	// All HostnameError. Go removed the CommonName fallback outright.
	WrongSAN       Kind = "wrong-san"
	CommonNameOnly Kind = "common-name-only"
	NoIPSAN        Kind = "no-ip-san"

	// All three produce a byte-identical `signed by unknown authority`.
	SelfSigned          Kind = "self-signed"
	UntrustedCA         Kind = "untrusted-ca"
	MissingIntermediate Kind = "missing-intermediate"

	// UnknownAuthorityError wrapping ConstraintViolationError.
	IssuerNotCA Kind = "issuer-not-ca"

	NameConstraintViolation Kind = "name-constraint-violation"
	PathLengthExceeded      Kind = "path-length-exceeded"

	// Go creates a SHA-1 signature, then refuses it at verification.
	SHA1Signature Kind = "sha1-signature"

	// Verify returns nil for these: they test the target's policy, not x509.
	WeakKey                         Kind = "weak-key"
	ExcessiveLifetime               Kind = "excessive-lifetime"
	KeyUsageWithoutDigitalSignature Kind = "key-usage-no-digital-signature"

	// Both are Reason 4. Go checks EKU down the chain, KeyUsage never.
	EKUClientAuthOnly          Kind = "eku-client-auth-only"
	EKUConstrainedIntermediate Kind = "eku-constrained-intermediate"

	// Verify returns nil: Go does no revocation checking of any kind.
	RevokedViaCRL Kind = "revoked-via-crl"

	// Nothing in the standard library checks a CRL's freshness.
	StaleCRL Kind = "stale-crl"

	CRLUnreachable Kind = "crl-unreachable"

	OCSPRevoked Kind = "ocsp-revoked"
	OCSPUnknown Kind = "ocsp-unknown"

	// The soft-fail traps: a client that proceeds having got no answer.
	OCSPTryLater    Kind = "ocsp-try-later"
	OCSPUnreachable Kind = "ocsp-unreachable"

	// x/crypto/ocsp ignores NextUpdate, so a replayed Good parses clean.
	OCSPStale Kind = "ocsp-stale"

	// ocsp.ParseResponse does not bind the response to the certificate.
	OCSPWrongSerial Kind = "ocsp-wrong-serial"

	OCSPWrongSigner Kind = "ocsp-wrong-signer"

	NoOCSPServer Kind = "no-ocsp-server"

	// Go never parses a staple, so both reach the application untouched.
	StapleGarbage Kind = "staple-garbage"
	StapleAbsent  Kind = "staple-absent"

	// A chain that is valid under a root khaos substituted, so undetectable.
	CASwap Kind = "ca-swap"

	// khaos is the server here, and issues the identity the target presents.
	ClientCertExpired Kind = "client-cert-expired"
	ClientCertAbsent  Kind = "client-cert-absent"
)

const (
	describeLeafExpired     = "serve %s a certificate that expired %s ago"
	describeLeafNotYetValid = "serve %s a certificate that is not valid for another %s"
	describeIntermediateOld = "serve %s a valid leaf under an intermediate that expired %s ago"

	describeWrongSAN       = "serve %s a certificate whose SANs name a different host"
	describeCommonNameOnly = "serve %s a certificate with no SAN extension at all, naming the host only in the legacy CommonName field"
	describeNoIPSAN        = "serve %s a certificate with no IP SANs, reached by address"

	describeSelfSigned     = "serve %s a self-signed leaf where a CA-signed one is expected"
	describeUntrustedCA    = "serve %s a leaf signed by a CA it does not trust"
	describeMissingInterCA = "serve %s a valid leaf while withholding the intermediate that chains it"
	describeIssuerNotCA    = "serve %s a leaf signed by a certificate whose basic constraints say it is not a CA"
	describeNameConstraint = "serve %s a leaf for a name its issuing CA is constrained against"
	describePathLength     = "serve %s a chain one intermediate deeper than its CA's path length allows"

	describeSHA1           = "serve %s a leaf signed with SHA-1 RSA"
	describeWeakKey        = "serve %s a leaf carrying a %d-bit RSA key, which x509 path validation has no floor against"
	describeLifetime       = "serve %s a leaf valid for %d days, which nothing outside a browser enforces"
	describeKeyUsage       = "serve %s a leaf whose KeyUsage omits digitalSignature, which Verify does not check"
	describeEKUClientOnly  = "serve %s a leaf whose extended key usage permits client authentication only"
	describeEKUConstrained = "serve %s a leaf under an intermediate not authorised for server authentication"

	describeRevokedCRL     = "revoke %s's certificate in a valid, in-date CRL from its own issuer"
	describeStaleCRL       = "revoke %s's certificate in a correctly signed CRL whose freshness window closed %s ago"
	describeCRLUnreachable = "refuse %s's connections to the CRL distribution point while every other endpoint stays up"

	describeOCSPRevoked     = "answer %s's revocation queries with a signed Revoked response"
	describeOCSPUnknown     = "answer %s's revocation queries with a signed Unknown response"
	describeOCSPTryLater    = "answer %s's revocation queries with TryLater, the soft-fail trap"
	describeOCSPUnreachable = "refuse %s's connections to the OCSP responder while every other endpoint stays up"
	describeOCSPStale       = "answer %s with a correctly signed Good response whose freshness window closed %s ago"
	describeOCSPWrongSerial = "answer %s with a signed Good response minted for a different certificate's serial"
	describeOCSPWrongSigner = "answer %s with a Good response signed by a key its CA never delegated"
	describeNoOCSPServer    = "serve %s a leaf that names no OCSP responder at all"

	describeStapleGarbage = "staple bytes that are not an OCSP response to %s's handshake"
	describeStapleAbsent  = "omit the stapled revocation response from %s's handshake entirely"

	describeCASwap = "replace the root %s trusts with one khaos controls, and serve a chain that is valid under it"

	describeClientExpired = "require mutual TLS of %s and issue it a client identity that expired %s ago"
	describeClientAbsent  = "require mutual TLS of %s and issue it no client identity at all"
)

const (
	errNeedsDelay = "%w: %s has no magnitude, and a window of zero is indistinguishable from no fault at all"
	errNeedsHost  = "%w: %s has to name the host its certificate is served for"
	errBadBits    = "%w: %s needs an RSA size of at least %d bits, which is the smallest crypto/rsa will generate, and below %d to be a weak key at all, got %d"
	errBadDays    = "%w: %s needs a lifetime longer than %d days to exceed anything, got %d"
	errUnknown    = "%w: %q (known traps: %s)"
	trapSep       = ", "
)

var (
	// ErrInvalidTrap is a known trap specified so that it cannot express it.
	ErrInvalidTrap = errors.New("that trap cannot be armed as specified")

	// ErrUnknownTrap is a name khaos's authority has no fault for.
	ErrUnknownTrap = errors.New(
		"khaos's certificate authority has no such trap",
	)
)

// Trap is one armed misbehaviour and its magnitude, kept as a value rather than
// a closure so it can be journaled.
type Trap struct {
	Kind Kind `json:"kind"`

	// Window is how far a time-based fault moves the boundary it corrupts.
	Window time.Duration `json:"window,omitempty"`

	Host string `json:"host,omitempty"`

	Bits int `json:"bits,omitempty"`

	Days int `json:"days,omitempty"`
}

func (t Trap) Validate() error {
	switch t.Kind {
	case LeafExpired, LeafNotYetValid, IntermediateExpired, StaleCRL,
		OCSPStale:
		if t.Window <= 0 {
			return fmt.Errorf(errNeedsDelay, ErrInvalidTrap, t.Kind)
		}

	case WeakKey:
		if t.Bits < MinimumBits || t.Bits >= StrongBits {
			return fmt.Errorf(
				errBadBits,
				ErrInvalidTrap,
				t.Kind,
				MinimumBits,
				StrongBits,
				t.Bits,
			)
		}

	case ExcessiveLifetime:
		if t.Days <= LifetimeCapDays {
			return fmt.Errorf(
				errBadDays,
				ErrInvalidTrap,
				t.Kind,
				LifetimeCapDays,
				t.Days,
			)
		}

	default:
		// The remaining traps carry no magnitude to validate.
	}

	// Every trap serves a leaf, including the ones that act on the responder.
	if t.Kind != PassThrough && t.Host == "" {
		return fmt.Errorf(errNeedsHost, ErrInvalidTrap, t.Kind)
	}

	if t.Kind != PassThrough && !slices.Contains(Kinds(), string(t.Kind)) {
		return fmt.Errorf(errUnknown, ErrUnknownTrap, t.Kind, joinKinds())
	}

	return nil
}
