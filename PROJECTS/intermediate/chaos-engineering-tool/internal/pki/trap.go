// ©AngelaMos | 2026
// trap.go

package pki

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Kind names one way khaos makes its own certificate authority wrong. Every
// kind maps to a row of the fault table in research 04, which recorded the
// client-side error type, the x509 InvalidReason integer and the fail-open
// behaviour the fault is for, all measured on go1.26.5.
//
// The groups below are the ones the research itself uses, and they are not
// cosmetic: a fault that corrupts the validity window is confirmed differently
// from one that corrupts the chain, and three of the chain faults produce a
// BYTE-IDENTICAL client error, which is the problem this family exists to make
// tractable.
type Kind string

const (
	// PassThrough is the zero value: the authority behaves correctly. An
	// authority with nothing armed has to be indistinguishable from a real one,
	// because every experiment's baseline is measured through it.
	PassThrough Kind = ""

	// LeafExpired and LeafNotYetValid both come back as
	// CertificateInvalidError with Reason 1. There is NO separate
	// NotYetValid reason, so the only thing that tells them apart is whether
	// the Detail says "is after" or "is before". Rows F01 and F02.
	LeafExpired     Kind = "leaf-expired"
	LeafNotYetValid Kind = "leaf-not-yet-valid"

	// IntermediateExpired leaves the leaf in date and expires the CA above it.
	// Row F03, and the fail-open it catches is monitoring that watches leaf
	// expiry only.
	IntermediateExpired Kind = "intermediate-expired"

	// WrongSAN, CommonNameOnly and NoIPSAN are the hostname faults, all
	// HostnameError. CommonNameOnly is worth its own kind because Go removed the
	// CommonName fallback outright: the error names the legacy field, which is a
	// different message from a plain mismatch. Rows F04, F05 and F07.
	WrongSAN       Kind = "wrong-san"
	CommonNameOnly Kind = "common-name-only"
	NoIPSAN        Kind = "no-ip-san"

	// SelfSigned, UntrustedCA and MissingIntermediate are THE THREE that matter
	// most in this family. All three produce exactly
	// `x509: certificate signed by unknown authority`, with no reason code and
	// nothing in the string to separate them, so a target's logs cannot tell an
	// operator which one happened. Disambiguating them is M7's exit gate. Rows
	// F09, F10 and F11.
	SelfSigned          Kind = "self-signed"
	UntrustedCA         Kind = "untrusted-ca"
	MissingIntermediate Kind = "missing-intermediate"

	// IssuerNotCA signs the leaf with a certificate whose IsCA is false, which
	// surfaces as UnknownAuthorityError wrapping ConstraintViolationError. Row
	// F16.
	IssuerNotCA Kind = "issuer-not-ca"

	// NameConstraintViolation and PathLengthExceeded are the two constraint
	// faults, Reason 2 and Reason 3. Rows F17 and F18.
	NameConstraintViolation Kind = "name-constraint-violation"
	PathLengthExceeded      Kind = "path-length-exceeded"

	// SHA1Signature signs the leaf with SHA1WithRSA. Go CREATES it without
	// complaint and refuses it at verification, wrapping InsecureAlgorithmError
	// inside UnknownAuthorityError, so this reads as an authority failure unless
	// the caller unwraps. Row F12, measured again on this box before the family
	// was built.
	SHA1Signature Kind = "sha1-signature"

	// WeakKey through KeyUsageWithoutDigitalSignature are the faults Go
	// ACCEPTS. They return nil from Verify, so they do not test the x509
	// library at all -- they test whether the TARGET imposed a policy of its
	// own. Rows F13, F20 and F19.
	//
	// These are the most valuable experiments in the family for exactly that
	// reason, and also the ones whose polarity is easiest to get wrong: a target
	// that accepts them is not being caught out by Go, it simply has no floor.
	WeakKey                         Kind = "weak-key"
	ExcessiveLifetime               Kind = "excessive-lifetime"
	KeyUsageWithoutDigitalSignature Kind = "key-usage-no-digital-signature"

	// EKUClientAuthOnly and EKUConstrainedIntermediate are the extended key
	// usage faults, Reason 4 and Reason 9. Go checks EKU nested down the chain
	// but does not check the basic KeyUsage bits on a leaf, which is why the
	// kind above exists beside these two. Rows F14 and F15.
	EKUClientAuthOnly          Kind = "eku-client-auth-only"
	EKUConstrainedIntermediate Kind = "eku-constrained-intermediate"

	// RevokedViaCRL is the headline of the whole family. The leaf is revoked in
	// a valid, in-date, correctly signed CRL from its own issuer, and
	// `Certificate.Verify` returns nil, because Go performs no revocation
	// checking of any kind and has no option to turn it on. Row F21.
	//
	// khaos must therefore report `unsupported` rather than `pass` against a Go
	// target that does nothing: there is no revocation check to have failed.
	// That distinction is the other half of M7's exit gate.
	RevokedViaCRL Kind = "revoked-via-crl"

	// StaleCRL revokes the leaf in a CRL whose NextUpdate is in the past. It is
	// a DIFFERENT fault from RevokedViaCRL and strictly harder to pass: the
	// target does fetch and parse a CRL, and still accepts the certificate,
	// because nothing in the standard library checks freshness and step 5 of the
	// six-step check is the one people skip. Row F33.
	StaleCRL Kind = "stale-crl"

	// CRLUnreachable serves the leaf with a CRL distribution point that refuses
	// the connection, while every other endpoint stays up. A target that treats
	// "could not fetch" as "not revoked" fails open here and nowhere else.
	CRLUnreachable Kind = "crl-unreachable"

	// OCSPRevoked and OCSPUnknown are the two answers a responder gives that a
	// correct client must reject. "Unknown" from the authoritative responder is
	// not "good", and collapsing the two is its own fail-open.
	OCSPRevoked Kind = "ocsp-revoked"
	OCSPUnknown Kind = "ocsp-unknown"

	// OCSPTryLater and OCSPUnreachable are the soft-fail traps, and research 04
	// calls soft-fail the reason revocation is near-useless in practice. A
	// client that proceeds because it could not get an answer has a seat belt
	// that unbuckles under load.
	OCSPTryLater    Kind = "ocsp-try-later"
	OCSPUnreachable Kind = "ocsp-unreachable"

	// OCSPStale returns a correctly signed Good response whose NextUpdate is in
	// the past. Measured: x/crypto/ocsp does not check freshness, so this parses
	// with a nil error and a replayed Good is trusted forever. Row F30.
	OCSPStale Kind = "ocsp-stale"

	// OCSPWrongSerial is the single highest-value trap in the OCSP group,
	// because the bypass is one word of caller code. A Good response minted for
	// a DIFFERENT serial is rejected by ocsp.ParseResponseForCert and accepted
	// by ocsp.ParseResponse, which does not bind the response to the
	// certificate at all. Row F31.
	OCSPWrongSerial Kind = "ocsp-wrong-serial"

	// OCSPWrongSigner signs the response with a key the CA never delegated.
	// CheckSignatureFrom catches it, but only if the caller calls it.
	OCSPWrongSigner Kind = "ocsp-wrong-signer"

	// NoOCSPServer mints a leaf with no OCSPServer at all, which models Let's
	// Encrypt after it ended OCSP in 2025. The question it asks is what the
	// target does when there is nothing to ask: fail open, or fall back to the
	// CRL it also published. Row F34.
	NoOCSPServer Kind = "no-ocsp-server"

	// StapleGarbage and StapleAbsent act on the stapled response rather than on
	// the responder. Go never parses a staple, so both reach the application
	// untouched: one as bytes that are not an OCSP response, the other as an
	// empty field a soft-failing app reads as good. Rows F28 and F29.
	StapleGarbage Kind = "staple-garbage"
	StapleAbsent  Kind = "staple-absent"

	// CASwap replaces the root the target trusts with one khaos controls, and
	// then serves a chain that is VALID under it. Nothing in the client can
	// detect this, which is the point: it is the CA-compromise scenario, and the
	// only defences are pinning or certificate transparency. Row F24.
	CASwap Kind = "ca-swap"

	// ClientCertExpired and ClientCertAbsent are the two MUTUAL TLS faults, and
	// they are the only traps that act on the target's own identity rather than
	// on the dependency's.
	//
	// khaos is the server here, so it is khaos that demands a client
	// certificate and khaos that issues the one the target presents. The fault
	// is in that issued identity: expired, or withheld entirely, which is what
	// a failed rotation and a bypassed sidecar actually look like.
	//
	// What they catch is NOT the rejection -- khaos's server rejects correctly
	// either way. It is whether the target NOTICES. Research 04 section 7.2
	// measured the whole ClientAuth matrix and under TLS 1.3 every single row
	// returned a successful tls.Dial, including the rows where the server
	// refused the identity and served nothing at all; the error arrives on the
	// first read. Under TLS 1.2 the same case fails at Dial. So a client that
	// dials and does not read reports a healthy dependency that refused it, and
	// the defect is invisible on the older protocol and total on the newer one.
	//
	// Rows F27 and F26.
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
	errBadBits    = "%w: %s needs an RSA size below %d bits to be a weak key at all, got %d"
	errBadDays    = "%w: %s needs a lifetime longer than %d days to exceed anything, got %d"
	errUnknown    = "%w: %q (known traps: %s)"
	trapSep       = ", "
)

var (
	// ErrInvalidTrap is a trap khaos understands, specified in a way that cannot
	// express the fault.
	ErrInvalidTrap = errors.New("that trap cannot be armed as specified")

	// ErrUnknownTrap is a name khaos's authority has no fault for.
	ErrUnknownTrap = errors.New(
		"khaos's certificate authority has no such trap",
	)
)

// Trap is one armed misbehaviour and its magnitude. It is a value rather than a
// closure so it can be journaled: the authority dies with the process, so the
// journal record is the only durable account of what a run actually did.
type Trap struct {
	Kind Kind `json:"kind"`

	// Window is how far a time-based fault moves the boundary it corrupts: how
	// long ago the leaf expired, how far in the future it starts, how stale the
	// CRL or OCSP response is.
	Window time.Duration `json:"window,omitempty"`

	// Host is the name the served certificate is minted for, and the name the
	// hostname faults deliberately get wrong.
	Host string `json:"host,omitempty"`

	// Bits is the RSA modulus size WeakKey mints. It is a parameter because the
	// interesting question is where the target's floor sits, and a single fixed
	// size can only ever answer it for one floor.
	Bits int `json:"bits,omitempty"`

	// Days is the leaf lifetime ExcessiveLifetime mints, for the same reason.
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
		if t.Bits <= 0 || t.Bits >= StrongBits {
			return fmt.Errorf(
				errBadBits,
				ErrInvalidTrap,
				t.Kind,
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

	// EVERY trap mints and serves a leaf, including the ones that act on the
	// responder, because a revocation answer about no certificate is not a fault
	// anyone can observe. So the host is required unconditionally rather than
	// through a per-kind predicate that would have no false case.
	if t.Kind != PassThrough && t.Host == "" {
		return fmt.Errorf(errNeedsHost, ErrInvalidTrap, t.Kind)
	}

	if t.Kind != PassThrough && !slices.Contains(Kinds(), string(t.Kind)) {
		return fmt.Errorf(errUnknown, ErrUnknownTrap, t.Kind, joinKinds())
	}

	return nil
}
