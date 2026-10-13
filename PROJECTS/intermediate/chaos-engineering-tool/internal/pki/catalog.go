// ©AngelaMos | 2026
// catalog.go

package pki

import (
	"fmt"
	"strings"
	"time"
)

const (
	// StrongBits is the modulus khaos mints when it is NOT attacking the key
	// size. 2048 is the floor every current policy agrees on, and x509 path
	// validation enforces none of them.
	StrongBits = 2048

	// LifetimeCapDays is the CA/Browser Forum maximum leaf lifetime. Nothing
	// outside a browser enforces it, which is what ExcessiveLifetime measures.
	LifetimeCapDays = 200

	// DefaultLeafDays is an ordinary, unremarkable lifetime for every honest
	// certificate khaos serves.
	DefaultLeafDays = 90

	// DefaultWindow is how far a time-based trap moves its boundary when the
	// experiment does not say. It is far longer than any plausible clock skew,
	// because a fault inside the skew tolerance is not a fault.
	DefaultWindow = 24 * time.Hour

	// DefaultWeakBits is the modulus WeakKey mints by default. Measured on
	// go1.26.5: a 1024-bit leaf chains and verifies with a nil error.
	DefaultWeakBits = 1024

	// DefaultExcessiveDays is comfortably past the CABF cap and past every
	// shorter policy a target might have adopted instead.
	DefaultExcessiveDays = 2000

	// DefaultHost is the name khaos mints honest certificates for when the
	// caller does not say. It is a .invalid name per RFC 2606, so a chain that
	// escaped into something real can never resolve.
	DefaultHost = "dependency.khaos.invalid"

	// loopbackSAN is the IP the honest leaf carries so that NoIPSAN has
	// something to take away. khaos binds loopback in tests and a bridge
	// address in a container, and this SAN only has to exist for the trap to be
	// expressible -- the hostname faults are what judge the names.
	loopbackSAN = "127.0.0.1"

	// clockSlack backdates every honest certificate slightly. Without it a leaf
	// minted and presented in the same millisecond can land on the wrong side
	// of a NotBefore comparison on a machine whose clock ticks between the two,
	// which would make the CONTROL flaky and leave khaos unable to establish
	// anything.
	clockSlack = time.Minute
)

const (
	// RouteCRL, RouteOCSP and RouteHealth are the authority's HTTP surface.
	//
	// RouteHealth exists to be the CONTROL for the two unreachable traps. Its
	// whole job is to stay up while the CRL or OCSP endpoint refuses, because
	// "khaos broke one endpoint" and "khaos fell over" are different claims and
	// only the first one is a fault.
	RouteCRL    = "/crl"
	RouteOCSP   = "/ocsp"
	RouteHealth = "/healthz"
)

// Kinds is the whole catalogue, in the order the research groups it: validity,
// identity, authority, algorithm, policy, CRL revocation, OCSP revocation,
// stapling, trust store. Tests census against this, so a new trap without a
// case of its own turns them red.
func Kinds() []string {
	return []string{
		string(LeafExpired),
		string(LeafNotYetValid),
		string(IntermediateExpired),

		string(WrongSAN),
		string(CommonNameOnly),
		string(NoIPSAN),

		string(SelfSigned),
		string(UntrustedCA),
		string(MissingIntermediate),
		string(IssuerNotCA),
		string(NameConstraintViolation),
		string(PathLengthExceeded),

		string(SHA1Signature),
		string(EKUClientAuthOnly),
		string(EKUConstrainedIntermediate),

		string(WeakKey),
		string(ExcessiveLifetime),
		string(KeyUsageWithoutDigitalSignature),

		string(RevokedViaCRL),
		string(StaleCRL),
		string(CRLUnreachable),

		string(OCSPRevoked),
		string(OCSPUnknown),
		string(OCSPTryLater),
		string(OCSPUnreachable),
		string(OCSPStale),
		string(OCSPWrongSerial),
		string(OCSPWrongSigner),
		string(NoOCSPServer),

		string(StapleGarbage),
		string(StapleAbsent),

		string(CASwap),
	}
}

func joinKinds() string {
	return strings.Join(Kinds(), trapSep)
}

// GoAccepts reports whether go1.26.5's own certificate verification returns a
// NIL error for this trap. It is the single most important predicate in the
// package, because it decides what a target's acceptance MEANS.
//
// For a trap Go refuses, an acceptance proves the target weakened or skipped
// verification. For a trap Go accepts, an acceptance proves nothing of the
// kind: there was no check to skip, and the finding is that the target has no
// policy of its own. Reporting the second as the first would be khaos accusing
// a target of a defect that only exists in the operator's expectations.
//
// Every entry here was measured, not assumed; research 04's fault table records
// the run, and the CRL and SHA-1 rows were re-measured on this box before this
// family was built.
func GoAccepts(kind Kind) bool {
	switch kind {
	case WeakKey, ExcessiveLifetime, KeyUsageWithoutDigitalSignature,
		RevokedViaCRL, StaleCRL, CRLUnreachable,
		OCSPRevoked, OCSPUnknown, OCSPTryLater, OCSPUnreachable,
		OCSPStale, OCSPWrongSerial, OCSPWrongSigner, NoOCSPServer,
		StapleGarbage, StapleAbsent, CASwap:
		return true

	case PassThrough, LeafExpired, LeafNotYetValid, IntermediateExpired,
		WrongSAN, CommonNameOnly, NoIPSAN,
		SelfSigned, UntrustedCA, MissingIntermediate, IssuerNotCA,
		NameConstraintViolation, PathLengthExceeded,
		SHA1Signature, EKUClientAuthOnly, EKUConstrainedIntermediate:
		return false

	default:
		// An unknown kind is treated as refused, which is the conservative
		// direction: it makes khaos claim LESS about a target than it could.
		return false
	}
}

// Describe states the trap with its actual magnitude, for the consent prompt
// and the plan output. The identity family established that a description
// naming a parameter without its VALUE is worse than none, because the operator
// approves a sentence and then gets a different fault.
func (t Trap) Describe(target string) string {
	switch t.Kind {
	case LeafExpired, LeafNotYetValid, IntermediateExpired, WrongSAN,
		CommonNameOnly, NoIPSAN:
		return t.describeSubject(target)

	case SelfSigned, UntrustedCA, MissingIntermediate, IssuerNotCA,
		NameConstraintViolation, PathLengthExceeded, SHA1Signature,
		EKUClientAuthOnly, EKUConstrainedIntermediate:
		return t.describeChain(target)

	case WeakKey, ExcessiveLifetime, KeyUsageWithoutDigitalSignature,
		CASwap:
		return t.describePolicy(target)

	case PassThrough:
		return ""

	default:
		return t.describeRevocation(target)
	}
}

// describeSubject covers the faults in WHEN the certificate is valid and WHO it
// is for.
func (t Trap) describeSubject(target string) string {
	switch t.Kind {
	case LeafExpired:
		return fmt.Sprintf(describeLeafExpired, target, t.window())
	case LeafNotYetValid:
		return fmt.Sprintf(describeLeafNotYetValid, target, t.window())
	case IntermediateExpired:
		return fmt.Sprintf(describeIntermediateOld, target, t.window())

	case WrongSAN:
		return fmt.Sprintf(describeWrongSAN, target)
	case CommonNameOnly:
		return fmt.Sprintf(describeCommonNameOnly, target)
	case NoIPSAN:
		return fmt.Sprintf(describeNoIPSAN, target)

	default:
		return ""
	}
}

// describeChain covers the faults in the path from leaf to trusted root, plus
// the two that are structurally the same question about signing and usage.
func (t Trap) describeChain(target string) string {
	switch t.Kind {
	case SelfSigned:
		return fmt.Sprintf(describeSelfSigned, target)
	case UntrustedCA:
		return fmt.Sprintf(describeUntrustedCA, target)
	case MissingIntermediate:
		return fmt.Sprintf(describeMissingInterCA, target)
	case IssuerNotCA:
		return fmt.Sprintf(describeIssuerNotCA, target)
	case NameConstraintViolation:
		return fmt.Sprintf(describeNameConstraint, target)
	case PathLengthExceeded:
		return fmt.Sprintf(describePathLength, target)

	case SHA1Signature:
		return fmt.Sprintf(describeSHA1, target)
	case EKUClientAuthOnly:
		return fmt.Sprintf(describeEKUClientOnly, target)
	case EKUConstrainedIntermediate:
		return fmt.Sprintf(describeEKUConstrained, target)

	default:
		return ""
	}
}

// describePolicy covers the faults crypto/x509 ACCEPTS, where the finding is
// the absence of a policy rather than a skipped check.
func (t Trap) describePolicy(target string) string {
	switch t.Kind {
	case WeakKey:
		return fmt.Sprintf(describeWeakKey, target, t.bits())
	case ExcessiveLifetime:
		return fmt.Sprintf(describeLifetime, target, t.days())
	case KeyUsageWithoutDigitalSignature:
		return fmt.Sprintf(describeKeyUsage, target)
	case CASwap:
		return fmt.Sprintf(describeCASwap, target)

	default:
		return ""
	}
}

// describeRevocation covers everything that acts on revocation rather than on
// the certificate.
func (t Trap) describeRevocation(target string) string {
	switch t.Kind {
	case RevokedViaCRL:
		return fmt.Sprintf(describeRevokedCRL, target)
	case StaleCRL:
		return fmt.Sprintf(describeStaleCRL, target, t.window())
	case CRLUnreachable:
		return fmt.Sprintf(describeCRLUnreachable, target)

	case OCSPRevoked:
		return fmt.Sprintf(describeOCSPRevoked, target)
	case OCSPUnknown:
		return fmt.Sprintf(describeOCSPUnknown, target)
	case OCSPTryLater:
		return fmt.Sprintf(describeOCSPTryLater, target)
	case OCSPUnreachable:
		return fmt.Sprintf(describeOCSPUnreachable, target)
	case OCSPStale:
		return fmt.Sprintf(describeOCSPStale, target, t.window())
	case OCSPWrongSerial:
		return fmt.Sprintf(describeOCSPWrongSerial, target)
	case OCSPWrongSigner:
		return fmt.Sprintf(describeOCSPWrongSigner, target)
	case NoOCSPServer:
		return fmt.Sprintf(describeNoOCSPServer, target)

	case StapleGarbage:
		return fmt.Sprintf(describeStapleGarbage, target)
	case StapleAbsent:
		return fmt.Sprintf(describeStapleAbsent, target)

	default:
		return ""
	}
}

func (t Trap) window() time.Duration {
	if t.Window <= 0 {
		return DefaultWindow
	}
	return t.Window
}

func (t Trap) bits() int {
	if t.Bits <= 0 {
		return DefaultWeakBits
	}
	return t.Bits
}

func (t Trap) days() int {
	if t.Days <= 0 {
		return DefaultExcessiveDays
	}
	return t.Days
}
