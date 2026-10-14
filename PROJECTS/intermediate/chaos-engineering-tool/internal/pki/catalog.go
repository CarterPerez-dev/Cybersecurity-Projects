// ©AngelaMos | 2026
// catalog.go

package pki

import (
	"fmt"
	"strings"
	"time"
)

const (
	StrongBits = 2048

	// crypto/rsa refuses to GENERATE below this, so a smaller size is not a
	// weak key khaos can serve, it is an arm that fails with a mint error.
	MinimumBits = 1024

	// The CA/Browser Forum cap, which nothing outside a browser enforces.
	LifetimeCapDays = 200

	DefaultLeafDays = 90

	// Far longer than any clock skew: a fault inside the tolerance is none.
	DefaultWindow = 24 * time.Hour

	DefaultWeakBits = 1024

	DefaultExcessiveDays = 2000

	DefaultHost = "dependency.khaos.invalid"

	loopbackSAN = "127.0.0.1"

	// Backdates honest certificates, so one minted and presented at once
	// cannot land on the wrong side of NotBefore.
	clockSlack = time.Minute
)

const (
	// RouteCRL, RouteOCSP and RouteHealth are the authority's HTTP surface.
	// Health keeps answering while CRL or OCSP refuses, so khaos can show it
	// broke one endpoint rather than fell over.
	RouteCRL    = "/crl"
	RouteOCSP   = "/ocsp"
	RouteHealth = "/healthz"

	// RouteRoot is read per request, because CASwap replaces the anchor at arm
	// time.
	RouteRoot = "/root"
)

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

		string(ClientCertExpired),
		string(ClientCertAbsent),
	}
}

func joinKinds() string {
	return strings.Join(Kinds(), trapSep)
}

// GoAccepts reports whether go1.26.5's own verification returns a NIL error
// for this trap, which decides what an acceptance means: for a trap Go
// refuses, the target skipped a check; for one Go accepts, there was none.
func GoAccepts(kind Kind) bool {
	switch kind {
	case WeakKey, ExcessiveLifetime, KeyUsageWithoutDigitalSignature,
		RevokedViaCRL, StaleCRL, CRLUnreachable,
		OCSPRevoked, OCSPUnknown, OCSPTryLater, OCSPUnreachable,
		OCSPStale, OCSPWrongSerial, OCSPWrongSigner, NoOCSPServer,
		StapleGarbage, StapleAbsent, CASwap:
		return true

	case ClientCertExpired, ClientCertAbsent:
		// The DEPENDENCY's certificate is impeccable; khaos rejects the client.
		return true

	case PassThrough, LeafExpired, LeafNotYetValid, IntermediateExpired,
		WrongSAN, CommonNameOnly, NoIPSAN,
		SelfSigned, UntrustedCA, MissingIntermediate, IssuerNotCA,
		NameConstraintViolation, PathLengthExceeded,
		SHA1Signature, EKUClientAuthOnly, EKUConstrainedIntermediate:
		return false

	default:
		// An unknown kind is refused, which claims less about a target.
		return false
	}
}

// Describe states the trap with its actual magnitude, for the consent prompt.
// Naming a parameter without its value would have the operator approve one
// sentence and get a different fault.
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

	case ClientCertExpired:
		return fmt.Sprintf(describeClientExpired, target, t.window())

	case ClientCertAbsent:
		return fmt.Sprintf(describeClientAbsent, target)

	case PassThrough:
		return ""

	default:
		return t.describeRevocation(target)
	}
}

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
