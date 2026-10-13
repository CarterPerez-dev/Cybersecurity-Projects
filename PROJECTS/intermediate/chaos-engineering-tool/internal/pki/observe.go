// ©AngelaMos | 2026
// observe.go

package pki

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	observeTimeout = 5 * time.Second

	errWrongArmed = "%w: this authority has %q armed, not %q"
	errNoChain    = "%w: nothing is armed, so there is no chain to read back"
	errNoControl  = "%w: khaos could not mint an honest chain to compare against (%v)"
	errAuthDown   = "%w: khaos's own authority did not answer its health route (%v)"

	observedExpired     = "the served leaf expired %s ago, where an honest one from the same authority is valid until %s"
	observedNotYet      = "the served leaf is not valid for another %s"
	observedInterOld    = "the served leaf is in date and the intermediate above it expired %s ago"
	observedWrongSAN    = "the served leaf names %v, not %q"
	observedNoSAN       = "the served leaf carries no SAN extension at all, naming %q only in the legacy CommonName"
	observedNoIPSAN     = "the served leaf carries no IP SANs"
	observedSelfSigned  = "the served leaf is its own issuer"
	observedForeignCA   = "the served chain anchors on %q, which is not the root the target trusts"
	observedNoInter     = "the handshake carries %d intermediates where an honest one carries %d"
	observedNotACA      = "the leaf's issuer %q has basic constraints saying it is not a CA"
	observedConstrained = "the leaf's issuer is constrained to %v and the leaf names %q"
	observedDeep        = "the handshake carries %d intermediates under a CA whose path length permits %d"
	observedSHA1        = "the served leaf is signed with %v"
	observedEKULeaf     = "the served leaf permits %v, not server authentication"
	observedEKUAbove    = "the leaf's issuer permits %v, which does not include server authentication"
	observedWeakKey     = "the served leaf carries a %d-bit key where an honest one carries %d"
	observedLifetime    = "the served leaf is valid for %d days, where the cap is %d"
	observedKeyUsage    = "the served leaf's KeyUsage omits digitalSignature"
	observedCASwap      = "the root the target trusts is now %q, which khaos controls"

	observedRevoked   = "khaos's CRL lists the served leaf's serial %s as revoked"
	observedStale     = "khaos's %s closed its freshness window %s ago"
	observedUnreached = "khaos's %s refuses connections while its health route still answers %d"
	observedOCSPSays  = "khaos's responder answers status %d for the served leaf"
	observedOCSPOther = "khaos's responder answers about serial %s, not the served leaf's %s"
	observedBadSigner = "khaos's responder signs with a certificate its CA never issued"
	observedNoOCSP    = "the served leaf names no OCSP responder, and still names a CRL at %s"
	observedStapleBad = "the handshake staples %d bytes that are not an OCSP response"
	observedNoStaple  = "the handshake carries no stapled response, where an honest one carries %d bytes"
)

// Observe confirms khaos's own fault landed, by reading back what the authority
// actually serves and comparing it against an HONEST chain from the same
// authority.
//
// Every branch asserts two things, not one: that the served material carries
// the defect AND that the control does not. An authority that was never armed
// must not be able to confirm a trap, which is what the inert flag exists to
// prove, and a one-sided assertion would let it.
//
// It reads the SERVED artefacts rather than the flag that was set. A flag
// records which branch khaos chose; it says nothing about what a target would
// receive, and an authority whose minting broke would happily confirm a fault
// it is not producing.
func (a *Authority) Observe(
	ctx context.Context,
	expected Kind,
) (string, bool, error) {
	armed := a.Trap()

	if armed.Kind != expected {
		return "", false, fmt.Errorf(
			errWrongArmed,
			ErrTrapNotObserved,
			armed.Kind,
			expected,
		)
	}

	chain, err := a.Served()
	if err != nil {
		return "", false, fmt.Errorf(errNoChain, ErrTrapNotObserved)
	}

	honest, err := a.build(Trap{Kind: PassThrough, Host: a.host})
	if err != nil {
		return "", false, fmt.Errorf(errNoControl, ErrTrapNotObserved, err)
	}

	switch expected {
	case LeafExpired, LeafNotYetValid, IntermediateExpired, WrongSAN,
		CommonNameOnly, NoIPSAN:
		return a.observeSubject(armed, chain, honest)

	case SelfSigned, UntrustedCA, MissingIntermediate, IssuerNotCA,
		NameConstraintViolation, PathLengthExceeded, SHA1Signature,
		EKUClientAuthOnly, EKUConstrainedIntermediate:
		return a.observeChainFault(armed, chain, honest)

	case WeakKey, ExcessiveLifetime, KeyUsageWithoutDigitalSignature,
		CASwap:
		return a.observePolicy(armed, chain, honest)

	case StapleGarbage, StapleAbsent, NoOCSPServer:
		return a.observeStaple(armed, chain, honest)

	case RevokedViaCRL, StaleCRL, CRLUnreachable, OCSPRevoked, OCSPUnknown,
		OCSPTryLater, OCSPUnreachable, OCSPStale, OCSPWrongSerial,
		OCSPWrongSigner:
		return a.observeRevocation(ctx, armed, chain)

	case PassThrough:
		return "", false, nil

	default:
		return "", false, nil
	}
}

// observeSubject confirms the faults in when the certificate is valid and who
// it is for, all of which are visible in the served leaf itself.
func (a *Authority) observeSubject(
	trap Trap,
	chain, honest *Chain,
) (string, bool, error) {
	now := a.clock()

	switch trap.Kind {
	case LeafExpired:
		if chain.Leaf.NotAfter.Before(now) &&
			honest.Leaf.NotAfter.After(now) {
			return sprintf(
				observedExpired,
				now.Sub(chain.Leaf.NotAfter).Round(time.Second),
				honest.Leaf.NotAfter.Format(time.RFC3339),
			), true, nil
		}

	case LeafNotYetValid:
		if chain.Leaf.NotBefore.After(now) &&
			!honest.Leaf.NotBefore.After(now) {
			return sprintf(
				observedNotYet,
				chain.Leaf.NotBefore.Sub(now).Round(time.Second),
			), true, nil
		}

	case IntermediateExpired:
		// The leaf has to be BLAMELESS, or this is just LeafExpired wearing a
		// different name and monitoring that watches leaf expiry would catch it.
		if chain.Issuer.NotAfter.Before(now) &&
			chain.Leaf.NotAfter.After(now) {
			return sprintf(
				observedInterOld,
				now.Sub(chain.Issuer.NotAfter).Round(time.Second),
			), true, nil
		}

	case WrongSAN:
		if len(chain.Leaf.DNSNames) > 0 &&
			!names(chain.Leaf).has(a.host) &&
			names(honest.Leaf).has(a.host) {
			return sprintf(
				observedWrongSAN,
				chain.Leaf.DNSNames,
				a.host,
			), true, nil
		}

	case CommonNameOnly:
		if len(chain.Leaf.DNSNames) == 0 &&
			len(honest.Leaf.DNSNames) > 0 &&
			chain.Leaf.Subject.CommonName == a.host {
			return sprintf(observedNoSAN, a.host), true, nil
		}

	case NoIPSAN:
		if len(chain.Leaf.IPAddresses) == 0 &&
			len(chain.Leaf.DNSNames) > 0 {
			return observedNoIPSAN, true, nil
		}

	default:
		// Unreachable: Observe routes only the subject group here.
	}

	return "", false, nil
}

// observeChainFault confirms the faults in the path from leaf to trusted root.
// Five of these produce byte-identical client errors in two groups, so what
// khaos knows it SERVED is the only thing that can tell them apart, and that is
// precisely what these branches record.
func (a *Authority) observeChainFault(
	trap Trap,
	chain, honest *Chain,
) (string, bool, error) {
	switch trap.Kind {
	case SelfSigned:
		if chain.Issuer.Equal(chain.Leaf) && !honest.Issuer.Equal(honest.Leaf) {
			return observedSelfSigned, true, nil
		}

	case UntrustedCA:
		if !chain.Root.Equal(a.root.cert) {
			return sprintf(
				observedForeignCA,
				chain.Root.Subject.CommonName,
			), true, nil
		}

	case MissingIntermediate:
		if chain.Presented() < honest.Presented() {
			return sprintf(
				observedNoInter,
				chain.Presented(),
				honest.Presented(),
			), true, nil
		}

	case IssuerNotCA:
		if chain.Issuer.BasicConstraintsValid && !chain.Issuer.IsCA {
			return sprintf(
				observedNotACA,
				chain.Issuer.Subject.CommonName,
			), true, nil
		}

	case NameConstraintViolation:
		if len(chain.Issuer.PermittedDNSDomains) > 0 &&
			!permits(chain.Issuer, a.host) {
			return sprintf(
				observedConstrained,
				chain.Issuer.PermittedDNSDomains,
				a.host,
			), true, nil
		}

	case PathLengthExceeded:
		if chain.Presented() > honest.Presented() {
			return sprintf(
				observedDeep,
				chain.Presented(),
				a.deepCapped.cert.MaxPathLen,
			), true, nil
		}

	case SHA1Signature, EKUClientAuthOnly, EKUConstrainedIntermediate:
		return a.observeSigning(trap, chain, honest)

	default:
		// Unreachable: Observe routes only the chain group here.
	}

	return "", false, nil
}

// observeSigning confirms the three faults in HOW the certificate is signed or
// what it may be used for. They sit apart from the path faults because none of
// them breaks the chain: the path is intact and the signature or the usage is
// what a correct client rejects.
func (a *Authority) observeSigning(
	trap Trap,
	chain, honest *Chain,
) (string, bool, error) {
	switch trap.Kind {
	case SHA1Signature:
		if chain.Leaf.SignatureAlgorithm == x509.SHA1WithRSA &&
			honest.Leaf.SignatureAlgorithm != x509.SHA1WithRSA {
			return sprintf(
				observedSHA1,
				chain.Leaf.SignatureAlgorithm,
			), true, nil
		}

	case EKUClientAuthOnly:
		if !serverAuth(chain.Leaf.ExtKeyUsage) &&
			serverAuth(honest.Leaf.ExtKeyUsage) {
			return sprintf(
				observedEKULeaf,
				chain.Leaf.ExtKeyUsage,
			), true, nil
		}

	case EKUConstrainedIntermediate:
		// The LEAF is blameless, which is what separates this from the leaf
		// level fault above. Both come back as Reason 4 and are otherwise
		// indistinguishable to the target.
		//
		// The length check is load-bearing. An EMPTY ExtKeyUsage on a CA means
		// UNCONSTRAINED, not "no server auth", so testing serverAuth alone
		// confirmed this trap against khaos's own honest intermediate, which
		// enumerates nothing. The inert control caught it.
		if len(chain.Issuer.ExtKeyUsage) > 0 &&
			!serverAuth(chain.Issuer.ExtKeyUsage) &&
			serverAuth(chain.Leaf.ExtKeyUsage) {
			return sprintf(
				observedEKUAbove,
				chain.Issuer.ExtKeyUsage,
			), true, nil
		}

	default:
		// Unreachable: observeChainFault routes only the signing group here.
	}

	return "", false, nil
}

// observePolicy confirms the faults crypto/x509 ACCEPTS. There is no refusal to
// read back, so the only evidence is the served material differing from the
// control, which makes the control load-bearing rather than decorative here.
func (a *Authority) observePolicy(
	trap Trap,
	chain, honest *Chain,
) (string, bool, error) {
	switch trap.Kind {
	case WeakKey:
		served, ok := modulus(chain.Leaf)
		control, controlOK := modulus(honest.Leaf)

		if ok && controlOK && served < control {
			return sprintf(observedWeakKey, served, control), true, nil
		}

	case ExcessiveLifetime:
		days := int(chain.Leaf.NotAfter.Sub(chain.Leaf.NotBefore).Hours() / 24)
		if days > LifetimeCapDays {
			return sprintf(observedLifetime, days, LifetimeCapDays), true, nil
		}

	case KeyUsageWithoutDigitalSignature:
		if chain.Leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 &&
			honest.Leaf.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
			return observedKeyUsage, true, nil
		}

	case CASwap:
		// The confirmation is that the TRUSTED ROOT moved, not that the chain is
		// odd. The chain is deliberately impeccable under the new anchor, which
		// is the entire point: nothing in a client can detect this.
		if a.TrustedRoot().Equal(a.rogueRoot.cert) {
			return sprintf(
				observedCASwap,
				a.rogueRoot.cert.Subject.CommonName,
			), true, nil
		}

	default:
		// Unreachable: Observe routes only the policy group here.
	}

	return "", false, nil
}

// observeStaple confirms the three faults that act on what the handshake
// carries rather than on what a responder says.
func (a *Authority) observeStaple(
	trap Trap,
	chain, honest *Chain,
) (string, bool, error) {
	switch trap.Kind {
	case StapleGarbage:
		if len(chain.Staple) == 0 {
			return "", false, nil
		}

		// The parse FAILING is the confirmation: the staple is garbage, which is
		// the fault. nilerr reads this as swallowing an error, and it is the
		// opposite -- the error is the evidence.
		if _, err := ocsp.ParseResponse(
			chain.Staple,
			chain.Issuer,
		); err != nil {
			//nolint:nilerr // the parse failure IS the observable
			return sprintf(observedStapleBad, len(chain.Staple)), true, nil
		}

	case StapleAbsent:
		if len(chain.Staple) == 0 && len(honest.Staple) > 0 {
			return sprintf(observedNoStaple, len(honest.Staple)), true, nil
		}

	case NoOCSPServer:
		// The CRL pointer has to SURVIVE, or this is a total revocation outage
		// rather than the end of OCSP that it models.
		if len(chain.Leaf.OCSPServer) == 0 &&
			len(chain.Leaf.CRLDistributionPoints) > 0 {
			return sprintf(
				observedNoOCSP,
				chain.Leaf.CRLDistributionPoints[0],
			), true, nil
		}

	default:
		// Unreachable: Observe routes only the stapling group here.
	}

	return "", false, nil
}

// names and permits are small readers over a certificate's identity, kept
// separate so the branches above read as assertions rather than as parsing.
type nameSet []string

func names(cert *x509.Certificate) nameSet {
	return cert.DNSNames
}

func (n nameSet) has(want string) bool {
	for _, each := range n {
		if each == want {
			return true
		}
	}

	return false
}

func permits(ca *x509.Certificate, host string) bool {
	for _, domain := range ca.PermittedDNSDomains {
		if domain == host {
			return true
		}
	}

	return false
}

func serverAuth(usages []x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageServerAuth ||
			usage == x509.ExtKeyUsageAny {
			return true
		}
	}

	return false
}

func modulus(cert *x509.Certificate) (int, bool) {
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return 0, false
	}

	return key.N.BitLen(), true
}

func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

// health is the control for both unreachable traps. Its whole job is to still
// answer while one endpoint refuses, because "khaos broke one endpoint" and
// "khaos fell over" are different claims and only the first is a fault.
func (a *Authority) health(ctx context.Context) (int, error) {
	base, err := a.Addr()
	if err != nil {
		return 0, err
	}

	status, err := a.probe(ctx, schemeHTTP+base+RouteHealth)
	if err != nil {
		return 0, fmt.Errorf(errAuthDown, ErrTrapNotObserved, err)
	}

	if status != http.StatusOK {
		return status, fmt.Errorf(
			errAuthDown,
			ErrTrapNotObserved,
			status,
		)
	}

	return status, nil
}
