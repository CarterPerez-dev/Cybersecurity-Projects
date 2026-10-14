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

	observedClientExpired = "khaos requires mutual TLS and the client identity it issued expired %s ago"
	observedNoIdentity    = "khaos requires mutual TLS and is issuing no client identity at all"
)

// Observe confirms khaos's own fault landed by reading back what the authority
// serves, never the trap record. Every branch asserts the served material
// carries the defect, and the branches whose fault is a DEVIATION also require
// an honest chain not to. An unarmed authority confirms nothing either way: it
// builds no trapped material, so the defect assertion alone fails on it.
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

	case ClientCertExpired, ClientCertAbsent:
		return a.observeMutual(armed)

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
		// The leaf has to be BLAMELESS, or this is LeafExpired renamed.
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
		// Kinds from the other groups reach their own observer.
	}

	return "", false, nil
}

// Five of these produce byte-identical client errors, so what khaos knows it
// SERVED is the only thing that can tell them apart.
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
		// Kinds from the other groups reach their own observer.
	}

	return "", false, nil
}

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
		// The length check is load-bearing: an EMPTY ExtKeyUsage on a CA means
		// UNCONSTRAINED, so serverAuth alone would confirm against the control.
		if len(chain.Issuer.ExtKeyUsage) > 0 &&
			!serverAuth(chain.Issuer.ExtKeyUsage) &&
			serverAuth(chain.Leaf.ExtKeyUsage) {
			return sprintf(
				observedEKUAbove,
				chain.Issuer.ExtKeyUsage,
			), true, nil
		}

	default:
		// Kinds from the other groups reach their own observer.
	}

	return "", false, nil
}

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
		if a.TrustedRoot().Equal(a.rogueRoot.cert) {
			return sprintf(
				observedCASwap,
				a.rogueRoot.cert.Subject.CommonName,
			), true, nil
		}

	default:
		// Kinds from the other groups reach their own observer.
	}

	return "", false, nil
}

func (a *Authority) observeStaple(
	trap Trap,
	chain, honest *Chain,
) (string, bool, error) {
	switch trap.Kind {
	case StapleGarbage:
		if len(chain.Staple) == 0 {
			return "", false, nil
		}

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
		// The CRL pointer has to SURVIVE, or this is a revocation outage.
		if len(chain.Leaf.OCSPServer) == 0 &&
			len(chain.Leaf.CRLDistributionPoints) > 0 {
			return sprintf(
				observedNoOCSP,
				chain.Leaf.CRLDistributionPoints[0],
			), true, nil
		}

	default:
		// Kinds from the other groups reach their own observer.
	}

	return "", false, nil
}

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
