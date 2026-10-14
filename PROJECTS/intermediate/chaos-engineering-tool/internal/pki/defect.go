// ©AngelaMos | 2026
// defect.go

package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Every trap starts from the HONEST leaf template and corrupts exactly one
// property of it, because a certificate wrong twice isolates neither check.
func (a *Authority) build(trap Trap) (*Chain, error) {
	now := a.clock()

	host := trap.Host
	if host == "" {
		host = a.host
	}

	chain, err := a.chainFor(trap, host, now)
	if err != nil {
		return nil, err
	}

	// The BASELINE staples, or StapleAbsent would serve exactly what the
	// baseline serves and the fault would be inert. staple decides per kind,
	// and four of them deliberately staple nothing.
	if chain, err = a.staple(trap, chain, now); err != nil {
		return nil, err
	}

	return a.publish(trap, chain, now)
}

func (a *Authority) publish(
	trap Trap,
	chain *Chain,
	now time.Time,
) (*Chain, error) {
	chain.crlOut = trap.Kind == CRLUnreachable
	chain.ocspOut = trap.Kind == OCSPUnreachable

	list, err := a.CRLFor(trap, chain, now)
	if err != nil {
		return nil, err
	}

	chain.crl = list

	if trap.Kind == OCSPTryLater {
		chain.ocsp = ocsp.TryLaterErrorResponse

		return chain, nil
	}

	answer, err := a.ocspFor(trap, chain, now)
	if err != nil {
		return nil, err
	}

	chain.ocsp = answer

	return chain, nil
}

func (a *Authority) chainFor(
	trap Trap,
	host string,
	now time.Time,
) (*Chain, error) {
	switch trap.Kind {
	case LeafExpired, LeafNotYetValid, IntermediateExpired:
		return a.buildValidity(trap, host, now)

	case WrongSAN, CommonNameOnly, NoIPSAN:
		return a.buildIdentity(trap, host, now)

	case SelfSigned, UntrustedCA, MissingIntermediate, IssuerNotCA,
		NameConstraintViolation, PathLengthExceeded:
		return a.buildChainFault(trap, host, now)

	case SHA1Signature, EKUClientAuthOnly, EKUConstrainedIntermediate:
		return a.buildAlgorithm(trap, host, now)

	case WeakKey, ExcessiveLifetime, KeyUsageWithoutDigitalSignature:
		return a.buildPolicy(trap, host, now)

	case RevokedViaCRL, StaleCRL, CRLUnreachable, OCSPRevoked, OCSPUnknown,
		OCSPTryLater, OCSPUnreachable, OCSPStale, OCSPWrongSerial,
		OCSPWrongSigner, NoOCSPServer, StapleGarbage, StapleAbsent:
		return a.buildRevocation(trap, host, now)

	case CASwap:
		return a.buildCASwap(host, now)

	case PassThrough:
		return a.honest(host, now)

	default:
		return a.honest(host, now)
	}
}

func (a *Authority) honest(host string, now time.Time) (*Chain, error) {
	template, err := a.leaf(host, now, DefaultLeafDays)
	if err != nil {
		return nil, err
	}

	return a.assemble(template, a.inter, a.root.cert, StrongBits, true)
}

// The honest leaf names both revocation endpoints too, or "the target queried
// OCSP" would be true only when khaos was already attacking it.
func (a *Authority) leaf(
	host string,
	now time.Time,
	days int,
) (*x509.Certificate, error) {
	template, err := leafTemplate(host, now, days)
	if err != nil {
		return nil, err
	}

	if base := a.Base(); base != "" {
		template.OCSPServer = []string{base + RouteOCSP}
		template.CRLDistributionPoints = []string{base + RouteCRL}
	}

	return template, nil
}

// presentChain is the entire MissingIntermediate fault.
func (a *Authority) assemble(
	template *x509.Certificate,
	issuer *pair,
	root *x509.Certificate,
	bits int,
	presentChain bool,
) (*Chain, error) {
	key, err := newKey(bits)
	if err != nil {
		return nil, err
	}

	leaf, err := issue(template, issuer, key)
	if err != nil {
		return nil, err
	}

	chain := &Chain{
		Leaf:      leaf.cert,
		leafDER:   leaf.der,
		leafKey:   key,
		Issuer:    issuer.cert,
		issuerKey: issuer.key,
		Root:      root,
	}

	if presentChain && issuer != a.root && issuer.cert != root {
		chain.presented = [][]byte{issuer.der}
	}

	return chain, nil
}

func (a *Authority) buildValidity(
	trap Trap,
	host string,
	now time.Time,
) (*Chain, error) {
	window := trap.window()

	if trap.Kind == IntermediateExpired {
		return a.underExpiredCA(host, now, window)
	}

	template, err := a.leaf(host, now, DefaultLeafDays)
	if err != nil {
		return nil, err
	}

	switch trap.Kind {
	case LeafExpired:
		// NotBefore moves with NotAfter, so it is expired and nothing else.
		template.NotBefore = now.Add(-window - DefaultWindow)
		template.NotAfter = now.Add(-window)

	case LeafNotYetValid:
		template.NotBefore = now.Add(window)
		template.NotAfter = now.Add(window).AddDate(0, 0, DefaultLeafDays)

	default:
		// Every other kind leaves the validity window honest.
	}

	return a.assemble(template, a.inter, a.root.cert, StrongBits, true)
}

// The leaf is deliberately blameless, so leaf-expiry monitoring sees nothing.
func (a *Authority) underExpiredCA(
	host string,
	now time.Time,
	window time.Duration,
) (*Chain, error) {
	template, err := caTemplate(
		nameInter,
		now.Add(-window-DefaultWindow),
		now.Add(-window),
	)
	if err != nil {
		return nil, err
	}

	key, err := newKey(StrongBits)
	if err != nil {
		return nil, err
	}

	expired, err := issue(template, a.root, key)
	if err != nil {
		return nil, err
	}

	leaf, err := a.leaf(host, now, DefaultLeafDays)
	if err != nil {
		return nil, err
	}

	return a.assemble(leaf, expired, a.root.cert, StrongBits, true)
}

func (a *Authority) buildIdentity(
	trap Trap,
	host string,
	now time.Time,
) (*Chain, error) {
	template, err := a.leaf(host, now, DefaultLeafDays)
	if err != nil {
		return nil, err
	}

	switch trap.Kind {
	case WrongSAN:
		template.DNSNames = []string{foreignHost}
		template.Subject = pkix.Name{CommonName: foreignHost}

	case CommonNameOnly:
		// Go removed the CommonName fallback, so this is not a plain mismatch.
		template.DNSNames = nil
		template.Subject = pkix.Name{CommonName: host}

	case NoIPSAN:
		template.DNSNames = []string{host}
		template.IPAddresses = nil

	default:
		// Every other kind leaves the identity fields honest.
	}

	return a.assemble(template, a.inter, a.root.cert, StrongBits, true)
}

func (a *Authority) buildChainFault(
	trap Trap,
	host string,
	now time.Time,
) (*Chain, error) {
	template, err := a.leaf(host, now, DefaultLeafDays)
	if err != nil {
		return nil, err
	}

	switch trap.Kind {
	case SelfSigned:
		return a.selfSigned(template)

	case UntrustedCA:
		return a.assemble(
			template,
			a.rogueInter,
			a.rogueRoot.cert,
			StrongBits,
			true,
		)

	case MissingIntermediate:
		return a.assemble(template, a.inter, a.root.cert, StrongBits, false)

	case IssuerNotCA:
		return a.assemble(template, a.notACA, a.root.cert, StrongBits, true)

	case NameConstraintViolation:
		return a.assemble(
			template,
			a.constrained,
			a.root.cert,
			StrongBits,
			true,
		)

	case PathLengthExceeded:
		return a.overDeep(template)

	default:
		return a.honest(host, now)
	}
}

// BOTH intermediates are presented. With only the lower one the client cannot
// reach the root, and Go reports an unknown authority instead.
func (a *Authority) overDeep(
	template *x509.Certificate,
) (*Chain, error) {
	chain, err := a.assemble(
		template,
		a.deepInter,
		a.root.cert,
		StrongBits,
		true,
	)
	if err != nil {
		return nil, err
	}

	chain.presented = append(chain.presented, a.deepCapped.der)

	return chain, nil
}

func (a *Authority) selfSigned(
	template *x509.Certificate,
) (*Chain, error) {
	// CertSign because Go refuses to let a non-CA sign anything, itself
	// included. CRLSign because this leaf is its own issuer and signs its CRL.
	template.IsCA = true
	template.BasicConstraintsValid = true
	template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	key, err := newKey(StrongBits)
	if err != nil {
		return nil, err
	}

	leaf, err := issue(template, nil, key)
	if err != nil {
		return nil, err
	}

	return &Chain{
		Leaf:      leaf.cert,
		leafDER:   leaf.der,
		leafKey:   key,
		Issuer:    leaf.cert,
		issuerKey: key,
		Root:      a.root.cert,
	}, nil
}

func (a *Authority) buildAlgorithm(
	trap Trap,
	host string,
	now time.Time,
) (*Chain, error) {
	template, err := a.leaf(host, now, DefaultLeafDays)
	if err != nil {
		return nil, err
	}

	switch trap.Kind {
	case SHA1Signature:
		template.SignatureAlgorithm = x509.SHA1WithRSA

	case EKUClientAuthOnly:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	case EKUConstrainedIntermediate:
		// The LEAF is blameless; the constraint is on the CA above it.
		return a.assemble(
			template,
			a.ekuLimited,
			a.root.cert,
			StrongBits,
			true,
		)

	default:
		// Every other kind leaves the signature algorithm honest.
	}

	return a.assemble(template, a.inter, a.root.cert, StrongBits, true)
}

func (a *Authority) buildPolicy(
	trap Trap,
	host string,
	now time.Time,
) (*Chain, error) {
	days := DefaultLeafDays
	bits := StrongBits

	if trap.Kind == ExcessiveLifetime {
		days = trap.days()
	}

	if trap.Kind == WeakKey {
		bits = trap.bits()
	}

	template, err := a.leaf(host, now, days)
	if err != nil {
		return nil, err
	}

	if trap.Kind == KeyUsageWithoutDigitalSignature {
		// Verify enforces EXTENDED key usage down the chain and never looks at
		// the basic KeyUsage bits RFC 5280 requires of a TLS leaf.
		template.KeyUsage = x509.KeyUsageCRLSign
	}

	// bits, not StrongBits, or WeakKey arms and serves a strong key.
	return a.assemble(template, a.inter, a.root.cert, bits, true)
}

func (a *Authority) buildCASwap(
	host string,
	now time.Time,
) (*Chain, error) {
	template, err := a.leaf(host, now, DefaultLeafDays)
	if err != nil {
		return nil, err
	}

	return a.assemble(
		template,
		a.rogueInter,
		a.rogueRoot.cert,
		StrongBits,
		true,
	)
}
