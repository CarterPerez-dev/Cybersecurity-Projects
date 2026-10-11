// ©AngelaMos | 2026
// defect.go

package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

// build assembles the chain for one trap. Every trap starts from the HONEST
// leaf template and corrupts exactly one property of it, which is the same
// discipline the token family uses and for the same reason: a certificate that
// is wrong twice trips two checks and isolates neither.
//
// The groups are the ones research 04 uses, and each is confirmed differently.
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

	// EVERY chain staples, not just the stapling traps. A well-configured
	// server staples, so the honest chain has to as well: if only the stapling
	// faults produced one, then StapleAbsent would serve exactly what the
	// baseline serves and the fault would be inert. The control test for this
	// file is what caught that.
	return a.staple(trap, chain, now)
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

// honest is the control every other chain is compared against: a correctly
// signed, in-date leaf under the trusted intermediate, naming both revocation
// endpoints so that a target which WANTS to check revocation can.
//
// Carrying the pointers on the honest chain matters. If only the revocation
// traps named a responder, then "the target queried OCSP" would be true only
// when khaos was already attacking it, and the baseline could never establish
// that the target checks revocation at all.
func (a *Authority) honest(host string, now time.Time) (*Chain, error) {
	template, err := a.leaf(host, now, DefaultLeafDays)
	if err != nil {
		return nil, err
	}

	return a.assemble(template, a.inter, a.root.cert, StrongBits, true)
}

// leaf is the honest template plus the revocation pointers, which depend on the
// configured base URL rather than on wherever khaos happens to be listening.
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

// assemble mints the leaf and wraps it with what the handshake and revocation
// both need. presentChain says whether the intermediate is admitted to the
// handshake, which is the entire MissingIntermediate fault.
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

// buildValidity moves a NotBefore or NotAfter. Both leaf faults come back as
// InvalidReason 1 with no separate not-yet-valid reason, so the only thing
// distinguishing them is the Detail wording, and the experiments assert on that
// rather than on the reason alone.
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
		// Internally consistent: the certificate is expired and nothing else.
		// Its NotBefore moves with its NotAfter so it was never also
		// not-yet-valid, which would trip the same reason for the other cause.
		template.NotBefore = now.Add(-window - DefaultWindow)
		template.NotAfter = now.Add(-window)

	case LeafNotYetValid:
		template.NotBefore = now.Add(window)
		template.NotAfter = now.Add(window).AddDate(0, 0, DefaultLeafDays)

	default:
		// Unreachable: build routes only the validity group here.
	}

	return a.assemble(template, a.inter, a.root.cert, StrongBits, true)
}

// underExpiredCA mints an in-date leaf under an intermediate that has expired.
// The leaf is deliberately blameless: monitoring that watches leaf expiry only
// sees nothing wrong, which is the fail-open this catches.
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

// buildIdentity corrupts who the certificate is FOR. All three are
// HostnameError, which carries no reason code, so the experiments assert on the
// error type and on which name the certificate actually carries.
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
		// No SAN extension at all, with the host named only in the legacy
		// CommonName. Go removed the CommonName fallback outright, so this
		// produces a DIFFERENT message from a plain mismatch: it names the
		// legacy field, which is the teaching point.
		template.DNSNames = nil
		template.Subject = pkix.Name{CommonName: host}

	case NoIPSAN:
		// Named by DNS but carrying no IP SAN, so a client that dials by
		// address has nothing to match against. The fail-open is a service
		// dialled by pod IP with verification disabled because it is internal.
		template.DNSNames = []string{host}
		template.IPAddresses = nil

	default:
		// Unreachable: build routes only the identity group here.
	}

	return a.assemble(template, a.inter, a.root.cert, StrongBits, true)
}

// buildChainFault breaks the path from leaf to trusted root. Three of these
// produce a BYTE-IDENTICAL client error and the experiments exist to tell them
// apart by what khaos knows it served, never by the string.
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
		// Signed by khaos's OTHER complete hierarchy. The chain is internally
		// valid and simply anchors somewhere the target does not trust.
		return a.assemble(
			template,
			a.rogueInter,
			a.rogueRoot.cert,
			StrongBits,
			true,
		)

	case MissingIntermediate:
		// A perfectly good chain with the intermediate withheld from the
		// handshake. Works in a browser that chases AIA, fails in Go.
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
		// Unreachable: build routes only the chain group here.
		return a.honest(host, now)
	}
}

// overDeep serves a leaf two intermediates below the root, under a CA whose
// MaxPathLen is zero.
//
// BOTH intermediates are presented. A handshake carrying only the lower one
// leaves the client unable to reach the root at all, and Go then reports an
// unknown authority rather than the path-length violation: the fault would
// still fail the connection, for a reason khaos did not inject and could not
// attribute. The differential caught exactly that in the first draft.
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

// selfSigned signs the leaf with its own key, which needs the CA bits on the
// template because Go refuses to let a non-CA certificate sign anything,
// including itself.
func (a *Authority) selfSigned(
	template *x509.Certificate,
) (*Chain, error) {
	// CertSign because Go refuses to let a non-CA certificate sign anything,
	// including itself. CRLSign because this leaf is its OWN issuer, so it is
	// also the thing that has to sign the CRL covering it, and
	// CreateRevocationList refuses an issuer without that bit.
	//
	// Omitting CRLSign made the CRL endpoint answer 500 for this trap, which
	// reached the client as "no usable revocation answer was obtained" -- a
	// refusal caused by khaos rather than by the fault. The matrix caught it.
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

// buildAlgorithm corrupts how the certificate is signed or what it is permitted
// to be used for. Two of the three surface as an authority failure unless the
// caller unwraps the error, which is itself the finding.
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
		// Measured on go1.26.5: CreateCertificate emits this without
		// complaint and Verify refuses it, wrapping InsecureAlgorithmError
		// inside UnknownAuthorityError.
		template.SignatureAlgorithm = x509.SHA1WithRSA

	case EKUClientAuthOnly:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	case EKUConstrainedIntermediate:
		// The LEAF is blameless here. The constraint is on the CA above it,
		// which is what separates this from the leaf-level EKU fault.
		return a.assemble(
			template,
			a.ekuLimited,
			a.root.cert,
			StrongBits,
			true,
		)

	default:
		// Unreachable: build routes only the algorithm group here.
	}

	return a.assemble(template, a.inter, a.root.cert, StrongBits, true)
}

// buildPolicy mints the certificates Go ACCEPTS. Verify returns nil for all
// three, so they do not test x509 at all -- they test whether the target
// imposed a floor of its own, and an acceptance here is not proof of a skipped
// check because there was no check to skip.
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
		// Verify enforces EXTENDED key usage, nested down the chain, and does
		// not look at the basic KeyUsage bits on a leaf at all. A leaf without
		// digitalSignature is unusable for TLS per RFC 5280 and Go will not say
		// a word about it.
		template.KeyUsage = x509.KeyUsageCRLSign
	}

	// bits, not StrongBits. Passing the constant here is what the first draft
	// did, and it made WeakKey mint a 2048-bit key: the trap armed, reported
	// success, and served a certificate with nothing wrong with it.
	return a.assemble(template, a.inter, a.root.cert, bits, true)
}

// buildCASwap serves a chain that is VALID under a root khaos controls, having
// made that root the one the target trusts. Nothing in the client can detect
// it, which is the point: the only defences are pinning and certificate
// transparency, and neither is in crypto/x509.
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
