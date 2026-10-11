// ©AngelaMos | 2026
// issuers.go

package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

// The purpose-built issuers. Each one is a CA that is wrong in exactly one
// structural way, minted once at construction.
//
// They are separate certificates rather than mutations of the honest
// intermediate because the fault is IN THE ISSUER for all four: a leaf cannot
// express "my CA is constrained against my name" or "my CA is not a CA" by
// anything it carries itself.

// buildConstrained is a CA carrying PermittedDNSDomains. A leaf it signs for
// any other name trips InvalidReason 2, CANotAuthorizedForThisName. The
// fail-open this catches is a constrained corporate sub-CA that a verifier lets
// issue for anything.
func (a *Authority) buildConstrained(from, until time.Time) error {
	template, err := caTemplate(nameConstrained, from, until)
	if err != nil {
		return err
	}

	template.PermittedDNSDomains = []string{constrainedDomain}
	template.PermittedDNSDomainsCritical = true

	key, err := newKey(StrongBits)
	if err != nil {
		return err
	}

	a.constrained, err = issue(template, a.root, key)

	return err
}

// buildEKULimited is a CA authorised for client authentication only. Go checks
// extended key usage NESTED DOWN THE CHAIN, so a perfectly ordinary serverAuth
// leaf under this CA trips InvalidReason 9,
// CANotAuthorizedForExtKeyUsage. The leaf itself is blameless, which is what
// makes this distinct from the leaf-level EKU fault.
func (a *Authority) buildEKULimited(from, until time.Time) error {
	template, err := caTemplate(nameEKULimited, from, until)
	if err != nil {
		return err
	}

	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	key, err := newKey(StrongBits)
	if err != nil {
		return err
	}

	a.ekuLimited, err = issue(template, a.root, key)

	return err
}

// buildNotACA is a certificate with basic constraints saying it is NOT a CA,
// which khaos then signs a leaf with anyway. Go reports this as
// UnknownAuthorityError wrapping ConstraintViolationError, so a caller that
// only reads the outer error sees "unknown authority" and learns nothing about
// the real defect.
func (a *Authority) buildNotACA(from, until time.Time) error {
	number, err := serial()
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber:          number,
		Subject:               pkix.Name{CommonName: nameNotACA},
		NotBefore:             from,
		NotAfter:              until,
		IsCA:                  false,
		BasicConstraintsValid: true,

		// CRLSign despite IsCA being false, because this certificate is still
		// the issuer of the leaf it signs and therefore still the thing that
		// signs the CRL covering it. CreateRevocationList refuses an issuer
		// without the bit, and without it the CRL endpoint answered 500 and the
		// client refused for khaos's reason instead of the fault's.
		//
		// The fault is unaffected: IsCA is still false, which is the defect.
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,

		// Set BY HAND, because Go computes a SubjectKeyId automatically only
		// while creating a CA certificate and this one is deliberately not a
		// CA. CreateRevocationList reads the identifier from the parsed issuer
		// and refuses an issuer without one, so a CRL for this chain could not
		// be minted at all and the endpoint answered 500.
		SubjectKeyId: []byte(nameNotACA),
	}

	key, err := newKey(StrongBits)
	if err != nil {
		return err
	}

	a.notACA, err = issue(template, a.root, key)

	return err
}

// buildDeepInter sits one level below an intermediate whose MaxPathLen is zero,
// so a leaf under it exceeds the path length the CA above permits and trips
// InvalidReason 3, TooManyIntermediates.
//
// The pathLen-0 CA is minted here too rather than reusing the honest
// intermediate, because setting MaxPathLen on the honest one would constrain
// every other trap in the family.
func (a *Authority) buildDeepInter(from, until time.Time) error {
	capped, err := caTemplate(nameInter, from, until)
	if err != nil {
		return err
	}

	capped.MaxPathLen = 0
	capped.MaxPathLenZero = true

	cappedKey, err := newKey(StrongBits)
	if err != nil {
		return err
	}

	if a.deepCapped, err = issue(capped, a.root, cappedKey); err != nil {
		return err
	}

	template, err := caTemplate(nameDeepInter, from, until)
	if err != nil {
		return err
	}

	key, err := newKey(StrongBits)
	if err != nil {
		return err
	}

	a.deepInter, err = issue(template, a.deepCapped, key)

	return err
}

// buildResponders mints the ONE OCSP signer khaos needs to hold: a certificate
// the CA never issued.
//
// There is no delegated responder here any more. Every honest response is
// signed by the chain's own issuer, acting as its own responder, which RFC 6960
// section 2.6 permits and which is the only arrangement that is consistent with
// EVERY chain this authority serves. A single delegated responder cannot be,
// because seven traps serve a chain under a different CA entirely, and the
// matrix caught six of them being refused for khaos's own mismatch.
//
// The undelegated signer stays, because OCSPWrongSigner is the fault that
// exercises delegation from the other side. It is self-signed rather than
// issued by the rogue hierarchy, so a client that happens to trust the rogue
// root -- because CASwap ran earlier in the same session -- still cannot be
// fooled by it.
func (a *Authority) buildResponders(from, until time.Time) error {
	rogue, err := caTemplate(nameUndelegated, from, until)
	if err != nil {
		return err
	}

	rogue.IsCA = false
	rogue.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}

	rogueKey, err := newKey(StrongBits)
	if err != nil {
		return err
	}

	a.undelegated, err = issue(rogue, nil, rogueKey)

	return err
}
