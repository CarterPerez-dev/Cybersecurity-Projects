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
		KeyUsage:              x509.KeyUsageDigitalSignature,
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

// buildResponders mints the two OCSP signers: one the CA delegated by giving it
// the OCSPSigning extended key usage, and one it never signed at all.
//
// The undelegated signer is what OCSPWrongSigner answers with. It is a
// self-signed certificate rather than one under the rogue CA, so that a client
// which happens to trust the rogue root (because CASwap ran earlier in the same
// session) still cannot be fooled by it.
func (a *Authority) buildResponders(from, until time.Time) error {
	delegated, err := caTemplate(nameResponder, from, until)
	if err != nil {
		return err
	}

	delegated.IsCA = false
	delegated.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}

	delegatedKey, err := newKey(StrongBits)
	if err != nil {
		return err
	}

	if a.responder, err = issue(
		delegated,
		a.inter,
		delegatedKey,
	); err != nil {
		return err
	}

	rogue, err := caTemplate(nameUndelegated, from, until)
	if err != nil {
		return err
	}

	rogueKey, err := newKey(StrongBits)
	if err != nil {
		return err
	}

	a.undelegated, err = issue(rogue, nil, rogueKey)

	return err
}
