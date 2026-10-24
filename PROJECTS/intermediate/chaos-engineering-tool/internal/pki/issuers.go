// ©AngelaMos | 2026
// issuers.go

package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

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

// Go checks EKU NESTED DOWN THE CHAIN, so a blameless serverAuth leaf under
// this client-auth-only CA is refused with Reason 4.
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

// Reported as UnknownAuthorityError wrapping ConstraintViolationError.
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

		// CRLSign despite IsCA false: it still signs its own leaf's CRL.
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,

		// Set BY HAND: Go computes a SubjectKeyId only while creating a CA, and
		// CreateRevocationList refuses an issuer without one.
		SubjectKeyId: []byte(nameNotACA),
	}

	key, err := newKey(StrongBits)
	if err != nil {
		return err
	}

	a.notACA, err = issue(template, a.root, key)

	return err
}

// One level below a pathLen-0 CA, so a leaf under it trips Reason 3.
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

// The one OCSP signer khaos holds: a certificate the CA never issued. Honest
// responses are signed by the chain's own issuer instead, which is the only
// arrangement every chain this authority serves is consistent with.
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
