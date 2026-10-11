// ©AngelaMos | 2026
// mint.go

package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	serialBits = 128

	errKeyGen  = "%w: generating a %d-bit key: %v"
	errSign    = "%w: signing %q: %v"
	errReparse = "%w: re-parsing %q: %v"
	errSerial  = "%w: drawing a serial: %v"
)

// ErrMint is any failure to produce the certificate material a trap needs. It
// is deliberately distinct from a trap that armed and then behaved wrongly:
// this one means khaos could not express the fault at all.
var ErrMint = errors.New("khaos could not mint the certificate material")

// pair is a certificate with the key that goes with it, always re-parsed from
// its own DER.
//
// The re-parse is not defensive tidiness. x509.CreateRevocationList requires
// the issuer to have SubjectKeyId set and reads it from the PARSED certificate,
// ignoring whatever the template said, and Go only computes a SubjectKeyId
// while creating a CA certificate. Holding the template would produce a CA that
// cannot issue a CRL, which is most of this family.
type pair struct {
	cert *x509.Certificate
	der  []byte
	key  crypto.Signer
}

func newKey(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf(errKeyGen, ErrMint, bits, err)
	}
	return key, nil
}

func serial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)

	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf(errSerial, ErrMint, err)
	}

	return n, nil
}

// issue signs template with parent, or self-signs it when parent is nil, and
// returns the result re-parsed. The signing key is the PARENT's, which is what
// makes a self-signed leaf and a CA-signed leaf one code path with one
// difference.
func issue(
	template *x509.Certificate,
	parent *pair,
	subject crypto.Signer,
) (*pair, error) {
	issuerCert := template
	issuerKey := subject

	if parent != nil {
		issuerCert = parent.cert
		issuerKey = parent.key
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		issuerCert,
		subject.Public(),
		issuerKey,
	)
	if err != nil {
		return nil, fmt.Errorf(
			errSign,
			ErrMint,
			template.Subject.CommonName,
			err,
		)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf(
			errReparse,
			ErrMint,
			template.Subject.CommonName,
			err,
		)
	}

	return &pair{cert: cert, der: der, key: subject}, nil
}

// caTemplate is every CA khaos mints. crlSign is set on all of them because
// CreateRevocationList refuses an issuer without it, and a CA that cannot
// revoke could not host most of this catalogue.
func caTemplate(name string, from, until time.Time) (
	*x509.Certificate,
	error,
) {
	number, err := serial()
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber:          number,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             from,
		NotAfter:              until,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign |
			x509.KeyUsageDigitalSignature,
	}, nil
}

// leafTemplate is an HONEST leaf. Every defect in this family is expressed by
// mutating what this returns, so anything wrong with it is wrong with the
// control too, and a control that is already broken cannot establish anything.
func leafTemplate(host string, now time.Time, days int) (
	*x509.Certificate,
	error,
) {
	number, err := serial()
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: number,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-clockSlack),
		NotAfter:     now.AddDate(0, 0, days),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, nil
}
