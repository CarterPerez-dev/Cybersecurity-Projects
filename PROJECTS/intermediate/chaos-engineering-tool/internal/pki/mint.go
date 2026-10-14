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
	"net"
	"time"
)

const (
	serialBits = 128

	errKeyGen  = "%w: generating a %d-bit key: %v"
	errSign    = "%w: signing %q: %v"
	errReparse = "%w: re-parsing %q: %v"
	errSerial  = "%w: drawing a serial: %v"
)

var ErrMint = errors.New("khaos could not mint the certificate material")

// pair is always re-parsed from its own DER: CreateRevocationList reads
// SubjectKeyId from the PARSED certificate and ignores the template.
type pair struct {
	cert *x509.Certificate
	der  []byte
	key  crypto.Signer
}

func rsaKeyOf(p *pair) *rsa.PrivateKey {
	key, ok := p.key.(*rsa.PrivateKey)
	if !ok {
		return nil
	}

	return key
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

// Every CA gets crlSign, because CreateRevocationList refuses one without it.
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

		// A loopback IP SAN, so NoIPSAN has something to REMOVE.
		IPAddresses: []net.IP{net.ParseIP(loopbackSAN)},

		NotBefore: now.Add(-clockSlack),
		NotAfter:  now.AddDate(0, 0, days),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, nil
}
