// ©AngelaMos | 2026
// chain.go

package pki

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
)

// Chain is one chain as it will be PRESENTED in a handshake. Issuer is kept
// apart from presented so a CA can be withheld from the handshake while still
// signing the leaf and the CRL that covers it.
type Chain struct {
	Leaf    *x509.Certificate
	leafDER []byte
	leafKey crypto.Signer

	// Can be empty even when the real chain has an intermediate.
	presented [][]byte

	Issuer    *x509.Certificate
	issuerKey crypto.Signer

	Root *x509.Certificate

	// Go never parses this; the application receives it verbatim.
	Staple []byte

	// Minted at ARM time, as a real CA publishes a list rather than per fetch.
	crl  []byte
	ocsp []byte

	// An unreachable endpoint cannot be expressed in pre-minted bytes.
	crlOut  bool
	ocspOut bool
}

func (c *Chain) CRL() ([]byte, bool) {
	return c.crl, !c.crlOut
}

func (c *Chain) OCSP() ([]byte, bool) {
	return c.ocsp, !c.ocspOut
}

func (c *Chain) TLS() tls.Certificate {
	certificate := tls.Certificate{
		Certificate: append([][]byte{c.leafDER}, c.presented...),
		PrivateKey:  c.leafKey,
		Leaf:        c.Leaf,
	}

	if len(c.Staple) > 0 {
		certificate.OCSPStaple = c.Staple
	}

	return certificate
}

func (c *Chain) RootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if c.Root != nil {
		pool.AddCert(c.Root)
	}
	return pool
}

func (c *Chain) Presented() int {
	return len(c.presented)
}

// Supplying khaos's real intermediate here would repair MissingIntermediate.
func (c *Chain) PresentedPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	for _, der := range c.presented {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}

		pool.AddCert(cert)
	}

	return pool, nil
}
