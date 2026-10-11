// ©AngelaMos | 2026
// chain.go

package pki

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
)

// Chain is one assembled certificate chain as it will be PRESENTED in a
// handshake, together with what revocation needs in order to talk about it.
//
// Presented and Issuer are separate fields on purpose, and the distinction is
// the whole of the MissingIntermediate fault: the server can withhold a CA from
// the handshake while that CA is still the one that signed the leaf and still
// the one whose CRL covers it. Collapsing them would make that fault
// inexpressible.
type Chain struct {
	// Leaf is the served certificate.
	Leaf    *x509.Certificate
	leafDER []byte
	leafKey crypto.Signer

	// presented is the intermediate DER the handshake carries, leaf-first
	// ordering excluded. It can be empty even when the real chain has an
	// intermediate.
	presented [][]byte

	// Issuer signed the leaf. Revocation answers are always issued by this,
	// even when the handshake withholds it.
	Issuer    *x509.Certificate
	issuerKey crypto.Signer

	// Root is the anchor a correct client needs to verify this chain. For
	// CASwap it is a root khaos minted rather than the one the target was
	// originally given.
	Root *x509.Certificate

	// Staple is the DER OCSP response stapled into the handshake, or nil for no
	// staple at all. Go never parses this; it is delivered to the application
	// verbatim, which is what makes both stapling faults reachable.
	Staple []byte
}

// TLS is the chain as crypto/tls wants it: leaf first, then whatever
// intermediates the server is willing to admit to.
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

// RootPool is the trust anchor set a correct client needs for this chain. It is
// what the range hands its reference client, and what CASwap quietly changes.
func (c *Chain) RootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if c.Root != nil {
		pool.AddCert(c.Root)
	}
	return pool
}

// Presented is how many intermediates the handshake actually carries, which is
// the observable MissingIntermediate is confirmed by.
func (c *Chain) Presented() int {
	return len(c.presented)
}

// PresentedPool is the intermediate set a client receives in the handshake, and
// therefore the only one it may use to build a path. Supplying khaos's real
// intermediate here instead would quietly repair MissingIntermediate, which is
// the mistake that makes that fault untestable.
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
