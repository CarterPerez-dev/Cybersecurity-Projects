// ©AngelaMos | 2026
// revocation.go

package pki

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	// RFC 5280 5.3.1. Reason code 0 is never used: on creation it omits the
	// extension, and on parsing it cannot be told from an absent one.
	reasonKeyCompromise = 1

	crlNumber = 1

	wrongSerialOffset = 1

	garbageStaple = "khaos: this is not an OCSP response"

	errCRL     = "%w: minting a CRL: %v"
	errOCSPGen = "%w: minting an OCSP response: %v"
)

// Go performs NO revocation checking, so every chain in this group verifies
// with a nil error, and that is the finding rather than a weak fault.
func (a *Authority) buildRevocation(
	trap Trap,
	host string,
	now time.Time,
) (*Chain, error) {
	if trap.Kind == RevokedViaCRL || trap.Kind == OCSPRevoked {
		a.mu.RLock()
		if a.armed != nil && (a.trap.Kind == "" || a.trap.Kind == PassThrough ||
			a.trap.Kind == RevokedViaCRL || a.trap.Kind == OCSPRevoked) {
			chain := *a.armed
			a.mu.RUnlock()
			return &chain, nil
		}
		a.mu.RUnlock()
	}

	template, err := a.leaf(host, now, DefaultLeafDays)
	if err != nil {
		return nil, err
	}

	if trap.Kind == NoOCSPServer {
		template.OCSPServer = nil
	}

	return a.assemble(template, a.inter, a.root.cert, StrongBits, true)
}

func (a *Authority) staple(
	trap Trap,
	chain *Chain,
	now time.Time,
) (*Chain, error) {
	switch trap.Kind {
	case StapleGarbage:
		chain.Staple = []byte(garbageStaple)

	case StapleAbsent:
		chain.Staple = nil

	case OCSPTryLater, OCSPUnreachable, CRLUnreachable:
		// NOTHING is stapled. These three are about an answer the client cannot
		// OBTAIN, and a stapled Good would be read before the broken endpoint.
		chain.Staple = nil

	case OCSPRevoked, OCSPStale, OCSPWrongSerial, OCSPWrongSigner,
		OCSPUnknown:
		// The responder faults staple what they would have answered, or an app
		// that trusts staples never contacts the responder under test.
		der, err := a.ocspFor(trap, chain, now)
		if err != nil {
			return nil, err
		}

		chain.Staple = der

	default:
		der, err := a.ocspGood(chain, now, now.Add(DefaultWindow))
		if err != nil {
			return nil, err
		}

		chain.Staple = der
	}

	return chain, nil
}

// Whether the leaf is listed and whether the list is fresh are INDEPENDENT.
func (a *Authority) CRLFor(
	trap Trap,
	chain *Chain,
	now time.Time,
) ([]byte, error) {
	template := &x509.RevocationList{
		Number:     big.NewInt(crlNumber),
		ThisUpdate: now.Add(-clockSlack),
		NextUpdate: now.Add(DefaultWindow),
	}

	if trap.Kind == StaleCRL {
		// ThisUpdate moves with NextUpdate, or the list is also not yet issued.
		window := trap.window()
		template.ThisUpdate = now.Add(-window - DefaultWindow)
		template.NextUpdate = now.Add(-window)
	}

	// Only RevokedViaCRL lists the serial. StaleCRL deliberately does NOT: it
	// models an old list that PREDATES the revocation, and one that revoked the
	// leaf as well would be refused by broken and correct clients alike.
	if trap.Kind == RevokedViaCRL {
		template.RevokedCertificateEntries = []x509.RevocationListEntry{{
			SerialNumber:   chain.Leaf.SerialNumber,
			RevocationTime: now.Add(-clockSlack),
			ReasonCode:     reasonKeyCompromise,
		}}
	}

	der, err := x509.CreateRevocationList(
		rand.Reader,
		template,
		chain.Issuer,
		chain.issuerKey,
	)
	if err != nil {
		return nil, fmt.Errorf(errCRL, ErrMint, err)
	}

	return der, nil
}

func (a *Authority) ocspFor(
	trap Trap,
	chain *Chain,
	now time.Time,
) ([]byte, error) {
	// The chain's OWN issuer signs, which RFC 6960 section 2.6 permits. One
	// delegated responder cannot work: several traps serve a chain under a
	// DIFFERENT CA.
	signer := &pair{cert: chain.Issuer, key: chain.issuerKey}

	template := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: chain.Leaf.SerialNumber,
		ThisUpdate:   now.Add(-clockSlack),
		NextUpdate:   now.Add(DefaultWindow),
	}

	switch trap.Kind {
	case OCSPRevoked:
		template.Status = ocsp.Revoked
		template.RevokedAt = now.Add(-clockSlack)
		template.RevocationReason = reasonKeyCompromise

	case OCSPUnknown:
		template.Status = ocsp.Unknown

	case OCSPStale:
		window := trap.window()
		template.ThisUpdate = now.Add(-window - DefaultWindow)
		template.NextUpdate = now.Add(-window)

	case OCSPWrongSerial:
		template.SerialNumber = new(big.Int).Add(
			chain.Leaf.SerialNumber,
			big.NewInt(wrongSerialOffset),
		)

	case OCSPWrongSigner:
		signer = a.undelegated

	default:
		// Every other kind leaves the response honest.
	}

	// x/crypto embeds the responder certificate only when this is non-nil, and
	// ParseResponse branches on its presence: with one it checks the response
	// against that and that against the issuer. Nil is what lets a
	// self-issued response verify.
	if signer != nil && signer.cert != chain.Issuer {
		template.Certificate = signer.cert
	}

	der, err := ocsp.CreateResponse(
		chain.Issuer,
		signer.cert,
		template,
		signer.key,
	)
	if err != nil {
		return nil, fmt.Errorf(errOCSPGen, ErrMint, err)
	}

	return der, nil
}

func (a *Authority) ocspGood(
	chain *Chain,
	now, until time.Time,
) ([]byte, error) {
	der, err := ocsp.CreateResponse(
		chain.Issuer,
		chain.Issuer,
		ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: chain.Leaf.SerialNumber,
			ThisUpdate:   now.Add(-clockSlack),
			NextUpdate:   until,
		},
		chain.issuerKey,
	)
	if err != nil {
		return nil, fmt.Errorf(errOCSPGen, ErrMint, err)
	}

	return der, nil
}
