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
	// reasonKeyCompromise is RFC 5280 section 5.3.1. Reason code 0 is NOT used
	// anywhere in khaos: when creating a CRL, 0 means the reasonCode extension
	// is omitted entirely, and when parsing, 0 is ambiguous between "extension
	// absent" and "extension present, value zero". An ambiguous signal cannot
	// carry a finding.
	reasonKeyCompromise = 1

	// crlNumber is the cRLNumber extension. khaos issues one CRL per arming, so
	// it does not need to increment.
	crlNumber = 1

	// wrongSerialOffset is added to the leaf's serial to mint an OCSP response
	// that is about a DIFFERENT certificate. Any value works; a fixed offset
	// makes the resulting serial reproducible in a failure message.
	wrongSerialOffset = 1

	// garbageStaple is bytes that are definitively not an OCSP response. Go
	// never parses a staple, so these reach the application verbatim and only
	// its own handling decides.
	garbageStaple = "khaos: this is not an OCSP response"

	errCRL     = "%w: minting a CRL: %v"
	errOCSPGen = "%w: minting an OCSP response: %v"
)

// buildRevocation mints the chain for every fault that acts on revocation
// rather than on the certificate itself.
//
// Go performs NO revocation checking of any kind, so every chain in this group
// verifies with a nil error. That is not a weakness of the faults, it IS the
// finding: the certificate is impeccable and the only thing wrong with it is
// something the standard library will never look at.
func (a *Authority) buildRevocation(
	trap Trap,
	host string,
	now time.Time,
) (*Chain, error) {
	template, err := a.leaf(host, now, DefaultLeafDays)
	if err != nil {
		return nil, err
	}

	if trap.Kind == NoOCSPServer {
		// Models Let's Encrypt after it ended OCSP in 2025. The CRL pointer
		// stays, so the honest answer for a target is to fall back to it; the
		// question is whether it does, or treats "nothing to ask" as "fine".
		template.OCSPServer = nil
	}

	return a.assemble(template, a.inter, a.root.cert, StrongBits, true)
}

// staple attaches whatever stapled response the trap calls for. A nil staple is
// not an error: it is the StapleAbsent fault, and it is also what every
// non-stapling trap serves.
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

	case OCSPRevoked, OCSPStale, OCSPWrongSerial, OCSPWrongSigner,
		OCSPUnknown:
		// The responder faults also staple what they would have answered, so a
		// target that reads the staple instead of querying sees the same fault.
		// Without this, an app that trusts staples would be measured against a
		// responder it never contacts and would read as fail-closed.
		der, err := a.ocspFor(trap, chain, now)
		if err != nil {
			return nil, err
		}

		chain.Staple = der

	default:
		// Every other trap staples an honest Good, which is what a correct
		// authority serving a good certificate would do.
		der, err := a.ocspGood(chain, now, now.Add(DefaultWindow))
		if err != nil {
			return nil, err
		}

		chain.Staple = der
	}

	return chain, nil
}

// CRLFor mints the revocation list the authority serves for this chain. The
// trap decides whether the leaf is listed and whether the list is fresh, and
// those are INDEPENDENT: a stale CRL that revokes nothing finds nothing, and a
// fresh CRL that revokes the leaf is the baseline every correct client passes.
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
		// ThisUpdate has to move with NextUpdate, or the list is both stale and
		// not yet issued and a client rejecting it cannot say which it rejected.
		window := trap.window()
		template.ThisUpdate = now.Add(-window - DefaultWindow)
		template.NextUpdate = now.Add(-window)
	}

	if trap.Kind == RevokedViaCRL || trap.Kind == StaleCRL {
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

// ocspFor mints the response the trap calls for. Each branch corrupts exactly
// one property of an otherwise correct Good response, so a client that refuses
// one of them has refused for the reason khaos intended.
func (a *Authority) ocspFor(
	trap Trap,
	chain *Chain,
	now time.Time,
) ([]byte, error) {
	signer := a.responder

	// The responder certificate has to be EMBEDDED in the response, and
	// x/crypto only embeds it when template.Certificate is non-nil
	// (ocsp.go:783). Without it, ParseResponse falls through to verifying the
	// response signature directly against the ISSUER key, which khaos did not
	// sign with, and every delegated answer comes back
	// `bad OCSP signature: crypto/rsa: verification error`.
	//
	// That failure mode is indistinguishable from the OCSPWrongSigner fault
	// landing, so omitting this made four traps look like they were working.
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
		// Unknown from the AUTHORITATIVE responder is not good. Collapsing the
		// two is its own fail-open and a common one.
		template.Status = ocsp.Unknown

	case OCSPStale:
		window := trap.window()
		template.ThisUpdate = now.Add(-window - DefaultWindow)
		template.NextUpdate = now.Add(-window)

	case OCSPWrongSerial:
		// The highest-value trap in the group: the bypass is one word of caller
		// code. ParseResponseForCert rejects this; ParseResponse does not bind
		// the response to the certificate at all and returns a nil error, so a
		// caller reading Status accepts a Good minted for another certificate.
		template.SerialNumber = new(big.Int).Add(
			chain.Leaf.SerialNumber,
			big.NewInt(wrongSerialOffset),
		)

	case OCSPWrongSigner:
		signer = a.undelegated

	default:
		// Good, fresh, correctly signed, for this serial.
	}

	// AFTER the switch, because OCSPWrongSigner changes who signs. Embedding
	// the delegated certificate alongside a signature made by the undelegated
	// key would be rejected for a mismatch between the two rather than for the
	// delegation that is the actual fault, and those are different findings.
	template.Certificate = signer.cert

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

// ocspGood is the honest response, and the control for every responder fault.
func (a *Authority) ocspGood(
	chain *Chain,
	now, until time.Time,
) ([]byte, error) {
	der, err := ocsp.CreateResponse(
		chain.Issuer,
		a.responder.cert,
		ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: chain.Leaf.SerialNumber,
			ThisUpdate:   now.Add(-clockSlack),
			NextUpdate:   until,
			Certificate:  a.responder.cert,
		},
		a.responder.key,
	)
	if err != nil {
		return nil, fmt.Errorf(errOCSPGen, ErrMint, err)
	}

	return der, nil
}

// Responder is the certificate khaos signs OCSP responses with, which a client
// needs in order to check the signature at all.
func (a *Authority) Responder() *x509.Certificate {
	return a.responder.cert
}
