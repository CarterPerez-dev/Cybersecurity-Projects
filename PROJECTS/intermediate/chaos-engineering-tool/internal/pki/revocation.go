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

	case OCSPTryLater, OCSPUnreachable, CRLUnreachable:
		// NOTHING is stapled. These three faults are about an answer the client
		// cannot OBTAIN, and a stapled Good is an answer obtained for free: the
		// client would read it, be satisfied, and never contact the endpoint
		// khaos broke. The fault would be completely unreachable.
		//
		// The matrix caught exactly this. Nine modes, including the correct
		// one, accepted ocsp-try-later and ocsp-unreachable because the staple
		// answered first.
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

	// Only RevokedViaCRL lists the serial. StaleCRL deliberately does NOT, and
	// that is the difference between the two faults.
	//
	// The first draft had the stale list also revoke the leaf, which made the
	// fault catch nothing: a client that ignores freshness still reaches the
	// serial scan, still finds the entry, and still refuses, so the broken
	// client behaved exactly like the correct one. The matrix caught it.
	//
	// The real scenario is a three-week-old list that PREDATES the revocation.
	// A correct client refuses because a list it cannot trust is not an answer;
	// a client that skips step five reads "not listed" as "not revoked" and
	// accepts. That differential is the whole fault.
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

// ocspFor mints the response the trap calls for. Each branch corrupts exactly
// one property of an otherwise correct Good response, so a client that refuses
// one of them has refused for the reason khaos intended.
func (a *Authority) ocspFor(
	trap Trap,
	chain *Chain,
	now time.Time,
) ([]byte, error) {
	// The chain's OWN issuer signs, acting as its own responder, which RFC 6960
	// section 2.6 permits alongside a delegated one.
	//
	// A single delegated responder cannot work here, and the matrix proved it.
	// Seven of these traps serve a chain under a DIFFERENT CA -- the rogue
	// hierarchy, a non-CA issuer, an over-deep intermediate, or the leaf
	// itself -- and a response signed by a responder delegated by the honest
	// intermediate does not verify against any of them. Six traps were being
	// refused for `the stapled response is not a usable OCSP response`, which
	// is khaos's own mismatch wearing the wrong-signer fault's clothes.
	//
	// Signing with the chain's issuer is always consistent with the chain by
	// construction. The delegation path is still exercised, from the other
	// side, by OCSPWrongSigner.
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

	// Embedded ONLY for the wrong-signer fault, and only after the switch has
	// decided who signs.
	//
	// x/crypto embeds the responder certificate just when template.Certificate
	// is non-nil (ocsp.go:783), and ParseResponse branches on whether one is
	// present: with a certificate it checks the response against that and that
	// against the issuer, and without one it checks the response against the
	// issuer directly. The issuer signs its own responses here, so leaving this
	// nil is what makes them verify. Setting it for the undelegated signer is
	// what makes that response fail at the SECOND check, which is the fault.
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

// ocspGood is the honest response, and the control for every responder fault.
// Signed by the chain's own issuer for the same reason ocspFor is.
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
