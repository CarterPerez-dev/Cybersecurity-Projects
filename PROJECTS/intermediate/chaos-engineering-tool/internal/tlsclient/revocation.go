// ©AngelaMos | 2026
// revocation.go

package tlsclient

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

const maxRevocationBody = 1 << 20

// revocation is the layer crypto/x509 does not have.
//
// The order matters and is not arbitrary. A STAPLED response is preferred
// because it costs no round trip and is what a real client sees first; then
// OCSP, because it answers about one certificate rather than about every
// certificate the CA ever revoked; then the CRL as a fallback, because that is
// what remains once a CA ends OCSP, which Let's Encrypt did in 2025.
//
// A mode that checks nothing returns accepted here without asking anything, and
// the Asked fields record that, because "accepted without looking" and
// "accepted after looking" are different findings about a target.
func (c *Client) revocation(
	ctx context.Context,
	leaf, issuer *x509.Certificate,
	state tls.ConnectionState,
) Decision {
	if !c.mode.checksRevocation() {
		return Decision{Accepted: true}
	}

	// THE RESUMPTION HOLE, stated exactly as crypto/tls documents it.
	//
	// VerifyPeerCertificate does NOT run on a resumed handshake, and the doc
	// comment says to use VerifyConnection or disable tickets instead
	// (common.go:645-677). So an application whose pinning, staple validation
	// or revocation check lives in that hook has a policy that is enforced on
	// the first handshake and skipped on every resumption for the ticket's
	// lifetime, which Go caps at seven days (common.go:983-985).
	//
	// Expiry cannot survive this: Go's client re-verifies the cached chain for
	// NotAfter and chain validity before offering a ticket, and drops the entry
	// if it fails. REVOCATION survives, because nothing anywhere checks it.
	if state.DidResume && !c.mode.rechecksPerConnection() {
		return Decision{Accepted: true, Resumed: true}
	}

	decision := Decision{Accepted: true, Resumed: state.DidResume}

	if reason, ok := c.fromStaple(state, leaf, issuer, &decision); !ok {
		return Decision{Reason: reason, AskedOCSP: decision.AskedOCSP}
	}

	if reason, ok := c.fromOCSP(ctx, leaf, issuer, &decision); !ok {
		return Decision{
			Reason:    reason,
			AskedOCSP: decision.AskedOCSP,
			AskedCRL:  decision.AskedCRL,
		}
	}

	if reason, ok := c.fromCRL(ctx, leaf, issuer, &decision); !ok {
		return Decision{
			Reason:    reason,
			AskedOCSP: decision.AskedOCSP,
			AskedCRL:  decision.AskedCRL,
		}
	}

	return decision
}

// fromStaple reads the response the handshake carried. Go never parses a
// staple, so whatever the server attached arrives verbatim and only this code
// decides anything about it.
func (c *Client) fromStaple(
	state tls.ConnectionState,
	leaf, issuer *x509.Certificate,
	decision *Decision,
) (string, bool) {
	if len(state.OCSPResponse) == 0 {
		// No staple at all. A soft-failing client reads this as "fine", which
		// is the StapleAbsent fault, and a correct one falls through to asking
		// the responder directly rather than refusing outright.
		return reasonAccepted, true
	}

	if c.mode == TrustStaple {
		// Believed without being parsed. Garbage bytes are accepted here, which
		// is the whole of the StapleGarbage fault.
		//
		// The question is marked ANSWERED and the function returns here. A client
		// that trusts the staple must not also query the responder: it would then
		// refuse on the real answer, and three traps would look caught by a mode
		// that by construction cannot catch them.
		decision.AskedOCSP = true

		return reasonAccepted, true
	}

	response, err := c.parseOCSP(state.OCSPResponse, leaf, issuer)
	if err != nil {
		if c.mode.hardFails() {
			return reasonBadStaple, false
		}

		return reasonAccepted, true
	}

	decision.AskedOCSP = true

	return c.judgeOCSP(response)
}

// fromOCSP asks the responder named in the certificate. A certificate naming no
// responder is not an error: it is what Let's Encrypt now issues, and the
// honest answer is to fall through to the CRL.
func (c *Client) fromOCSP(
	ctx context.Context,
	leaf, issuer *x509.Certificate,
	decision *Decision,
) (string, bool) {
	if len(leaf.OCSPServer) == 0 {
		return reasonAccepted, true
	}

	if decision.AskedOCSP {
		// Already answered by the staple.
		return reasonAccepted, true
	}

	request, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return c.cannotTell()
	}

	body, err := c.post(ctx, leaf.OCSPServer[0], request)
	if err != nil {
		// Could not reach the responder, or it answered TryLater. A
		// soft-failing client proceeds here, which is the trap.
		return c.cannotTell()
	}

	response, err := c.parseOCSP(body, leaf, issuer)
	if err != nil {
		return c.cannotTell()
	}

	decision.AskedOCSP = true

	return c.judgeOCSP(response)
}

// parseOCSP is the one-word difference that is a total bypass. ParseResponse
// does NOT bind the response to the certificate, so a Good minted for another
// serial is accepted; ParseResponseForCert refuses it. Both verify the
// signature.
func (c *Client) parseOCSP(
	der []byte,
	leaf, issuer *x509.Certificate,
) (*ocsp.Response, error) {
	if c.mode.bindsResponse() {
		return ocsp.ParseResponseForCert(der, leaf, issuer)
	}

	return ocsp.ParseResponse(der, issuer)
}

// judgeOCSP decides on a response that already verified. Good is the only
// acceptable status: Unknown from the authoritative responder is not good, and
// collapsing the two is its own fail-open.
func (c *Client) judgeOCSP(response *ocsp.Response) (string, bool) {
	if response.Status == ocsp.Revoked {
		return reasonRevoked, false
	}

	if response.Status != ocsp.Good {
		if c.mode.hardFails() {
			return reasonOCSPStatus, false
		}

		return reasonAccepted, true
	}

	if c.mode.checksOCSPFreshness() && !response.NextUpdate.IsZero() &&
		response.NextUpdate.Before(c.clock()) {
		// x/crypto/ocsp does not check this, measured: a response with
		// NextUpdate a day in the past parses with a nil error. A client that
		// skips it trusts a replayed Good forever.
		return reasonStaleOCSP, false
	}

	return reasonAccepted, true
}

// fromCRL is the six-step check from research 04 section 4.3, in full, because
// steps five and six are the ones people skip and skipping either is a
// fail-open on its own.
func (c *Client) fromCRL(
	ctx context.Context,
	leaf, issuer *x509.Certificate,
	decision *Decision,
) (string, bool) {
	if len(leaf.CRLDistributionPoints) == 0 {
		return reasonAccepted, true
	}

	// Step 2: fetch. Go parses the distribution point and never follows it.
	der, err := c.fetch(ctx, leaf.CRLDistributionPoints[0])
	if err != nil {
		return c.cannotTell()
	}

	// Step 3: parse.
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return c.cannotTell()
	}

	decision.AskedCRL = true

	// Step 4: the signature, or anyone can hand you a list.
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return reasonBadCRLSig, false
	}

	// Step 5: freshness. Nothing in the standard library does this, and a
	// three-week-old list is otherwise authoritative.
	if c.mode.checksCRLFreshness() && !list.NextUpdate.IsZero() &&
		list.NextUpdate.Before(c.clock()) {
		return reasonStaleCRL, false
	}

	// Step 6: the linear scan.
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return reasonRevoked, false
		}
	}

	return reasonAccepted, true
}

// cannotTell is the soft-fail decision point, and the single most consequential
// branch in this file. A client that proceeds because it could not get an
// answer has a seat belt that unbuckles in a crash.
func (c *Client) cannotTell() (string, bool) {
	if c.mode.hardFails() {
		return reasonNoAnswer, false
	}

	return reasonAccepted, true
}

func (c *Client) fetch(ctx context.Context, url string) ([]byte, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		url,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return c.send(request)
}

func (c *Client) post(
	ctx context.Context,
	url string,
	body []byte,
) ([]byte, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		url,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/ocsp-request")

	return c.send(request)
}

func (c *Client) send(request *http.Request) ([]byte, error) {
	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, &httpStatusError{status: response.Status}
	}

	return io.ReadAll(io.LimitReader(response.Body, maxRevocationBody))
}

type httpStatusError struct {
	status string
}

func (e *httpStatusError) Error() string {
	return "revocation endpoint answered " + e.status
}

// modulusBits is the leaf's RSA size, and false for any other key type. An
// ECDSA key has no modulus and the floor does not apply to it.
func modulusBits(leaf *x509.Certificate) (int, bool) {
	key, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return 0, false
	}

	return key.N.BitLen(), true
}
