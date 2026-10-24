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

// revocation is the layer crypto/x509 does not have, in order: the staple
// costs no round trip, then OCSP, then the CRL once a CA ends OCSP.
func (c *Client) revocation(
	ctx context.Context,
	leaf, issuer *x509.Certificate,
	state tls.ConnectionState,
) Decision {
	if !c.mode.checksRevocation() {
		return Decision{Accepted: true}
	}

	// THE RESUMPTION HOLE: crypto/tls does not run VerifyPeerCertificate on a
	// resumed handshake, so a policy in that hook is skipped for the ticket's
	// lifetime. An expired identity still cannot slip through, because Go
	// re-verifies the cached chain before offering a ticket; a revoked one can.
	if state.DidResume && !c.mode.rechecksPerConnection() {
		return Decision{Accepted: true, Resumed: true}
	}

	decision := Decision{Accepted: true, Resumed: state.DidResume}
	if state.DidResume {
		state.OCSPResponse = nil
	}

	if reason, ok := c.fromStaple(state, leaf, issuer, &decision); !ok {
		return Decision{
			Reason: reason, AskedOCSP: decision.AskedOCSP,
			Resumed: state.DidResume,
		}
	}

	if reason, ok := c.fromOCSP(ctx, leaf, issuer, &decision); !ok {
		return Decision{
			Reason:    reason,
			Resumed:   state.DidResume,
			AskedOCSP: decision.AskedOCSP,
			AskedCRL:  decision.AskedCRL,
		}
	}

	if reason, ok := c.fromCRL(ctx, leaf, issuer, &decision); !ok {
		return Decision{
			Reason:    reason,
			Resumed:   state.DidResume,
			AskedOCSP: decision.AskedOCSP,
			AskedCRL:  decision.AskedCRL,
		}
	}

	return decision
}

// Go never parses a staple, so whatever the server attached arrives verbatim.
func (c *Client) fromStaple(
	state tls.ConnectionState,
	leaf, issuer *x509.Certificate,
	decision *Decision,
) (string, bool) {
	if len(state.OCSPResponse) == 0 {
		return reasonAccepted, true
	}

	if c.mode == TrustStaple {
		// Marking it asked suppresses the live query below, or a mode that
		// trusts the staple would refuse on the real answer it exists to
		// ignore.
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

// No responder named is not an error: fall through to the CRL.
func (c *Client) fromOCSP(
	ctx context.Context,
	leaf, issuer *x509.Certificate,
	decision *Decision,
) (string, bool) {
	if len(leaf.OCSPServer) == 0 {
		return reasonAccepted, true
	}

	if decision.AskedOCSP {
		return reasonAccepted, true
	}

	request, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return c.cannotTell()
	}

	body, err := c.post(ctx, leaf.OCSPServer[0], request)
	if err != nil {
		return c.cannotTell()
	}

	response, err := c.parseOCSP(body, leaf, issuer)
	if err != nil {
		return c.cannotTell()
	}

	decision.AskedOCSP = true

	return c.judgeOCSP(response)
}

// The one-word difference that is a total bypass: ParseResponse does NOT bind
// the response to the certificate, so a Good for another serial is accepted.
func (c *Client) parseOCSP(
	der []byte,
	leaf, issuer *x509.Certificate,
) (*ocsp.Response, error) {
	if c.mode.bindsResponse() {
		return ocsp.ParseResponseForCert(der, leaf, issuer)
	}

	return ocsp.ParseResponse(der, issuer)
}

// Good is the only acceptable status; Unknown is not Good.
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
		// x/crypto/ocsp does not: a stale NextUpdate parses with a nil error.
		return reasonStaleOCSP, false
	}

	return reasonAccepted, true
}

func (c *Client) fromCRL(
	ctx context.Context,
	leaf, issuer *x509.Certificate,
	decision *Decision,
) (string, bool) {
	if len(leaf.CRLDistributionPoints) == 0 {
		return reasonAccepted, true
	}

	// Go parses the distribution point and never follows it.
	der, err := c.fetch(ctx, leaf.CRLDistributionPoints[0])
	if err != nil {
		return c.cannotTell()
	}

	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return c.cannotTell()
	}

	decision.AskedCRL = true

	// The signature, or anyone at all can hand you a list.
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return reasonBadCRLSig, false
	}

	// Freshness, which nothing in the standard library checks.
	if c.mode.checksCRLFreshness() && !list.NextUpdate.IsZero() &&
		list.NextUpdate.Before(c.clock()) {
		return reasonStaleCRL, false
	}

	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return reasonRevoked, false
		}
	}

	return reasonAccepted, true
}

// The soft-fail point: a seat belt that unbuckles in a crash.
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

// False for any other key type: an ECDSA key has no modulus to floor.
func modulusBits(leaf *x509.Certificate) (int, bool) {
	key, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return 0, false
	}

	return key.N.BitLen(), true
}
