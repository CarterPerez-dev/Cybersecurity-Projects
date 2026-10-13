// ©AngelaMos | 2026
// observe_revocation.go

package pki

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

const maxReadBack = 1 << 20

// observeRevocation confirms the faults that act on revocation rather than on
// the certificate.
//
// Every one of these serves a chain crypto/x509 accepts, so there is no refusal
// anywhere to read back and nothing in the certificate differs from the
// control. The ONLY evidence is what khaos's own endpoints answer, which is why
// this reads them over HTTP exactly as a target would rather than inspecting
// the state that produced them.
func (a *Authority) observeRevocation(
	ctx context.Context,
	trap Trap,
	chain *Chain,
) (string, bool, error) {
	base, err := a.Addr()
	if err != nil {
		return "", false, err
	}

	root := schemeHTTP + base

	switch trap.Kind {
	case CRLUnreachable, OCSPUnreachable:
		return a.observeUnreachable(ctx, trap, root)

	case RevokedViaCRL, StaleCRL:
		return a.observeCRL(ctx, trap, chain, root)

	default:
		return a.observeResponder(ctx, trap, chain, root)
	}
}

// observeUnreachable confirms that ONE endpoint refuses while the health route
// still answers. Both halves are required: an authority that fell over would
// satisfy the first on its own, and khaos would be reporting its own crash as a
// fault it injected.
func (a *Authority) observeUnreachable(
	ctx context.Context,
	trap Trap,
	root string,
) (string, bool, error) {
	route := RouteCRL
	if trap.Kind == OCSPUnreachable {
		route = RouteOCSP
	}

	if _, err := a.probe(ctx, root+route); err == nil {
		return "", false, nil
	}

	status, err := a.health(ctx)
	if err != nil {
		return "", false, err
	}

	return sprintf(observedUnreached, route, status), true, nil
}

// observeCRL reads the list khaos serves. The two CRL faults are distinguished
// HERE and not by what they were asked to do: one lists the serial in a fresh
// list, the other omits it from a stale one, and a mix-up either way makes one
// of them inert.
func (a *Authority) observeCRL(
	ctx context.Context,
	trap Trap,
	chain *Chain,
	root string,
) (string, bool, error) {
	// Every failure below returns NOT CONFIRMED rather than an error, and that
	// is the same discipline the identity provider's oracle uses: khaos being
	// unable to read its own fault back is a refusal to confirm, which makes
	// the engine abort the run. Returning the read error instead would make
	// khaos fail with a plumbing complaint when the honest answer is "khaos
	// could not see this fault land".
	der, err := a.read(ctx, root+RouteCRL)
	if err != nil {
		return "", false, nil //nolint:nilerr // not confirmed, not an error
	}

	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return "", false, nil //nolint:nilerr // not confirmed, not an error
	}

	if err := list.CheckSignatureFrom(chain.Issuer); err != nil {
		// A list a correct client would discard proves nothing about the
		// target: it would refuse for khaos's defect rather than the fault's.
		return "", false, nil //nolint:nilerr // not confirmed, not an error
	}

	now := a.clock()
	listed := revoked(list, chain.Leaf)

	if trap.Kind == RevokedViaCRL {
		if listed && list.NextUpdate.After(now) {
			return sprintf(
				observedRevoked,
				chain.Leaf.SerialNumber,
			), true, nil
		}

		return "", false, nil
	}

	// StaleCRL. The serial must be ABSENT, or a client that ignores freshness
	// still finds it and refuses, and the fault catches nothing.
	if !listed && list.NextUpdate.Before(now) {
		return sprintf(
			observedStale,
			"CRL",
			now.Sub(list.NextUpdate).Round(time.Second),
		), true, nil
	}

	return "", false, nil
}

// observeResponder reads what the OCSP endpoint answers. Each branch asserts
// the ONE property its fault corrupts, so a responder that was wrong in some
// other way cannot confirm a trap it is not producing.
func (a *Authority) observeResponder(
	ctx context.Context,
	trap Trap,
	chain *Chain,
	root string,
) (string, bool, error) {
	der, err := a.read(ctx, root+RouteOCSP)
	if err != nil {
		return "", false, nil //nolint:nilerr // not confirmed, not an error
	}

	if trap.Kind == OCSPTryLater {
		// TryLater is a RESPONSE status, so it must NOT parse as an answer. A
		// successful parse here would mean khaos served a real verdict and the
		// soft-fail trap never gets its chance.
		var unusable ocsp.ResponseError
		if _, parseErr := ocsp.ParseResponse(
			der,
			chain.Issuer,
		); errors.As(parseErr, &unusable) &&
			unusable.Status == ocsp.TryLater {
			return sprintf(observedOCSPSays, int(ocsp.TryLater)), true, nil
		}

		return "", false, nil
	}

	if trap.Kind == OCSPWrongSigner {
		// Rejected when bound to the certificate is the whole fault. Parsing it
		// successfully would mean the CA did issue the signer after all.
		if _, bindErr := ocsp.ParseResponseForCert(
			der,
			chain.Leaf,
			chain.Issuer,
		); bindErr != nil {
			// The binding FAILING is the confirmation, not an error being
			// swallowed: the CA never issued this signer, which is the fault.
			//nolint:nilerr // the rejection IS the observable
			return observedBadSigner, true, nil
		}

		return "", false, nil //nolint:nilerr // not confirmed, not an error
	}

	// The remaining three answer about SOMETHING, so they have to parse. The
	// loose call is used deliberately: ParseResponseForCert refuses the
	// wrong-serial response, which is the fault khaos is trying to read back.
	response, err := ocsp.ParseResponse(der, chain.Issuer)
	if err != nil {
		return "", false, nil //nolint:nilerr // not confirmed, not an error
	}

	return a.judgeResponse(trap, chain, response)
}

func (a *Authority) judgeResponse(
	trap Trap,
	chain *Chain,
	response *ocsp.Response,
) (string, bool, error) {
	now := a.clock()

	switch trap.Kind {
	case OCSPRevoked:
		if response.Status == ocsp.Revoked {
			return sprintf(observedOCSPSays, response.Status), true, nil
		}

	case OCSPUnknown:
		if response.Status == ocsp.Unknown {
			return sprintf(observedOCSPSays, response.Status), true, nil
		}

	case OCSPStale:
		// Good AND stale. A stale Revoked would be refused for its status, so a
		// client refusing it would prove nothing about freshness.
		if response.Status == ocsp.Good &&
			response.NextUpdate.Before(now) {
			return sprintf(
				observedStale,
				"OCSP response",
				now.Sub(response.NextUpdate).Round(time.Second),
			), true, nil
		}

	case OCSPWrongSerial:
		// Good, and about a DIFFERENT certificate. Both halves: a Revoked for
		// the wrong serial would be refused on status by a client that never
		// checks the binding.
		if response.Status == ocsp.Good &&
			response.SerialNumber.Cmp(chain.Leaf.SerialNumber) != 0 {
			return sprintf(
				observedOCSPOther,
				response.SerialNumber,
				chain.Leaf.SerialNumber,
			), true, nil
		}

	default:
		// Unreachable: observeResponder handles the other kinds itself.
	}

	return "", false, nil
}

// probe and read are khaos's OWN requests, marked so the counters can subtract
// them. Without the header, "the target consulted revocation" would be true for
// every run in which khaos confirmed its own fault, and the UNSUPPORTED verdict
// would never fire.
func (a *Authority) probe(ctx context.Context, url string) (int, error) {
	response, err := a.send(ctx, url)
	if err != nil {
		return 0, err
	}

	defer func() { _ = response.Body.Close() }()

	_, _ = io.Copy(io.Discard, response.Body)

	return response.StatusCode, nil
}

func (a *Authority) read(ctx context.Context, url string) ([]byte, error) {
	response, err := a.send(ctx, url)
	if err != nil {
		return nil, err
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, errors.New("khaos's own endpoint answered " +
			response.Status)
	}

	return io.ReadAll(io.LimitReader(response.Body, maxReadBack))
}

func (a *Authority) send(
	ctx context.Context,
	url string,
) (*http.Response, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		url,
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Set(headerProbe, probeValue)

	client := &http.Client{Timeout: observeTimeout}

	return client.Do(request)
}

func revoked(list *x509.RevocationList, leaf *x509.Certificate) bool {
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return true
		}
	}

	return false
}
