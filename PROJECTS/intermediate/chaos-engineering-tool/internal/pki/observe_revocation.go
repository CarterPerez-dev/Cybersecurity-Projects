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

// Every one of these serves a chain crypto/x509 accepts, so the only evidence
// is what khaos's endpoints answer, read over HTTP as a target would.
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

// Both halves: one endpoint refuses AND the health route still answers.
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

func (a *Authority) observeCRL(
	ctx context.Context,
	trap Trap,
	chain *Chain,
	root string,
) (string, bool, error) {
	// Failing to read khaos's own fault back is NOT CONFIRMED, not an error.
	der, err := a.read(ctx, root+RouteCRL)
	if err != nil {
		return "", false, nil //nolint:nilerr // not confirmed, not an error
	}

	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return "", false, nil //nolint:nilerr // not confirmed, not an error
	}

	if err := list.CheckSignatureFrom(chain.Issuer); err != nil {
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

	// StaleCRL. The serial must be ABSENT, or a client ignoring freshness
	// still finds it and refuses.
	if !listed && list.NextUpdate.Before(now) {
		return sprintf(
			observedStale,
			"CRL",
			now.Sub(list.NextUpdate).Round(time.Second),
		), true, nil
	}

	return "", false, nil
}

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
		if _, bindErr := ocsp.ParseResponseForCert(
			der,
			chain.Leaf,
			chain.Issuer,
		); bindErr != nil {
			//nolint:nilerr // the rejection IS the observable
			return observedBadSigner, true, nil
		}

		return "", false, nil //nolint:nilerr // not confirmed, not an error
	}

	// The loose call is deliberate: ParseResponseForCert refuses the
	// wrong-serial response, which is the fault khaos is reading back.
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
		if response.Status == ocsp.Good &&
			response.NextUpdate.Before(now) {
			return sprintf(
				observedStale,
				"OCSP response",
				now.Sub(response.NextUpdate).Round(time.Second),
			), true, nil
		}

	case OCSPWrongSerial:
		// Good, and about a DIFFERENT certificate: a Revoked for the wrong
		// serial would be refused on status instead.
		if response.Status == ocsp.Good &&
			response.SerialNumber.Cmp(chain.Leaf.SerialNumber) != 0 {
			return sprintf(
				observedOCSPOther,
				response.SerialNumber,
				chain.Leaf.SerialNumber,
			), true, nil
		}

	default:
		// Kinds from the other groups reach their own observer.
	}

	return "", false, nil
}

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
