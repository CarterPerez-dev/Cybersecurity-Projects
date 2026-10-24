// ©AngelaMos | 2026
// mutual.go

package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"time"
)

const (
	// RouteIdentity issues the target's client certificate. khaos is the CA for
	// both ends, which is the only way it can make this wrong.
	RouteIdentity = "/identity"

	nameClient = "khaos range client"

	blockCertificate = "CERTIFICATE"
	blockKey         = "RSA PRIVATE KEY"

	mimePEM = "application/x-pem-file"
)

// Read per handshake through GetConfigForClient, because a ClientAuth fixed at
// bind time could only be armed before the range was pointed at khaos.
func (a *Authority) RequiresMutualTLS() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.mutual
}

// Withholding the identity IS the ClientCertAbsent fault.
func (a *Authority) ClientIdentity() (*pair, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.clientID, a.clientID != nil
}

func (a *Authority) mintClientIdentity(
	trap Trap,
	now time.Time,
) (*pair, error) {
	if trap.Kind == ClientCertAbsent {
		return nil, nil
	}

	number, err := serial()
	if err != nil {
		return nil, err
	}

	from := now.Add(-clockSlack)
	until := now.AddDate(0, 0, DefaultLeafDays)

	if trap.Kind == ClientCertExpired {
		// Moved TOGETHER, so the identity is expired and nothing else.
		window := trap.window()
		from = now.Add(-window - DefaultWindow)
		until = now.Add(-window)
	}

	template := &x509.Certificate{
		SerialNumber: number,
		Subject:      pkix.Name{CommonName: nameClient},
		NotBefore:    from,
		NotAfter:     until,
		KeyUsage:     x509.KeyUsageDigitalSignature,

		// clientAuth, or khaos's server refuses it for the wrong reason.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	key, err := newKey(StrongBits)
	if err != nil {
		return nil, err
	}

	return issue(template, a.inter, key)
}

// Serving a private key over plain HTTP is defensible only in a fixture whose
// purpose is to be broken, and is what makes the mTLS faults injectable.
func (a *Authority) serveIdentity(w http.ResponseWriter, _ *http.Request) {
	identity, issuing := a.ClientIdentity()
	if !issuing {
		// Not an error: a target that connects anyway is the finding.
		w.WriteHeader(http.StatusNotFound)

		return
	}

	w.Header().Set(headerType, mimePEM)
	w.WriteHeader(http.StatusOK)

	_ = pem.Encode(w, &pem.Block{
		Type:  blockCertificate,
		Bytes: identity.der,
	})

	_ = pem.Encode(w, &pem.Block{
		Type:  blockKey,
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKeyOf(identity)),
	})
}

// Both halves, every time: a server that requires nothing rejects nobody, and
// an identity nobody is asked for is never presented.
func (a *Authority) observeMutual(trap Trap) (string, bool, error) {
	if !a.RequiresMutualTLS() {
		return "", false, nil
	}

	identity, issuing := a.ClientIdentity()

	if trap.Kind == ClientCertAbsent {
		if issuing {
			return "", false, nil
		}

		return observedNoIdentity, true, nil
	}

	if !issuing {
		return "", false, nil
	}

	now := a.clock()
	if !identity.cert.NotAfter.Before(now) {
		return "", false, nil
	}

	return sprintf(
		observedClientExpired,
		now.Sub(identity.cert.NotAfter).Round(time.Second),
	), true, nil
}
