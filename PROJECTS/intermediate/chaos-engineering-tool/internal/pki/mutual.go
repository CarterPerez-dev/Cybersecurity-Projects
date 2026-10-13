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
	// RouteIdentity serves the CLIENT certificate and key khaos has issued to
	// the target, as PEM.
	//
	// khaos issues the target's identity because khaos is the CA for both ends,
	// which is how a service mesh actually works and the only arrangement in
	// which khaos can make that identity wrong. A target holding a certificate
	// khaos did not issue is a target khaos cannot inject an mTLS fault into.
	RouteIdentity = "/identity"

	nameClient = "khaos range client"

	blockCertificate = "CERTIFICATE"
	blockKey         = "RSA PRIVATE KEY"

	mimePEM = "application/x-pem-file"
)

// RequiresMutualTLS reports whether the armed trap makes khaos demand a client
// certificate.
//
// It is read per handshake rather than fixed at bind time, through
// GetConfigForClient, because arming a trap has to take effect on the next
// connection without the listener moving. A ClientAuth fixed at bind time would
// mean the mTLS traps could only be armed before the range was pointed at
// khaos, which is not when an experiment arms anything.
func (a *Authority) RequiresMutualTLS() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// BUILT state, not read off the trap. An inert authority -- one that
	// records a trap and builds nothing -- would otherwise report that it
	// demands mutual TLS and is issuing no identity, which is both halves of
	// the client-cert-absent observable satisfied by a fault that never
	// happened. The oracle's negative control caught exactly that, for the
	// second time in this package and for the identical reason.
	return a.mutual
}

// ClientIdentity is the certificate and key khaos has issued to the target
// right now, or false when it is issuing none.
//
// Withholding it IS the ClientCertAbsent fault. Research 04 is explicit that
// this is the more dangerous of the two: an attacker does not present a bad
// certificate, they present nothing, and the ClientAuth mode that rejects a bad
// one while accepting none reads as secure and fails completely open.
func (a *Authority) ClientIdentity() (*pair, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Built state again. Withholding the identity is expressed by there BEING
	// no identity, not by a flag consulted at serve time, so an authority that
	// built nothing keeps handing out the honest one.
	return a.clientID, a.clientID != nil
}

// mintClientIdentity issues the target's own certificate. It is called at arm
// time like everything else the authority serves, so an inert authority -- one
// that records a trap and builds nothing -- keeps serving the honest identity
// and the oracle's negative control holds.
func (a *Authority) mintClientIdentity(
	trap Trap,
	now time.Time,
) (*pair, error) {
	// NOTHING, which is the whole of the absent fault. A nil identity here is
	// how "khaos issues the target none" is represented, so it cannot be
	// confused with an authority that simply has not built one yet.
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
		// Moved TOGETHER, so the identity is expired and nothing else. One that
		// was also not-yet-valid would be refused for either reason and khaos
		// could not say which.
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

		// clientAuth, not serverAuth. An identity presented as a client has to
		// be permitted for it, or khaos's own server refuses it for the wrong
		// reason and the fault is unattributable.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	key, err := newKey(StrongBits)
	if err != nil {
		return nil, err
	}

	return issue(template, a.inter, key)
}

// serveIdentity hands the target its own certificate and key.
//
// Serving a private key over plain HTTP is indefensible in anything but a
// fixture whose whole purpose is to be broken, and it is what makes the mTLS
// faults injectable at all: khaos has to be able to change the identity the
// target presents, which means khaos has to be the one handing it over.
func (a *Authority) serveIdentity(w http.ResponseWriter, _ *http.Request) {
	identity, issuing := a.ClientIdentity()
	if !issuing {
		// Not an error. khaos is deliberately issuing nothing, and a target
		// that treats "no identity available" as a reason to connect anyway is
		// exactly what this fault is looking for.
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

// observeMutual confirms the two mutual TLS faults.
//
// BOTH halves, every time. khaos has to be demanding a client certificate AND
// the identity it issued has to be wrong, because either alone is not the
// fault: a server that does not require mTLS rejects nobody, and a bad identity
// nobody is asked for is never presented.
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
