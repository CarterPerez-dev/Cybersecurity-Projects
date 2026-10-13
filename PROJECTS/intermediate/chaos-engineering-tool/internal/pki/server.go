// ©AngelaMos | 2026
// server.go

package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	network     = "tcp"
	schemeHTTP  = "http://"
	mimePKIX    = "application/pkix-crl"
	mimeOCSP    = "application/ocsp-response"
	mimeDER     = "application/pkix-cert"
	headerType  = "Content-Type"
	healthBody  = "ok"
	maxOCSPBody = 64 << 10

	errNoListener = "%w: the authority is not listening, so %s cannot be reached"
	errBindFailed = "%w: binding %q: %v"
	errAlreadyUp  = "%w: the authority is already listening on %s"
)

// ErrListener is any failure to stand up or reach the authority's own
// endpoints. It is separate from a trap failing, because khaos being
// unreachable is khaos's bug and a trap landing is the product working.
var ErrListener = errors.New("khaos's certificate authority listener")

// listenerState holds both of the authority's listeners. There are two because
// they serve different protocols to the same target: a TLS endpoint where khaos
// IS the dependency whose certificate is under test, and a plain HTTP endpoint
// for the revocation data that certificate points at.
//
// They cannot be one listener. The revocation endpoints have to stay reachable
// while the TLS certificate is broken, or every revocation fault would also be
// an outage and khaos could not attribute what it measured.
type listenerState struct {
	mu sync.Mutex

	revocation net.Listener
	revSrv     *http.Server

	dependency net.Listener
	depSrv     *http.Server

	base string
	wg   sync.WaitGroup
}

// Base is the URL the TARGET uses to reach the CRL and OCSP endpoints.
//
// It is configured rather than derived from the listener, and that distinction
// cost a full debugging session in the identity family. khaos binds the Docker
// bridge gateway's numeric address while the target addresses
// `host.docker.internal`, so a URL built from khaos's own listener address is
// unreachable from inside the target's network namespace. Every revocation
// fetch would then fail for a reason that has nothing to do with the trap, and
// the run would report the target as fail-closed when khaos had simply pointed
// it at nowhere.
func (a *Authority) Base() string {
	a.listener.mu.Lock()
	defer a.listener.mu.Unlock()

	return a.listener.base
}

// SetBase pins the externally-reachable base URL. It refuses to overwrite one
// that is already set, because Listen used to do exactly that in the identity
// provider and silently invalidated every credential it minted.
func (a *Authority) SetBase(base string) {
	a.listener.mu.Lock()
	defer a.listener.mu.Unlock()

	if a.listener.base == "" {
		a.listener.base = base
	}
}

// Listen binds the revocation endpoints. If no base URL has been pinned, the
// listener's own address becomes it, which is right for a test on loopback and
// wrong for a container, hence SetBase.
func (a *Authority) Listen(addr string) error {
	a.listener.mu.Lock()
	defer a.listener.mu.Unlock()

	if a.listener.revocation != nil {
		return fmt.Errorf(
			errAlreadyUp,
			ErrListener,
			a.listener.revocation.Addr(),
		)
	}

	listener, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf(errBindFailed, ErrListener, addr, err)
	}

	server := &http.Server{
		Handler:           a.routes(),
		ReadHeaderTimeout: readHeaderTimeout,
	}

	a.listener.revocation = listener
	a.listener.revSrv = server

	if a.listener.base == "" {
		a.listener.base = schemeHTTP + listener.Addr().String()
	}

	a.listener.wg.Add(1)

	// The goroutine serves the LOCAL, not the field. Reading a.listener.revSrv
	// in here is a data race against shutdown, which nils it under the mutex
	// this goroutine does not hold, and `go test -race` catches it.
	go func() {
		defer a.listener.wg.Done()
		_ = server.Serve(listener)
	}()

	return nil
}

// ListenTLS binds the endpoint where khaos plays the dependency, presenting
// whatever chain is armed. The certificate is resolved per handshake through
// GetCertificate rather than fixed at bind time, so arming a trap takes effect
// on the next connection without the listener moving.
func (a *Authority) ListenTLS(addr string) error {
	a.listener.mu.Lock()
	defer a.listener.mu.Unlock()

	if a.listener.dependency != nil {
		return fmt.Errorf(
			errAlreadyUp,
			ErrListener,
			a.listener.dependency.Addr(),
		)
	}

	listener, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf(errBindFailed, ErrListener, addr, err)
	}

	server := &http.Server{
		Handler:           a.dependencyRoutes(),
		ReadHeaderTimeout: readHeaderTimeout,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: a.getCertificate,

			// Per handshake, so arming an mTLS trap takes effect on the next
			// connection without the listener moving. ClientAuth fixed at bind
			// time would mean those traps could only be armed before the target
			// was ever pointed at khaos, which is not when an experiment arms
			// anything.
			GetConfigForClient: a.configForClient,
		},
	}

	a.listener.dependency = listener
	a.listener.depSrv = server

	a.listener.wg.Add(1)

	// Serves the LOCAL, for the same reason Listen does.
	go func() {
		defer a.listener.wg.Done()
		_ = server.ServeTLS(listener, "", "")
	}()

	return nil
}

// configForClient decides, per handshake, whether khaos demands a client
// certificate.
//
// RequireAndVerifyClientCert specifically, and not VerifyClientCertIfGiven.
// Research 04 measured the whole matrix and that mode is the fail-open trap: it
// rejects a BAD certificate and accepts NONE, so it reads as secure while its
// failure mode is a total authentication bypass. khaos's own server must not be
// the thing being wrong here -- the fault is in the identity it ISSUED, and a
// server that let an identity-less client through would make both mTLS traps
// unobservable.
func (a *Authority) configForClient(
	*tls.ClientHelloInfo,
) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: a.getCertificate,
	}

	if a.RequiresMutualTLS() {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = a.issuingPool()
	}

	return cfg, nil
}

// issuingPool is the CA that signed the target's identity, which is what khaos
// verifies that identity against. It is the real intermediate rather than
// whatever TrustedRoot currently reports, because a CA swap changes what the
// TARGET trusts and has nothing to do with who issued the client.
func (a *Authority) issuingPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.inter.cert)
	pool.AddCert(a.root.cert)

	return pool
}

// getCertificate resolves the armed chain per handshake.
//
// A handshake that arrives with nothing armed is served the honest chain rather
// than refused, because the baseline is measured through this listener and a
// baseline that cannot connect establishes nothing.
func (a *Authority) getCertificate(
	*tls.ClientHelloInfo,
) (*tls.Certificate, error) {
	chain, err := a.Served()
	if err != nil {
		honest, buildErr := a.build(Trap{Kind: PassThrough, Host: a.host})
		if buildErr != nil {
			return nil, buildErr
		}

		certificate := honest.TLS()

		return &certificate, nil
	}

	certificate := chain.TLS()

	return &certificate, nil
}

// Addr is where the revocation endpoints are bound.
func (a *Authority) Addr() (string, error) {
	a.listener.mu.Lock()
	defer a.listener.mu.Unlock()

	if a.listener.revocation == nil {
		return "", fmt.Errorf(errNoListener, ErrListener, "revocation")
	}

	return a.listener.revocation.Addr().String(), nil
}

// TLSAddr is where khaos is playing the dependency.
func (a *Authority) TLSAddr() (string, error) {
	a.listener.mu.Lock()
	defer a.listener.mu.Unlock()

	if a.listener.dependency == nil {
		return "", fmt.Errorf(errNoListener, ErrListener, "the dependency")
	}

	return a.listener.dependency.Addr().String(), nil
}

func (a *Authority) shutdown() error {
	a.listener.mu.Lock()

	servers := []*http.Server{a.listener.revSrv, a.listener.depSrv}
	a.listener.revSrv = nil
	a.listener.depSrv = nil
	a.listener.revocation = nil
	a.listener.dependency = nil

	a.listener.mu.Unlock()

	var failures []error

	for _, server := range servers {
		if server == nil {
			continue
		}

		if err := server.Close(); err != nil {
			failures = append(failures, err)
		}
	}

	a.listener.wg.Wait()

	return errors.Join(failures...)
}

const readHeaderTimeout = 10 * time.Second
