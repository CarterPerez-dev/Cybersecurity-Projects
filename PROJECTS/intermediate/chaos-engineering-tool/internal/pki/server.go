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

	"github.com/CarterPerez-dev/khaos/internal/bindguard"
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

	// Each listener names what it is, because one sentinel now serves every
	// listener khaos opens and a refusal has to say which was about to be
	// exposed. The CA signs for one hostname and the revocation endpoint
	// decides whether a certificate is still good, so neither belongs on an
	// interface the target under test cannot reach anyway.
	SubjectRevocation = "a certificate authority's revocation endpoint"
	SubjectDependency = "a dependency khaos presents deliberately broken certificates on"

	errNoListener = "%w: the authority is not listening, so %s cannot be reached"
	errBindFailed = "%w: binding %q: %v"
	errAlreadyUp  = "%w: the authority is already listening on %s"
)

var ErrListener = errors.New("khaos's certificate authority listener")

// Two listeners, because the revocation endpoints have to stay reachable while
// the TLS certificate is broken, or every revocation fault is also an outage.
type listenerState struct {
	mu sync.Mutex

	revocation net.Listener
	revSrv     *http.Server

	dependency net.Listener
	depSrv     *http.Server

	base string
	wg   sync.WaitGroup
}

// Configured, not derived from the listener: khaos binds the Docker bridge
// gateway while the target addresses `host.docker.internal`.
func (a *Authority) Base() string {
	a.listener.mu.Lock()
	defer a.listener.mu.Unlock()

	return a.listener.base
}

func (a *Authority) SetBase(base string) {
	a.listener.mu.Lock()
	defer a.listener.mu.Unlock()

	if a.listener.base == "" {
		a.listener.base = base
	}
}

func (a *Authority) Listen(addr string) error {
	if err := bindguard.Check(addr, SubjectRevocation); err != nil {
		return err
	}

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

	// Serves the LOCAL, not the field: reading a.listener.revSrv here races
	// shutdown, which nils it under a mutex this goroutine does not hold.
	go func() {
		defer a.listener.wg.Done()
		_ = server.Serve(listener)
	}()

	return nil
}

// ListenTLS binds the endpoint where khaos plays the dependency. The
// certificate is resolved per handshake rather than fixed at bind time, so
// arming takes effect on the next connection.
func (a *Authority) ListenTLS(addr string) error {
	if err := bindguard.Check(addr, SubjectDependency); err != nil {
		return err
	}

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

			// Per handshake too, so an mTLS trap can be armed later.
			GetConfigForClient: a.configForClient,
		},
	}

	a.listener.dependency = listener
	a.listener.depSrv = server

	a.listener.wg.Add(1)

	go func() {
		defer a.listener.wg.Done()
		_ = server.ServeTLS(listener, "", "")
	}()

	return nil
}

// RequireAndVerifyClientCert, not VerifyClientCertIfGiven: that mode rejects a
// BAD certificate and accepts NONE, which would be khaos itself failing open.
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

func (a *Authority) issuingPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.inter.cert)
	pool.AddCert(a.root.cert)

	return pool
}

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

func (a *Authority) Addr() (string, error) {
	a.listener.mu.Lock()
	defer a.listener.mu.Unlock()

	if a.listener.revocation == nil {
		return "", fmt.Errorf(errNoListener, ErrListener, "revocation")
	}

	return a.listener.revocation.Addr().String(), nil
}

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
