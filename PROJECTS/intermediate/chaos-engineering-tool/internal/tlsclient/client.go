// ©AngelaMos | 2026
// client.go

package tlsclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	network = "tcp"

	// x509 has no minimum of its own and crypto/tls only a maximum of 8192,
	// the fix for CVE-2023-29409, so a floor is the application's or nobody's.
	MinimumModulusBits = 2048

	// The CA/Browser Forum leaf cap, which nothing outside a browser enforces.
	MaximumLifetimeDays = 200

	DefaultTimeout = 5 * time.Second

	probeRequest = "GET / HTTP/1.1\r\nHost: khaos.probe\r\nConnection: close\r\n\r\n"
)

const (
	reasonAccepted   = ""
	reasonHandshake  = "the handshake failed: "
	reasonNoChain    = "the server presented no certificate"
	reasonWeakKey    = "the leaf's key is below the configured floor"
	reasonLongLife   = "the leaf's lifetime exceeds the configured maximum"
	reasonRevoked    = "the certificate is revoked"
	reasonNoAnswer   = "no usable revocation answer was obtained"
	reasonStaleCRL   = "the CRL's freshness window has closed"
	reasonStaleOCSP  = "the OCSP response's freshness window has closed"
	reasonBadCRLSig  = "the CRL is not signed by the certificate's issuer"
	reasonOCSPStatus = "the responder did not say the certificate is good"
	reasonBadStaple  = "the stapled response is not a usable OCSP response"

	reasonNoSigningUse = "the leaf's KeyUsage does not permit digital signatures"
)

type Config struct {
	Mode Mode

	Host string

	Roots *x509.CertPool

	Timeout time.Duration

	Now func() time.Time

	// Identity is the CLIENT certificate, and nil is a fault khaos can inject.
	Identity *tls.Certificate

	// Sessions has to be SHARED across connections: a cache created per
	// connection resumes nothing, and resumption is the thing under test.
	Sessions tls.ClientSessionCache
}

type Client struct {
	mode    Mode
	host    string
	roots   *x509.CertPool
	timeout time.Duration
	clock   func() time.Time

	identity *tls.Certificate
	sessions tls.ClientSessionCache

	http *http.Client
}

func New(cfg Config) *Client {
	c := &Client{
		mode:     cfg.Mode,
		host:     cfg.Host,
		roots:    cfg.Roots,
		timeout:  cfg.Timeout,
		clock:    cfg.Now,
		identity: cfg.Identity,
		sessions: cfg.Sessions,
	}

	if c.mode == "" {
		c.mode = Correct
	}

	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}

	if c.clock == nil {
		c.clock = time.Now
	}

	c.http = &http.Client{Timeout: c.timeout}

	return c
}

func (c *Client) Mode() Mode {
	return c.mode
}

type Decision struct {
	Accepted bool

	Reason string

	// Accepting WITHOUT asking is a different finding from asking and being
	// satisfied, and only these two fields separate them.
	AskedCRL  bool
	AskedOCSP bool

	// Resumed, or the resumption fault is unattributable.
	Resumed bool
}

// Decide leaves the chain, the hostname and the validity window to crypto/tls,
// because khaos re-implementing those turns khaos's bugs into findings.
func (c *Client) Decide(
	ctx context.Context,
	addr string,
) Decision {
	state, err := c.handshake(ctx, addr)
	if err != nil {
		return Decision{Reason: reasonHandshake + err.Error()}
	}

	if len(state.PeerCertificates) == 0 {
		return Decision{Reason: reasonNoChain}
	}

	leaf := state.PeerCertificates[0]
	issuer := c.issuerOf(state)

	if reason, ok := c.policy(leaf); !ok {
		return Decision{Reason: reason}
	}

	return c.revocation(ctx, leaf, issuer, state)
}

func (c *Client) handshake(
	ctx context.Context,
	addr string,
) (tls.ConnectionState, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: c.timeout},
		Config:    c.tlsConfig(),
	}

	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}

	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, errors.New("not a TLS connection")
	}

	state := tlsConn.ConnectionState()

	// Every probe reads: under TLS 1.3 a server's rejection of the client
	// certificate does NOT surface at Dial, only on the first read.
	if c.mode.reads() {
		if err := readOnce(tlsConn, c.timeout); err != nil {
			return tls.ConnectionState{}, err
		}
	}

	return state, nil
}

func readOnce(conn *tls.Conn, timeout time.Duration) error {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}

	if _, err := io.WriteString(conn, probeRequest); err != nil {
		return err
	}

	buffer := make([]byte, 1)

	// io.EOF is NOT success: a server that rejected the handshake and closed
	// reads as a clean EOF, which is the same fail-open one level down.
	if _, err := conn.Read(buffer); err != nil {
		return err
	}

	return nil
}

func (c *Client) tlsConfig() *tls.Config {
	cfg := &tls.Config{
		ServerName: c.host,
		RootCAs:    c.roots,
		MinVersion: tls.VersionTLS12,
	}

	if c.identity != nil {
		cfg.Certificates = []tls.Certificate{*c.identity}
	}

	// Only a mode that declares it reuses sessions gets a cache.
	if c.mode.resumes() && c.sessions != nil {
		cfg.ClientSessionCache = c.sessions
	}

	if !c.mode.checksChain() {
		cfg.InsecureSkipVerify = true

		return cfg
	}

	if !c.mode.checksHostname() {
		// Go has no setting for this, so it is reimplemented by hand.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = c.verifyWithoutName

		return cfg
	}

	if c.mode == TrustPresentedCA {
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = c.verifyAgainstPresented

		return cfg
	}

	return cfg
}

func (c *Client) verifyWithoutName(
	raw [][]byte,
	_ [][]*x509.Certificate,
) error {
	leaf, pool, err := parseChain(raw)
	if err != nil {
		return err
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         c.roots,
		Intermediates: pool,
		CurrentTime:   c.clock(),
	})

	return err
}

func (c *Client) verifyAgainstPresented(
	raw [][]byte,
	_ [][]*x509.Certificate,
) error {
	leaf, pool, err := parseChain(raw)
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()

	for _, der := range raw {
		cert, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return parseErr
		}

		roots.AddCert(cert)
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		DNSName:       c.host,
		CurrentTime:   c.clock(),
	})

	return err
}

func parseChain(raw [][]byte) (
	*x509.Certificate,
	*x509.CertPool,
	error,
) {
	if len(raw) == 0 {
		return nil, nil, errors.New(reasonNoChain)
	}

	leaf, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return nil, nil, err
	}

	pool := x509.NewCertPool()

	for _, der := range raw[1:] {
		cert, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return nil, nil, parseErr
		}

		pool.AddCert(cert)
	}

	return leaf, pool, nil
}

func (c *Client) issuerOf(state tls.ConnectionState) *x509.Certificate {
	for _, chain := range state.VerifiedChains {
		if len(chain) > 1 {
			return chain[1]
		}
	}

	if len(state.PeerCertificates) > 1 {
		return state.PeerCertificates[1]
	}

	return state.PeerCertificates[0]
}

// policy is the checks crypto/x509 does not have.
func (c *Client) policy(leaf *x509.Certificate) (string, bool) {
	if c.mode.checksKeyFloor() {
		if bits, ok := modulusBits(leaf); ok &&
			bits < MinimumModulusBits {
			return reasonWeakKey, false
		}
	}

	if c.mode.checksLifetime() {
		lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
		if lifetime > time.Duration(MaximumLifetimeDays)*24*time.Hour {
			return reasonLongLife, false
		}
	}

	if c.mode.checksKeyUsage() &&
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		// RFC 5280 section 4.2.1.3: a leaf without digitalSignature cannot be
		// used for TLS, and Verify never reads these bits, only extended ones.
		return reasonNoSigningUse, false
	}

	return reasonAccepted, true
}
