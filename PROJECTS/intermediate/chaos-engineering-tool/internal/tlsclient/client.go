// ©AngelaMos | 2026
// client.go

package tlsclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"time"
)

const (
	network = "tcp"

	// MinimumModulusBits is khaos's reference key floor. x509 path validation
	// has NO minimum of its own -- crypto/tls has a maximum of 8192 as the fix
	// for CVE-2023-29409, and neither package has a floor -- so this is a policy
	// the application imposes or nobody does.
	MinimumModulusBits = 2048

	// MaximumLifetimeDays is the CA/Browser Forum leaf cap. Nothing outside a
	// browser enforces it.
	MaximumLifetimeDays = 200

	// DefaultTimeout bounds both the handshake and every revocation fetch. A
	// client with no timeout cannot distinguish a slow responder from a dead
	// one, and that distinction is a fault in its own right.
	DefaultTimeout = 5 * time.Second
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

// Config aims a reference client at one dependency.
type Config struct {
	// Mode decides which checks this client performs. Correct performs all of
	// them.
	Mode Mode

	// Host is the name the client asks for and expects to be in the
	// certificate.
	Host string

	// Roots is what the client trusts. For the trust-store faults this is the
	// thing khaos changed.
	Roots *x509.CertPool

	// Timeout bounds the handshake and every revocation fetch.
	Timeout time.Duration

	// Now overrides the clock, so a freshness assertion does not race a real
	// one.
	Now func() time.Time
}

// Client is khaos's reference TLS client: what a correct consumer of a
// dependency's certificate does, and eleven named ways of doing it wrong.
//
// It is a teaching artifact as much as a test fixture. The Correct path is the
// code a reader should copy, which is why it performs the whole six-step CRL
// check rather than the two steps that are usually written.
type Client struct {
	mode    Mode
	host    string
	roots   *x509.CertPool
	timeout time.Duration
	clock   func() time.Time

	http *http.Client
}

// New builds a client. Every field has a working default except the mode and
// the host, because a client with no trust anchors and no name is not a client
// that can decide anything.
func New(cfg Config) *Client {
	c := &Client{
		mode:    cfg.Mode,
		host:    cfg.Host,
		roots:   cfg.Roots,
		timeout: cfg.Timeout,
		clock:   cfg.Now,
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

// Mode is which client this is.
func (c *Client) Mode() Mode {
	return c.mode
}

// Decision is one client's answer about one dependency.
type Decision struct {
	// Accepted is whether the client was willing to use the dependency.
	Accepted bool

	// Reason is why it refused, empty when it accepted. It is for a human
	// reading a khaos run, and tests assert on Accepted rather than on this.
	Reason string

	// AskedCRL and AskedOCSP record whether the client actually went and
	// looked. A client that accepted WITHOUT asking is a different finding from
	// one that asked and was satisfied, and only these fields separate them.
	AskedCRL  bool
	AskedOCSP bool
}

// Decide connects to addr and reports whether this client was willing to use
// what it found there.
//
// The handshake and the policy are deliberately separate. crypto/tls is left to
// do the chain, the hostname and the validity window, because khaos
// re-implementing those would mean khaos's own bugs showing up as findings
// about the target. What this adds afterwards is only the layer Go does not
// have.
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

// handshake performs the TLS exchange under this mode's verification settings.
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

	// The handshake has already completed by the time DialContext returns, but
	// under TLS 1.3 a server's rejection of a CLIENT certificate surfaces only
	// on the first read. khaos does not use client certificates here, so this
	// state is final; research 04 section 7.2 covers the case where it is not.
	return tlsConn.ConnectionState(), nil
}

func (c *Client) tlsConfig() *tls.Config {
	cfg := &tls.Config{
		ServerName: c.host,
		RootCAs:    c.roots,
		MinVersion: tls.VersionTLS12,
	}

	if !c.mode.checksChain() {
		// InsecureSkipVerify in one assignment turns off the chain, the name
		// and the validity window together. That breadth is the reason it is
		// the most common fail-open in real code.
		cfg.InsecureSkipVerify = true

		return cfg
	}

	if !c.mode.checksHostname() {
		// The chain is still checked, by hand, with the name left out. Go has
		// no setting for this, which is why a client that wants it has to
		// reimplement verification and usually gets something else wrong too.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = c.verifyWithoutName

		return cfg
	}

	if c.mode == TrustPresentedCA {
		// Anchoring on whatever arrived accepts any self-consistent chain,
		// including one minted by anybody at all.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = c.verifyAgainstPresented

		return cfg
	}

	return cfg
}

// verifyWithoutName does the full path check and omits the hostname, which is
// the SkipHostname fault.
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

// verifyAgainstPresented anchors on the chain the server sent, which is the
// TrustPresentedCA fault.
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

// issuerOf is whichever certificate signed the leaf, taken from the verified
// chain where there is one and from the presented chain otherwise. Revocation
// needs it to check a CRL signature or an OCSP response.
func (c *Client) issuerOf(state tls.ConnectionState) *x509.Certificate {
	for _, chain := range state.VerifiedChains {
		if len(chain) > 1 {
			return chain[1]
		}
	}

	if len(state.PeerCertificates) > 1 {
		return state.PeerCertificates[1]
	}

	// A self-signed leaf is its own issuer, which is the honest answer rather
	// than nil: a revocation question about it is still answerable.
	return state.PeerCertificates[0]
}

// policy is the pair of checks crypto/x509 does not have. A mode without them
// is not breaking any rule Go enforces, which is exactly why the traps they
// catch are the ones that reveal whether a target has a policy of its own.
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
		// used for a TLS handshake. Verify enforces EXTENDED key usage and
		// never reads these bits, so this check exists in the application or
		// nowhere.
		return reasonNoSigningUse, false
	}

	return reasonAccepted, true
}
