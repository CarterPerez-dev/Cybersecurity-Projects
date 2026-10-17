// ©AngelaMos | 2026
// provider.go

package idp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/bindguard"
)

const (
	RouteDiscovery  = "/.well-known/openid-configuration"
	RouteJWKS       = "/jwks"
	RouteToken      = "/token"
	RouteIntrospect = "/introspect"
	RouteRevoke     = "/revoke"
	RouteHealth     = "/health"

	ParamToken = "token"

	headerContentType = "Content-Type"
	mimeJSON          = "application/json"
	mimeText          = "text/plain"

	// Fixed, not configurable: the target is built with this audience too.
	DefaultAudience = "khaos-range"
	DefaultSubject  = "khaos-operator"

	ForeignAudience = "khaos-range-other"
	ForeignIssuerID = "https://khaos.invalid/second-tenant"

	DefaultLifetime = 10 * time.Minute

	opaquePrefix = "khaos-opaque-"

	malformedBody = "{\"active\": tru"

	shutdownGrace = 2 * time.Second

	// It mints the credentials khaos's own probes present and serves the key
	// set a target resolves them against, so it does not belong on an
	// interface that target cannot reach anyway.
	SubjectProvider = "an identity provider that mints deliberately defective credentials"

	errAlreadyListening = "%w: khaos's identity provider is already listening on %s"
	errNotListening     = "%w: khaos's identity provider is not listening, so it has no address"
	errNoRevocable      = "%w: this run never issued a revocable credential, so there is nothing to revoke"
	errWrongTrap        = "%w: the provider holds %q but %q was expected"
	errUnknownGrant     = "%w: khaos's identity provider never issued %q"
)

var ErrListening = errors.New("khaos's identity provider cannot be bound twice")

var ErrNotListening = errors.New("khaos's identity provider has no listener")

var ErrClosed = errors.New("khaos's identity provider is closed")

var ErrNothingToRevoke = errors.New("khaos has no credential to revoke")

var ErrTrapNotObserved = errors.New(
	"the armed trap did not produce its own observable",
)

var ErrNoSuchGrant = errors.New("that credential was never issued here")

// armedTrap is swapped as one value, so a trap and a generation always agree.
type armedTrap struct {
	trap       Trap
	generation uint64
}

type keySnapshot struct {
	signing *Key
	retired []*Key
}

// Revoking a grant flips active rather than deleting it, so Disarm can undo it.
type grant struct {
	subject string
	active  bool
}

// Provider is khaos's own OIDC-shaped signing oracle, built to emit malformed
// tokens and break its own endpoints on command. It validates VERIFIERS.
type Provider struct {
	audience        string
	foreignAudience string
	foreignIssuer   string
	lifetime        time.Duration

	mu       sync.RWMutex
	issuer   string
	signing  *Key
	retired  []*Key
	foreign  *Key
	stable   *Key
	weak     *Key
	ec       *Key
	attacker *Key
	grants   map[string]*grant
	snapshot *keySnapshot

	// Read at inject time: the probe that issues it has not fired at build.
	revocable string

	state  atomic.Pointer[armedTrap]
	inert  atomic.Bool
	closed chan struct{}
	once   sync.Once

	listener net.Listener
	server   *http.Server
	wg       sync.WaitGroup

	// The accessors report the DIFFERENCE, keeping khaos's probes out of it.
	jwksFetches atomic.Int64
	ownFetches  atomic.Int64

	introspects    atomic.Int64
	ownIntrospects atomic.Int64

	now func() time.Time
}

type Config struct {
	Audience string
	Lifetime time.Duration

	Now func() time.Time
}

// New generates every key up front, so arming a trap is a pointer swap for all
// but the two rotation traps, which mint a fresh key inside Arm.
func New(config Config) (*Provider, error) {
	if config.Audience == "" {
		config.Audience = DefaultAudience
	}
	if config.Lifetime <= 0 {
		config.Lifetime = DefaultLifetime
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}

	signing, err := NewRSAKey()
	if err != nil {
		return nil, err
	}

	foreign, err := NewRSAKey()
	if err != nil {
		return nil, err
	}

	// Published and never rotated: a liveness proof is never new-key traffic.
	stable, err := NewRSAKey()
	if err != nil {
		return nil, err
	}

	// NOT published, ever: the trap's claim is a key never advertised.
	attacker, err := NewRSAKey()
	if err != nil {
		return nil, err
	}

	weak, err := NewWeakRSAKey()
	if err != nil {
		return nil, err
	}

	ec, err := NewECKey()
	if err != nil {
		return nil, err
	}

	p := &Provider{
		audience:        config.Audience,
		foreignAudience: ForeignAudience,
		foreignIssuer:   ForeignIssuerID,
		lifetime:        config.Lifetime,
		signing:         signing,
		foreign:         foreign,
		stable:          stable,
		attacker:        attacker,
		weak:            weak,
		ec:              ec,
		grants:          map[string]*grant{},
		closed:          make(chan struct{}),
		now:             config.Now,
	}

	p.state.Store(&armedTrap{})

	return p, nil
}

func (p *Provider) clock() time.Time {
	return p.now()
}

// Listen binds the address the target was built to address, not khaos's choice.
func (p *Provider) Listen(addr string) error {
	if err := bindguard.Check(addr, SubjectProvider); err != nil {
		return err
	}

	// Guard and bind under ONE acquisition, or two callers both bind and the
	// second orphans the first listener and its goroutine.
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.listener != nil {
		return fmt.Errorf(
			errAlreadyListening,
			ErrListening,
			p.listener.Addr().String(),
		)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler:           p.routes(),
		ReadHeaderTimeout: shutdownGrace,
	}

	p.listener = listener
	p.server = server

	// Only when nothing pinned one. A pinned issuer is the string the TARGET
	// trusts, and khaos's own listener address is never that string.
	if p.issuer == "" {
		p.issuer = "http://" + listener.Addr().String()
	}

	// Inside the lock, so a Listen racing Close cannot add to a waited group.
	p.wg.Add(1)

	go func() {
		defer p.wg.Done()
		_ = server.Serve(listener)
	}()

	return nil
}

func (p *Provider) Issuer() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.issuer
}

// SetIssuer pins the issuer to the value the target was built expecting.
func (p *Provider) SetIssuer(issuer string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.issuer = issuer
}

func (p *Provider) Addr() (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.listener == nil {
		return "", fmt.Errorf(errNotListening, ErrNotListening)
	}

	return p.listener.Addr().String(), nil
}

func (p *Provider) Close() error {
	var err error

	p.once.Do(func() {
		close(p.closed)

		p.mu.RLock()
		server := p.server
		p.mu.RUnlock()

		if server != nil {
			err = server.Close()
		}

		p.wg.Wait()
	})

	return err
}

// Arm swaps the trap in and snapshots the key state Disarm will put back.
func (p *Provider) Arm(trap Trap) error {
	select {
	case <-p.closed:
		return ErrClosed
	default:
	}

	if err := trap.Validate(); err != nil {
		return err
	}

	// Taken even when the arm is inert, or confirmation has nothing to compare.
	p.snap()

	if !p.inert.Load() {
		switch trap.Kind {
		case KidRollover:
			if err := p.rotate(false); err != nil {
				return err
			}
		case KeyRotation:
			if err := p.rotate(true); err != nil {
				return err
			}
		case Revoke:
			if err := p.revoke(trap.Credential); err != nil {
				return err
			}
		default:
			// The token traps hold no provider state; they act at mint time.
		}
	}

	previous := p.state.Load()
	p.state.Store(&armedTrap{trap: trap, generation: previous.generation + 1})

	return nil
}

// snap OVERWRITES rather than keeping the first snapshot of a cycle.
func (p *Provider) snap() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.snapshot = &keySnapshot{
		signing: p.signing,
		retired: append([]*Key{}, p.retired...),
	}
}

// RetiredKid is the key that was signing before the current arming cycle.
func (p *Provider) RetiredKid() (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.snapshot == nil || p.snapshot.signing == nil {
		return "", false
	}

	return p.snapshot.signing.ID, true
}

func (p *Provider) Disarm() {
	previous := p.state.Load()
	p.state.Store(&armedTrap{generation: previous.generation + 1})

	p.restoreKeys()
	p.restoreGrants()
}

func (p *Provider) Trap() Trap {
	return p.state.Load().trap
}

// Inert behaves correctly with a trap armed: the oracle's negative control.
func (p *Provider) Inert(inert bool) {
	p.inert.Store(inert)
}

func (p *Provider) effective() Trap {
	if p.inert.Load() {
		return Trap{}
	}
	return p.Trap()
}

// rotate installs a fresh signing key; with overlap the old one stays live.
func (p *Provider) rotate(overlap bool) error {
	fresh, err := NewRSAKey()
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if overlap {
		p.retired = append(p.retired, p.signing)
	} else {
		p.retired = nil
	}

	p.signing = fresh

	return nil
}

func (p *Provider) restoreKeys() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.snapshot == nil {
		return
	}

	p.signing = p.snapshot.signing
	p.retired = p.snapshot.retired
	p.snapshot = nil
}

// revoke refuses an unknown credential rather than silently succeeding.
func (p *Provider) revoke(credential string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	held, ok := p.grants[credential]
	if !ok {
		return fmt.Errorf(errUnknownGrant, ErrNoSuchGrant, credential)
	}

	held.active = false

	return nil
}

func (p *Provider) restoreGrants() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, held := range p.grants {
		held.active = true
	}
}

// HonestToken is always a correct token, whatever is armed.
func (p *Provider) HonestToken() (string, error) {
	return p.mintToken(
		Trap{},
		grantRequest{subject: DefaultSubject, lifetime: p.lifetime},
	)
}

func (p *Provider) TrappedToken() (string, error) {
	return p.mintToken(
		p.effective(),
		grantRequest{subject: DefaultSubject, lifetime: p.lifetime},
	)
}

// StableToken is signed by a key that is always published and never rotated,
// so a valid stream never supplies the traffic that evicts a retired key.
func (p *Provider) StableToken() (string, error) {
	p.mu.RLock()
	stable := p.stable
	p.mu.RUnlock()

	return p.mintSignedBy(stable)
}

// Opaque issues a credential carrying no claims, so a verifier has to ask.
func (p *Provider) Opaque() string {
	credential := opaquePrefix + rand.Text()

	p.mu.Lock()
	p.grants[credential] = &grant{subject: DefaultSubject, active: true}
	p.mu.Unlock()

	return credential
}

// Revocable issues an opaque credential and records it as this run's target.
func (p *Provider) Revocable() string {
	credential := p.Opaque()

	p.mu.Lock()
	p.revocable = credential
	p.mu.Unlock()

	return credential
}

func (p *Provider) RevocableCredential() (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.revocable == "" {
		return "", fmt.Errorf(errNoRevocable, ErrNothingToRevoke)
	}

	return p.revocable, nil
}

// PublishedSet is every key khaos signs with except the attacker key.
func (p *Provider) PublishedSet() JWKSet {
	p.mu.RLock()
	defer p.mu.RUnlock()

	set := JWKSet{Keys: make([]JWK, 0, len(p.retired)+4)}
	set.Keys = append(set.Keys, p.signing.PublicJWK())

	for _, key := range p.retired {
		set.Keys = append(set.Keys, key.PublicJWK())
	}

	set.Keys = append(
		set.Keys,
		p.foreign.PublicJWK(),
		p.stable.PublicJWK(),
		p.weak.PublicJWK(),
		p.ec.PublicJWK(),
	)

	return set
}

func (p *Provider) SigningKid() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.signing.ID
}

// JWKSFetches is how many times something OTHER than khaos fetched the key set.
func (p *Provider) JWKSFetches() int64 {
	return p.jwksFetches.Load() - p.ownFetches.Load()
}

func (p *Provider) Introspections() int64 {
	return p.introspects.Load() - p.ownIntrospects.Load()
}
