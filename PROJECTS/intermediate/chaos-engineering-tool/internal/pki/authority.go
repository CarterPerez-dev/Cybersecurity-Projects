// ©AngelaMos | 2026
// authority.go

package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	nameRoot        = "khaos chaos root"
	nameInter       = "khaos chaos intermediate"
	nameRogueRoot   = "khaos rogue root"
	nameRogueInter  = "khaos rogue intermediate"
	nameConstrained = "khaos constrained intermediate"
	nameEKULimited  = "khaos client-auth-only intermediate"
	nameNotACA      = "khaos issuer that is not a CA"
	nameDeepInter   = "khaos over-deep intermediate"
	nameUndelegated = "khaos undelegated responder"

	constrainedDomain = "constrained.khaos.invalid"

	foreignHost = "not-the-host-you-asked-for.khaos.invalid"

	caYears = 10

	errNoTrap   = "%w: nothing is armed, so there is no chain to serve"
	errArmTrap  = "%w: %v"
	errBuildFor = "%w: building a chain for %s: %v"
)

var (
	// ErrNothingArmed is a request for the served chain while behaving correctly.
	ErrNothingArmed = errors.New(
		"khaos's certificate authority has no fault armed",
	)

	// ErrTrapNotObserved aborts the run: a measurement under a fault that may
	// not have landed is no evidence.
	ErrTrapNotObserved = errors.New(
		"khaos could not confirm its own certificate fault landed",
	)
)

type Config struct {
	Host string

	Now func() time.Time
}

// Authority is a CA deliberately willing to be wrong, one named way at a time.
type Authority struct {
	mu sync.RWMutex

	clock func() time.Time
	host  string

	root  *pair
	inter *pair

	rogueRoot  *pair
	rogueInter *pair

	constrained *pair
	ekuLimited  *pair
	notACA      *pair
	undelegated *pair

	// deepCapped has MaxPathLen zero, and BOTH are presented: with only
	// deepInter the client cannot reach the root and Go blames the authority.
	deepInter  *pair
	deepCapped *pair

	trap  Trap
	armed *Chain

	clientID *pair
	mutual   bool

	// BUILT state: UntrustedCA and CASwap build the identical chain.
	swapped bool

	// The only way to hand the confirmation oracle an input it MUST reject.
	inert atomic.Bool

	// What the TARGET asked for, with khaos's own probes counted apart.
	crlFetches  atomic.Int64
	ocspQueries atomic.Int64
	ownCRL      atomic.Int64
	ownOCSP     atomic.Int64

	listener  listenerState
	closeOnce sync.Once
	closed    chan struct{}
}

// New builds every CA and intermediate up front, so the issuer hierarchy a trap
// needs is already there when it is armed. The LEAF key is still generated per
// arm, which is why Trap.Validate refuses a size crypto/rsa would reject.
func New(cfg Config) (*Authority, error) {
	a := &Authority{
		clock:  cfg.Now,
		host:   cfg.Host,
		closed: make(chan struct{}),
	}

	if a.clock == nil {
		a.clock = time.Now
	}

	if a.host == "" {
		a.host = DefaultHost
	}

	if err := a.buildHierarchies(); err != nil {
		return nil, err
	}

	if err := a.buildSpecialIssuers(); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *Authority) buildHierarchies() error {
	now := a.clock()
	from := now.Add(-clockSlack)
	until := now.AddDate(caYears, 0, 0)

	var err error

	if a.root, err = a.mintCA(nameRoot, nil, from, until); err != nil {
		return err
	}

	if a.inter, err = a.mintCA(nameInter, a.root, from, until); err != nil {
		return err
	}

	if a.rogueRoot, err = a.mintCA(
		nameRogueRoot,
		nil,
		from,
		until,
	); err != nil {
		return err
	}

	a.rogueInter, err = a.mintCA(nameRogueInter, a.rogueRoot, from, until)

	return err
}

func (a *Authority) buildSpecialIssuers() error {
	now := a.clock()
	from := now.Add(-clockSlack)
	until := now.AddDate(caYears, 0, 0)

	if err := a.buildConstrained(from, until); err != nil {
		return err
	}

	if err := a.buildEKULimited(from, until); err != nil {
		return err
	}

	if err := a.buildNotACA(from, until); err != nil {
		return err
	}

	if err := a.buildDeepInter(from, until); err != nil {
		return err
	}

	return a.buildResponders(from, until)
}

func (a *Authority) mintCA(
	name string,
	parent *pair,
	from, until time.Time,
) (*pair, error) {
	template, err := caTemplate(name, from, until)
	if err != nil {
		return nil, err
	}

	key, err := newKey(StrongBits)
	if err != nil {
		return nil, err
	}

	return issue(template, parent, key)
}

func (a *Authority) Host() string {
	return a.host
}

// TrustedRoot is the anchor the TARGET holds, and CASwap is what moves it.
func (a *Authority) TrustedRoot() *x509.Certificate {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.swapped {
		return a.rogueRoot.cert
	}

	return a.root.cert
}

func (a *Authority) TrustedPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.TrustedRoot())

	return pool
}

// Arm applies a trap and mints the chain HERE rather than per handshake, so a
// leaf is not re-minted with a new serial while revocation names the old one.
func (a *Authority) Arm(trap Trap) error {
	if err := trap.Validate(); err != nil {
		return fmt.Errorf(errArmTrap, ErrInvalidTrap, err)
	}

	// An inert authority RECORDS the trap and builds nothing, so the oracle
	// still reaches its observable.
	if a.inert.Load() {
		a.mu.Lock()
		defer a.mu.Unlock()

		a.trap = trap

		return nil
	}

	chain, err := a.build(trap)
	if err != nil {
		return err
	}

	identity, err := a.mintClientIdentity(trap, a.clock())
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.trap = trap
	a.armed = chain
	a.swapped = trap.Kind == CASwap
	a.clientID = identity
	a.mutual = trap.Kind == ClientCertExpired ||
		trap.Kind == ClientCertAbsent

	return nil
}

// Disarm re-mints an honest chain, so recovery is measured through a working
// authority.
func (a *Authority) Disarm() error {
	honest, err := a.build(Trap{Kind: PassThrough, Host: a.host})
	if err != nil {
		return err
	}

	identity, err := a.mintClientIdentity(
		Trap{Kind: PassThrough},
		a.clock(),
	)
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.trap = Trap{}
	a.armed = honest
	a.swapped = false
	a.clientID = identity
	a.mutual = false

	return nil
}

func (a *Authority) Inert(on bool) {
	a.inert.Store(on)
}

func (a *Authority) Trap() Trap {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.trap
}

func (a *Authority) Served() (*Chain, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.armed == nil {
		return nil, fmt.Errorf(errNoTrap, ErrNothingArmed)
	}

	return a.armed, nil
}

// CRLFetches and OCSPQueries report what the TARGET did, probes subtracted.
func (a *Authority) CRLFetches() int64 {
	return a.crlFetches.Load() - a.ownCRL.Load()
}

func (a *Authority) OCSPQueries() int64 {
	return a.ocspQueries.Load() - a.ownOCSP.Load()
}

func (a *Authority) Close() error {
	a.closeOnce.Do(func() { close(a.closed) })

	return a.shutdown()
}
