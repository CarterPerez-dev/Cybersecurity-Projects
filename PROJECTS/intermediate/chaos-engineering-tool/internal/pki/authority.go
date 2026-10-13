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

	// constrainedDomain is what the name-constrained CA is permitted to issue
	// for. Anything else trips Reason 2, which is the fault.
	constrainedDomain = "constrained.khaos.invalid"

	// foreignHost is the name WrongSAN puts in the certificate instead of the
	// one the client asked for.
	foreignHost = "not-the-host-you-asked-for.khaos.invalid"

	caYears = 10

	errNoTrap   = "%w: nothing is armed, so there is no chain to serve"
	errArmTrap  = "%w: %v"
	errBuildFor = "%w: building a chain for %s: %v"
)

var (
	// ErrNothingArmed is a request for the served chain while the authority is
	// behaving correctly and no trap has been armed.
	ErrNothingArmed = errors.New(
		"khaos's certificate authority has no fault armed",
	)

	// ErrTrapNotObserved is khaos failing to confirm its OWN fault. It is
	// deliberately loud: an unconfirmed fault means the run must not proceed,
	// because a measurement under a fault that may not have landed is not
	// evidence about the target.
	ErrTrapNotObserved = errors.New(
		"khaos could not confirm its own certificate fault landed",
	)
)

// Config is how a caller aims the authority. Every field has a working default,
// because an authority that needs configuring before it can serve an honest
// certificate would make the baseline the hard case.
type Config struct {
	// Host is the name honest certificates are minted for.
	Host string

	// Now overrides the clock, for tests that need a deterministic validity
	// window rather than one relative to a real wall clock.
	Now func() time.Time
}

// Authority is khaos's in-process certificate authority: a CA deliberately
// willing to be wrong, in one named way at a time.
//
// It exists because no correct CA will mint an expired, revoked or
// wrongly-named certificate at any price, and those are precisely the
// certificates this family needs. The same argument that justified the in-
// process identity provider for tokens justifies this for chains.
type Authority struct {
	mu sync.RWMutex

	clock func() time.Time
	host  string

	// The hierarchy the target is configured to trust.
	root  *pair
	inter *pair

	// A second, complete hierarchy khaos also controls. UntrustedCA serves a
	// leaf under it while the target still trusts the first; CASwap makes this
	// one the root the target trusts, which is the CA-compromise scenario and
	// the one fault nothing in a client can detect.
	rogueRoot  *pair
	rogueInter *pair

	// Purpose-built issuers, minted once at construction so that arming a trap
	// is cheap, deterministic, and cannot fail for a reason unrelated to the
	// fault.
	constrained *pair
	ekuLimited  *pair
	notACA      *pair
	undelegated *pair

	// deepInter sits under deepCapped, whose MaxPathLen is zero. BOTH have to
	// be presented in the handshake: a client given only deepInter cannot reach
	// the root at all, and the fault then reads as an unknown authority rather
	// than the path-length violation it is. That is measured, not theorised --
	// the first draft presented one and the differential caught it.
	deepInter  *pair
	deepCapped *pair

	trap  Trap
	armed *Chain

	// clientID is the identity khaos has issued to the TARGET, for the mutual
	// TLS traps, and mutual is whether khaos demands one. Both are minted and
	// set at arm time like everything else the authority serves, so an inert
	// authority keeps handing out the honest identity and keeps not demanding
	// anything.
	clientID *pair
	mutual   bool

	// swapped is BUILT state, not derived from the trap, and the distinction is
	// what makes the confirmation oracle honest.
	//
	// UntrustedCA and CASwap build the IDENTICAL chain under the rogue
	// hierarchy; the only difference between them is what the target trusts. So
	// the trusted root cannot come from the chain, and reading it off trap.Kind
	// instead meant an INERT authority -- one that records a trap and builds
	// nothing -- would report the swap as confirmed. The oracle's negative
	// control would have been passing against a fault that never happened.
	swapped bool

	// inert makes every arming a no-op while still reporting success. It is the
	// NEGATIVE CONTROL for the confirmation oracle: without a way to make the
	// authority refuse to misbehave, a gutted Observe that always says yes
	// leaves the whole suite green. The identity family learned this the
	// expensive way.
	inert atomic.Bool

	// crlFetches and ocspQueries count what the TARGET asked for. khaos's own
	// confirmation probes are counted separately and subtracted, or khaos would
	// be measuring itself.
	crlFetches  atomic.Int64
	ocspQueries atomic.Int64
	ownCRL      atomic.Int64
	ownOCSP     atomic.Int64

	listener  listenerState
	closeOnce sync.Once
	closed    chan struct{}
}

// New builds the authority and every CA it will ever need. All of the minting
// happens here rather than at arm time, so a trap that cannot be armed is a
// real fault in the trap and never a key generation that happened to fail
// mid-experiment.
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

// mintCA is the one path every CA in this package comes from, so a defect in
// CA construction cannot differ between the honest hierarchy and a trap's.
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

// Host is the name honest certificates are minted for.
func (a *Authority) Host() string {
	return a.host
}

// TrustedRoot is the anchor the TARGET is configured with. CASwap is the one
// trap that changes what this returns, which is exactly why the trap works.
func (a *Authority) TrustedRoot() *x509.Certificate {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.swapped {
		return a.rogueRoot.cert
	}

	return a.root.cert
}

// TrustedPool is TrustedRoot as a pool, which is what a client actually needs.
func (a *Authority) TrustedPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.TrustedRoot())

	return pool
}

// Arm applies a trap and mints the chain it will serve. The chain is built HERE
// rather than per handshake so that every handshake in one experiment presents
// the same certificate: a leaf re-minted per connection would get a new serial
// each time, and a revocation answer about a serial the client is no longer
// holding is not a fault, it is khaos racing itself.
func (a *Authority) Arm(trap Trap) error {
	if err := trap.Validate(); err != nil {
		return fmt.Errorf(errArmTrap, ErrInvalidTrap, err)
	}

	// An inert authority RECORDS the trap and builds nothing. Recording it is
	// deliberate: it makes the confirmation oracle run its real observable
	// against honest material, rather than short-circuiting on the
	// wrong-trap-armed guard and never reaching the branch under test.
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

// Disarm returns the authority to behaving correctly and re-mints an honest
// chain, so the recovery window is measured through a working authority rather
// than through no authority at all.
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

// Inert makes arming a no-op that still reports success, which is the only way
// to give the confirmation oracle an input it MUST reject.
func (a *Authority) Inert(on bool) {
	a.inert.Store(on)
}

// Trap is what is currently armed.
func (a *Authority) Trap() Trap {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.trap
}

// Served is the chain the authority is presenting right now.
func (a *Authority) Served() (*Chain, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.armed == nil {
		return nil, fmt.Errorf(errNoTrap, ErrNothingArmed)
	}

	return a.armed, nil
}

// CRLFetches and OCSPQueries report what the TARGET did, with khaos's own
// confirmation probes subtracted. A count that included khaos's probes would
// make "the target checked revocation" true for every run.
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
