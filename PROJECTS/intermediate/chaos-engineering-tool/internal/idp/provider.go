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

	// DefaultAudience and DefaultSubject are what khaos's provider puts in every
	// honest token. They are constants rather than parameters because the target
	// has to be configured with the same audience at container creation, and a
	// knob on both ends that must agree is a knob that will disagree.
	DefaultAudience = "khaos-range"
	DefaultSubject  = "khaos-operator"

	// ForeignAudience and ForeignIssuer are the second tenant. The wrong-audience
	// and foreign-issuer traps address tokens to these, and a verifier that
	// accepts either has stopped treating its own identity as a constraint.
	ForeignAudience = "khaos-range-other"
	ForeignIssuerID = "https://khaos.invalid/second-tenant"

	// DefaultLifetime is long enough that no run expires a token it is using and
	// short enough to be a plausible access-token lifetime.
	DefaultLifetime = 10 * time.Minute

	opaquePrefix = "khaos-opaque-"

	malformedBody = "{\"active\": tru"

	shutdownGrace = 2 * time.Second

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

// armedTrap is the whole mutable fault state, swapped as one value so a handler
// can never read a trap from one revert and a generation from another. It is the
// same discipline the fault proxy uses, and for the same reason: arming has to
// be indivisible or a probe can observe a half-applied fault.
type armedTrap struct {
	trap       Trap
	generation uint64
}

// keySnapshot is the key state as it stood before a rotating trap was armed.
// Reverting restores it, so the recovery phase measures the provider the
// baseline measured rather than a provider the fault permanently changed.
type keySnapshot struct {
	signing *Key
	retired []*Key
}

// grant is one opaque credential the provider issued. Introspection answers from
// these, and revoking one flips active rather than deleting it, so a revert can
// put it back and the recovery phase means something.
type grant struct {
	subject string
	active  bool
}

// Provider is khaos's own OIDC-shaped identity provider: a programmable signing
// oracle with a JWK Set, an introspection endpoint and a kill switch.
//
// It is hand-built rather than adopted, and research 07 section 4.2 is blunt
// about why: ten of the traps need a provider that will deliberately emit a
// malformed token, and four more need it to break its own endpoints on command
// and report how many times it was fetched. A correct provider does none of
// that, and that is not a gap in Keycloak or Dex, it is the definition of their
// being correct.
//
// The cost is stated out loud: this is not a conformance-tested OP and khaos
// must never claim it validates OIDC conformance. It validates VERIFIERS.
//
// Minting needs no listener, which is what lets an experiment build its probes
// before khaos has discovered the address the target is already addressing.
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

	// revocable is the credential THIS run intends to revoke. The mutator reads
	// it at inject time rather than at build time, because the probe that issues
	// it has not fired yet when the experiment is built.
	revocable string

	state  atomic.Pointer[armedTrap]
	inert  atomic.Bool
	closed chan struct{}
	once   sync.Once

	listener net.Listener
	server   *http.Server
	wg       sync.WaitGroup

	// jwksFetches counts every fetch of the key set, and ownFetches counts the
	// subset khaos's own confirmation probes made. The accessor reports the
	// difference, because this number is the measurement research 07 requirement
	// R5 exists for — how often a verifier refetches, which no third-party
	// provider exposes — and khaos's instrumentation must not appear in the
	// measurement khaos is taking.
	//
	// Subtracting is used rather than a header the handler skips, because a
	// header is spoofable and the arithmetic is not.
	jwksFetches atomic.Int64
	ownFetches  atomic.Int64

	// The same arrangement for introspection. This counter is not decoration:
	// three experiments fault the introspection endpoint, and without a way to
	// see that the target ever CALLED it they can only report that the target
	// survived a fault it never experienced.
	introspects    atomic.Int64
	ownIntrospects atomic.Int64

	now func() time.Time
}

type Config struct {
	Audience string
	Lifetime time.Duration

	// Now is the clock. Tests control it so a claim trap can be asserted against
	// a known instant rather than against whatever the wall clock said.
	Now func() time.Time
}

// New builds a provider with every key it might ever sign with, and no listener.
// All five keys are generated up front so arming a trap is a pointer swap rather
// than a key generation, which keeps the fault indivisible.
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

	// Published, and never rotated. It exists so an experiment that measures key
	// ROTATION can still prove the target is serving without the proof itself
	// disturbing what is being measured: a control token under the current
	// signing key becomes new-key traffic the moment the key rotates, and that
	// traffic is exactly what evicts the retired key.
	stable, err := NewRSAKey()
	if err != nil {
		return nil, err
	}

	// NOT published, ever. The whole claim of the embedded-key trap is that the
	// verifier resolved a key the provider never advertised, so publishing this
	// one would make an acceptance unremarkable.
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

// Listen binds the provider where the target is already looking for it. The
// address is not khaos's choice: the verifier gateway's environment is fixed at
// container creation, so khaos binds the port that container is addressing
// rather than one khaos would have picked.
func (p *Provider) Listen(addr string) error {
	// The guard and the bind are under ONE lock acquisition. Releasing between
	// them let two concurrent calls both pass the guard and both bind, with the
	// second orphaning the first listener and its goroutine. Holding the lock
	// across net.Listen is fine: it is a local syscall, not a round trip, and
	// nothing else can usefully run until the provider has an address.
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

	// Only when nothing pinned one. An explicitly set issuer is the string the
	// TARGET was configured to trust, and the address khaos listens on is never
	// that string: khaos binds the bridge gateway's numeric address while the
	// container addresses `host.docker.internal`.
	//
	// Overwriting it here minted every token with `iss` set to khaos's own
	// listener, and the target refused all of them on the issuer check. The
	// symptom was `baseline-not-met / "the valid credential was never accepted"`,
	// which reads as a broken target rather than as khaos sending the wrong
	// thing, and no unit test saw it because a test that reads Issuer() after
	// Listen() agrees with itself by construction.
	if p.issuer == "" {
		p.issuer = "http://" + listener.Addr().String()
	}

	// wg.Add inside the lock, so a Listen racing a Close cannot add to a
	// WaitGroup that Close is already waiting on — the one misuse the
	// sync.WaitGroup documentation calls out by name.
	p.wg.Add(1)

	go func() {
		defer p.wg.Done()
		_ = server.Serve(listener)
	}()

	return nil
}

// Issuer is the `iss` claim and the base of the JWKS URI. Before Listen it is
// whatever SetIssuer was told, because the target is configured with the issuer
// at container creation and khaos has to mint tokens that match it.
func (p *Provider) Issuer() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.issuer
}

// SetIssuer pins the issuer khaos mints under, to the value the target was built
// expecting. A token whose `iss` disagrees with the target's configuration is
// rejected for a reason that has nothing to do with the trap under test, which
// reads exactly like a target that caught the trap.
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

// Arm swaps the trap in as one value and snapshots any key state the trap is
// about to change, so Disarm can put it back.
func (p *Provider) Arm(trap Trap) error {
	select {
	case <-p.closed:
		return ErrClosed
	default:
	}

	if err := trap.Validate(); err != nil {
		return err
	}

	// The snapshot is taken whether or not the state change happens, because it
	// is what the confirmation oracle compares the published set against. An
	// inert arm has to leave the oracle able to say NO, and an oracle with
	// nothing to compare cannot say anything.
	p.snap()

	// Inert skips the state change and nothing else. That is what makes it a
	// negative control for the two traps that mutate key material and the one
	// that mutates a grant: the trap reads as armed, the observable never
	// appears, and confirmation must refuse.
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
			// The token traps hold no provider state. They are expressed when a
			// token is minted, so arming them is just recording the trap.
		}
	}

	previous := p.state.Load()
	p.state.Store(&armedTrap{trap: trap, generation: previous.generation + 1})

	return nil
}

// snap records the key state as it stands now, once per arming cycle. Disarm
// restores it and clears it, so a second arming snapshots afresh.
//
// It OVERWRITES rather than keeping the first snapshot. The previous version
// returned early when one existed, so a second Arm without an intervening
// Disarm left RetiredKid naming the first retired key and made Disarm restore
// the wrong one — the confirmation oracle would then compare the published set
// against a kid two rotations old. No path arms twice today; the mutator arms in
// Apply and disarms in Revert. This is the behaviour that is correct whether or
// not that stays true.
func (p *Provider) snap() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.snapshot = &keySnapshot{
		signing: p.signing,
		retired: append([]*Key{}, p.retired...),
	}
}

// RetiredKid is the key that was signing before the current arming cycle. The
// confirmation oracle asserts against the PUBLISHED SET rather than against this
// value, so reading it here cannot make a failed rotation look like a successful
// one: a rotation that did not happen leaves this kid still published.
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

// Inert makes the provider behave correctly while a trap is still armed. It
// exists so the confirmation oracle has a negative control.
//
// Without a way to arm a trap that does NOT happen, every test can only assert
// that confirmation SUCCEEDS, and a confirmation gutted to `return true`
// satisfies all of them. The fault proxy paid for that lesson: measured, that
// gut left all seventeen packages and the Docker gate green.
func (p *Provider) Inert(inert bool) {
	p.inert.Store(inert)
}

func (p *Provider) effective() Trap {
	if p.inert.Load() {
		return Trap{}
	}
	return p.Trap()
}

// rotate installs a fresh signing key. With overlap the retired key stays
// published, which is the availability-preserving rotation every provider is
// supposed to perform. Without it the retired key is withdrawn immediately,
// which is what makes a previously valid token unverifiable to anyone who
// refetches and still valid to anyone who caches forever.
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

// revoke flips a grant inactive. It refuses a credential the provider never
// issued rather than silently succeeding, because a revocation that did not
// happen makes every later acceptance correct behaviour and the run's finding
// unreachable.
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

// HonestToken is always a correct token, whatever is armed. The valid stream
// carries it, and a stream that drifted into carrying forged tokens would make
// every verdict read as a crash.
func (p *Provider) HonestToken() (string, error) {
	return p.mintToken(
		Trap{},
		grantRequest{subject: DefaultSubject, lifetime: p.lifetime},
	)
}

// TrappedToken honours whatever is armed. It is what the forged stream carries,
// and it is also what the rotation experiment's VALID stream carries, because
// there the question is whether the target accepts a correctly signed token under
// the provider's new key.
func (p *Provider) TrappedToken() (string, error) {
	return p.mintToken(
		p.effective(),
		grantRequest{subject: DefaultSubject, lifetime: p.lifetime},
	)
}

// StableToken is a correct JWT signed by a key that is always published and
// never rotated.
//
// It is the valid-stream credential for the rotation experiments, and the reason
// is an observer effect khaos measured on itself. A valid stream minting under
// the CURRENT signing key supplies new-key traffic after a rotation, and research
// 07 section 2.3 establishes that the eviction of a retired key is a side effect
// of exactly that traffic — so khaos was causing the recovery it then reported.
//
// An opaque credential also avoids it, and was the first fix, but it requires
// the target to support introspection, which a JWT-only verifier does not. This
// one is a JWT, so it works against any verifier, and its kid is in the key set
// from the baseline onwards, so resolving it never forces a refetch.
func (p *Provider) StableToken() (string, error) {
	p.mu.RLock()
	stable := p.stable
	p.mu.RUnlock()

	return p.mintSignedBy(stable)
}

// Opaque issues a credential that carries no claims, so the only way a verifier
// can decide anything about it is to ask. It is what the introspection traps are
// measured with.
func (p *Provider) Opaque() string {
	credential := opaquePrefix + rand.Text()

	p.mu.Lock()
	p.grants[credential] = &grant{subject: DefaultSubject, active: true}
	p.mu.Unlock()

	return credential
}

// Revocable issues an opaque credential and records it as the one this run
// intends to revoke, so the mutator can find it at inject time. The probe that
// calls this has not fired when the experiment is built, which is why the
// credential cannot travel on the trap from the start.
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

// PublishedSet is every key a verifier may resolve, which is every key khaos
// signs with EXCEPT the attacker key. The weak and EC keys are always published
// rather than published on arming, so that a forgery trap changes only what the
// provider MINTS and a key trap changes only what it SERVES. Confusing the two
// would make each one's read-back ambiguous.
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

// Introspections is how many times something OTHER than khaos asked about a
// credential.
func (p *Provider) Introspections() int64 {
	return p.introspects.Load() - p.ownIntrospects.Load()
}
