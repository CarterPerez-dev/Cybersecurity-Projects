// ©AngelaMos | 2026
// authz.go

package authz

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/bindguard"
)

const (
	// Any path, because this is the Envoy `ext_authz` HTTP contract rather than
	// an endpoint of khaos's own invention: the filter forwards the request's
	// headers to whatever path it was configured with and reads the RESPONSE
	// STATUS as the decision. 200 allows, 403 denies, and a 5xx is the only
	// answer the `failure_mode_allow` knob is permitted to act on.
	routeAny = "/"

	headerAuthorization = "Authorization"
	bearerPrefix        = "Bearer "
	headerReason        = "X-Khaos-Authz"

	reasonAllowed = "khaos's authorization dependency has not been told to deny this credential"
	reasonDenied  = "khaos's authorization dependency denies this credential: a definitive verdict, with full reachability"
	reasonOutage  = "khaos's authorization dependency cannot answer; this is the absence of a decision, not a decision"

	SubjectAuthz = "an authorization service that allows every credential it was not told to deny"

	askTimeout    = 2 * time.Second
	shutdownGrace = 2 * time.Second
	controlLen    = 16

	errAlreadyListening = "%w: khaos's authorization dependency is already listening on %s"
	errAsk              = "khaos could not ask its own authorization dependency: %w"
	errNotListening     = "%w: khaos's authorization dependency is not listening, so there is nothing to read back"

	confirmDenied = "khaos's own authorization dependency answers %d for the credential under test and %d for a control credential it was never told to deny, read back through its own HTTP surface"

	confirmOutage = "khaos's own authorization dependency answers %d for every credential, including a control one it was never told to deny"
)

var ErrListening = errors.New(
	"khaos's authorization dependency is already listening",
)

var ErrNotListening = errors.New(
	"khaos's authorization dependency has no listener",
)

var ErrClosed = errors.New(
	"khaos's authorization dependency is closed",
)

// Dependency is khaos playing an authorization service, for the same reason it
// plays an identity provider and a certificate authority: no correct dependency
// will answer a definitive deny on command, and the defect this tier hunts only
// exists when one does.
//
// It ALLOWS by default. A stand-in authority that refused anything it was not
// told to deny would make the baseline khaos's posture rather than the target's,
// and the whole measurement is the difference between two windows.
type Dependency struct {
	mu   sync.RWMutex
	trap Trap

	denied map[string]bool
	outage bool

	listener net.Listener
	server   *http.Server

	asked   atomic.Int64
	refused atomic.Int64

	wg     sync.WaitGroup
	once   sync.Once
	closed chan struct{}
}

func New() *Dependency {
	return &Dependency{
		denied: map[string]bool{},
		closed: make(chan struct{}),
	}
}

// Listen binds where the TARGET already looks, and refuses an address khaos
// must not serve this from. The refusal is not ceremony: until it is told
// otherwise this dependency ALLOWS every credential presented to it, so a
// wildcard bind would put an allow-everything authorization service on every
// interface the host has.
func (d *Dependency) Listen(addr string) error {
	if err := bindguard.Check(addr, SubjectAuthz); err != nil {
		return err
	}

	// Guard and bind under ONE acquisition, or two callers both bind and the
	// second orphans the first listener and its goroutine.
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.listener != nil {
		return fmt.Errorf(
			errAlreadyListening,
			ErrListening,
			d.listener.Addr().String(),
		)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler:           d.routes(),
		ReadHeaderTimeout: shutdownGrace,
	}

	d.listener = listener
	d.server = server

	d.wg.Add(1)

	go func() {
		defer d.wg.Done()
		_ = server.Serve(listener)
	}()

	return nil
}

func (d *Dependency) Addr() string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.listener == nil {
		return ""
	}

	return d.listener.Addr().String()
}

func (d *Dependency) Close() error {
	var err error

	d.once.Do(func() {
		close(d.closed)

		d.mu.RLock()
		server := d.server
		d.mu.RUnlock()

		if server != nil {
			err = server.Close()
		}

		d.wg.Wait()
	})

	return err
}

func (d *Dependency) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(routeAny, d.authorize)

	return mux
}

func (d *Dependency) authorize(w http.ResponseWriter, r *http.Request) {
	d.asked.Add(1)

	credential, _ := strings.CutPrefix(
		r.Header.Get(headerAuthorization),
		bearerPrefix,
	)

	status, reason := d.decide(credential)

	// Only the DEFINITIVE refusals are counted, and only the credential under
	// test is ever answered with one. That makes this count the number of
	// times the target asked again about a credential it had already been
	// told no about, which nothing else can measure from outside it.
	if status == http.StatusForbidden {
		d.refused.Add(1)
	}

	w.Header().Set(headerReason, reason)
	w.WriteHeader(status)
}

// decide is the whole dependency. Three outcomes, because an authorization
// dependency has three and only the third is eligible for a fallback policy.
func (d *Dependency) decide(credential string) (int, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.outage {
		return http.StatusServiceUnavailable, reasonOutage
	}

	if d.denied[credential] {
		return http.StatusForbidden, reasonDenied
	}

	return http.StatusOK, reasonAllowed
}

// Arm applies a trap. An inert arm prepares everything and tells the dependency
// nothing, so the confirmation that reads it back through its own surface has
// something it must reject.
func (d *Dependency) Arm(trap Trap) error {
	select {
	case <-d.closed:
		return ErrClosed
	default:
	}

	if err := trap.Validate(); err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.trap = trap

	if trap.Inert {
		return nil
	}

	switch trap.Kind {
	case Deny:
		d.denied[trap.Credential] = true
	case Outage:
		d.outage = true
	}

	return nil
}

// Disarm restores the allow-everything posture. Nothing is removed from the
// denied set by Arm, so this is the single place the fault is lifted.
func (d *Dependency) Disarm() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.denied = map[string]bool{}
	d.outage = false
}

// Asked is the liveness guard: the number of authorization decisions the target
// asked for. Zero during the baseline means the target does not consult an
// authorization dependency at all, and the fault is one it cannot experience.
//
// khaos's own two-sided confirmation reads this dependency through the same
// surface and is counted here too. Every guard built on this number reads a
// DIFFERENCE across a window, and the confirmations run between windows rather
// than inside one, so none of them sees khaos's own traffic.
func (d *Dependency) Asked() (int64, error) {
	return d.asked.Load(), nil
}

func (d *Dependency) Refused() int64 {
	return d.refused.Load()
}

// Observe is the two-sided confirmation, and it reads the dependency back
// through its OWN HTTP surface rather than the flag that was set: a dependency
// whose handler was wrong would otherwise confirm a fault it is not serving.
//
// Both sides are needed. The credential under test must be refused, and a
// control credential khaos never named must still be allowed, or a dependency
// that had started refusing everything would read as a successful deny.
func (d *Dependency) Observe(ctx context.Context) (string, bool, error) {
	d.mu.RLock()
	trap := d.trap
	d.mu.RUnlock()

	control, err := d.ask(ctx, rand.Text()[:controlLen])
	if err != nil {
		return "", false, err
	}

	if trap.Kind == Outage {
		return confirms(trap.Kind, control, control)
	}

	subject, err := d.ask(ctx, trap.Credential)
	if err != nil {
		return "", false, err
	}

	return confirms(trap.Kind, subject, control)
}

// confirms is the two-sided judgement, kept separate from the dialling so that
// every combination of answers can be put to it. The control side is not
// reachable through this type's own API -- nothing can tell the dependency to
// refuse everything -- and a regression that made it do so is precisely what
// the control side exists to catch: khaos would otherwise measure a run where
// its own dependency denied the valid credential, and report the target's
// correct refusal of it as a defect.
func confirms(kind Kind, subject, control int) (string, bool, error) {
	if kind == Outage {
		if control != http.StatusServiceUnavailable {
			return "", false, nil
		}

		return fmt.Sprintf(confirmOutage, control), true, nil
	}

	if subject != http.StatusForbidden || control != http.StatusOK {
		return "", false, nil
	}

	return fmt.Sprintf(confirmDenied, subject, control), true, nil
}

// ask dials khaos's own listener, which is the only way to read what the
// dependency ANSWERS rather than what khaos believes it armed.
func (d *Dependency) ask(ctx context.Context, credential string) (int, error) {
	addr := d.Addr()
	if addr == "" {
		return 0, fmt.Errorf(errNotListening, ErrNotListening)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://"+addr+routeAny,
		nil,
	)
	if err != nil {
		return 0, fmt.Errorf(errAsk, err)
	}

	request.Header.Set(headerAuthorization, bearerPrefix+credential)

	client := &http.Client{Timeout: askTimeout}

	response, err := client.Do(request)
	if err != nil {
		return 0, fmt.Errorf(errAsk, err)
	}
	defer func() { _ = response.Body.Close() }()

	_, _ = io.Copy(io.Discard, response.Body)

	return response.StatusCode, nil
}
