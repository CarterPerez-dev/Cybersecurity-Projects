// ©AngelaMos | 2026
// control.go

package dnsrv

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	// ControlPort is where the resolver's control surface listens INSIDE its
	// container. Nothing is published to the host, and khaos reaches it on the
	// container's own address the same way it reaches the resolver's DNS port,
	// so this never collides with anything on the operator's machine and never
	// needs remapping.
	ControlPort = 9053

	// NonceHeader authorises a control request. The resolver shares a network
	// with the target, so the target can reach this surface; the nonce is what
	// stops it arming or disarming khaos's own fault. khaos generates it,
	// passes it at container creation, and reads it back out of the container
	// rather than remembering what it chose.
	NonceHeader = "X-Khaos-Nonce"

	// NonceBytes is 16, so a target cannot find the nonce by trying. Every
	// refused attempt is counted and reported in Stats, which turns guessing
	// into evidence rather than noise.
	NonceBytes = 16

	PathArm     = "/arm"
	PathDisarm  = "/disarm"
	PathState   = "/state"
	PathHealthz = "/healthz"

	controlReadTimeout   = 5 * time.Second
	controlWriteTimeout  = 5 * time.Second
	controlHeaderTimeout = 3 * time.Second
	controlBodyLimit     = 4 << 10
)

const (
	errControlBind  = "bind the resolver's control surface on %s: %w"
	errControlUp    = "%w: this resolver's control surface is already serving"
	errControlReply = "encode the control reply: %w"
)

var ErrControlServing = errors.New(
	"that resolver's control surface is already serving",
)

// Health is what /healthz answers. It is a liveness signal and deliberately NOT
// nonce-protected, because khaos has to be able to wait for the container to
// come up before it has read the nonce back out of it, and because a readiness
// probe that needs a secret is one khaos cannot use from a `range status`.
//
// It reports nothing about the armed fault. A target that reads it learns only
// that a resolver exists, which it already knows from its own resolv.conf.
type Health struct {
	OK       bool   `json:"ok"`
	Upstream string `json:"upstream"`
	Control  string `json:"control"`
}

// ServeControl binds the control surface and returns once it is accepting.
func (r *Resolver) ServeControl(listen string) error {
	if listen == "" {
		listen = fmt.Sprintf(":%d", ControlPort)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(PathHealthz, r.handleHealth)
	mux.HandleFunc(PathState, r.guard(r.handleState))
	mux.HandleFunc(PathArm, r.guard(r.handleArm))
	mux.HandleFunc(PathDisarm, r.guard(r.handleDisarm))

	server := &http.Server{
		Handler:           mux,
		ReadTimeout:       controlReadTimeout,
		WriteTimeout:      controlWriteTimeout,
		ReadHeaderTimeout: controlHeaderTimeout,
	}

	listener, err := net.Listen(tcpNet, listen)
	if err != nil {
		return fmt.Errorf(errControlBind, listen, err)
	}

	r.mu.Lock()
	if r.control != nil {
		r.mu.Unlock()
		_ = listener.Close()
		return fmt.Errorf(errControlUp, ErrControlServing)
	}
	r.control = server
	r.controlAddr = listener.Addr().String()
	r.mu.Unlock()

	// The goroutine serves the LOCALS it was handed. Reading them back off the
	// struct is the exact shape that gave `internal/pki` three data races, and
	// the plain test suite was green for both of its new packages.
	go func() {
		_ = server.Serve(listener)
	}()

	return nil
}

// ControlAddr reports where the control surface bound, which a test needs when
// it asked for port 0.
func (r *Resolver) ControlAddr() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.controlAddr
}

func (r *Resolver) shutdownControl() error {
	r.mu.Lock()
	server := r.control
	r.control = nil
	r.controlAddr = ""
	r.mu.Unlock()

	if server == nil {
		return nil
	}

	return server.Close()
}

// guard refuses a request carrying the wrong nonce and COUNTS it. A refusal
// that is merely returned tells khaos nothing; a refusal that is counted is
// evidence khaos can read in the run record.
func (r *Resolver) guard(
	next func(http.ResponseWriter, *http.Request),
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get(NonceHeader) != r.cfg.Nonce || r.cfg.Nonce == "" {
			r.countDenied()
			http.Error(
				w,
				http.StatusText(http.StatusForbidden),
				http.StatusForbidden,
			)
			return
		}

		r.countControl()
		next(w, req)
	}
}

func (r *Resolver) handleHealth(w http.ResponseWriter, _ *http.Request) {
	r.writeJSON(w, Health{
		OK:       true,
		Upstream: r.cfg.Upstream,
		Control:  r.cfg.Control,
	})
}

func (r *Resolver) handleState(w http.ResponseWriter, _ *http.Request) {
	r.writeJSON(w, r.Stats())
}

// handleArm installs a fault and answers with the resolver's resulting state,
// so the caller gets a synchronous acknowledgement of what is now armed.
//
// The acknowledgement is deliberately NOT what khaos confirms the fault by. A
// state echo says which branch was chosen, not what a target would receive, and
// the PKI tier's inert-authority control caught fifteen traps confirming
// themselves off exactly that kind of read-back. Confirmation measures the
// SERVED answer.
func (r *Resolver) handleArm(w http.ResponseWriter, req *http.Request) {
	var trap Trap

	decoder := json.NewDecoder(
		http.MaxBytesReader(w, req.Body, controlBodyLimit),
	)
	if err := decoder.Decode(&trap); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := r.Arm(trap); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	r.writeJSON(w, r.Stats())
}

func (r *Resolver) handleDisarm(w http.ResponseWriter, _ *http.Request) {
	r.Disarm()
	r.writeJSON(w, r.Stats())
}

func (r *Resolver) writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		r.countError()
	}
}

func (r *Resolver) countControl() {
	r.mu.Lock()
	r.controls++
	r.mu.Unlock()
}

func (r *Resolver) countDenied() {
	r.mu.Lock()
	r.denied++
	r.mu.Unlock()
}
