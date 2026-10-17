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
	// ControlPort listens INSIDE the resolver's container and is never
	// published, so it cannot collide with anything on the operator's machine.
	ControlPort = 9053

	// NonceHeader authorises a control request. The resolver shares a network
	// with the target, so the nonce is what stops the target arming or
	// disarming khaos's own fault.
	NonceHeader = "X-Khaos-Nonce"

	NonceBytes = 16

	PathArm     = "/arm"
	PathDisarm  = "/disarm"
	PathRotate  = "/rotate"
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

// Health is what /healthz answers. It is deliberately NOT nonce-protected,
// because khaos has to wait for the container to come up before it has read
// the nonce out of it. It reports nothing about the armed fault.
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
	mux.HandleFunc(PathRotate, r.guard(r.handleRotate))

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

	// The goroutine serves the LOCALS it was handed; reading them back off the
	// struct would race a concurrent shutdown.
	go func() {
		_ = server.Serve(listener)
	}()

	return nil
}

// ControlAddr reports the address the control surface actually bound, which
// matters when port 0 was requested.
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

// guard refuses a request carrying the wrong nonce and counts the refusal, so
// a target probing the surface shows up in the run record.
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

// handleRotate moves a name's address in the zone and echoes the state, whose
// Zone map is read back rather than remembered -- so khaos's observable can name
// the address the rotation replaced rather than the one it asked for.
func (r *Resolver) handleRotate(w http.ResponseWriter, req *http.Request) {
	var rotation Rotation

	decoder := json.NewDecoder(
		http.MaxBytesReader(w, req.Body, controlBodyLimit),
	)
	if err := decoder.Decode(&rotation); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	previous, err := r.Rotate(rotation.Name, rotation.Address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	stats := r.Stats()
	stats.Rotated = previous

	r.writeJSON(w, stats)
}

// Rotation is one zone change, and it is a different request shape from a Trap
// on purpose: arming a fault and moving the zone are different acts.
type Rotation struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// handleArm installs a fault and echoes the resulting state. The echo says
// which branch was chosen, not what a target would receive, so it is never
// what a fault is confirmed by.
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
