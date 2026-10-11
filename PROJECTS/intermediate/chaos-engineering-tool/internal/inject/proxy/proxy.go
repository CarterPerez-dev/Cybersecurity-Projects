// ©AngelaMos | 2026
// proxy.go

package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dialTimeout = 5 * time.Second

	// A hung connection is held open, not closed, because closing it is a
	// different fault. The ceiling exists only so a proxy that is never reverted
	// cannot leak the goroutine forever. It is not the rollback: Arm, Disarm and
	// Close all free held connections immediately.
	hangCeiling = 10 * time.Minute

	noLinger   = 0
	network    = "tcp"
	copyBuffer = 32 * 1024

	// How long EOF waits for the target's in-flight request before closing. The
	// kernel sends FIN only when the receive queue is empty, so the queue has to
	// be drained to the deadline rather than to the first short read.
	drainWindow = 250 * time.Millisecond

	errWildcard   = "%w: %q binds every address on this host, and a fault proxy in front of a dependency under test must not be reachable off it; bind the Docker bridge gateway instead"
	errPrivileged = "%w: %q is a privileged port"
	errBadAddr    = "%w: %q is not a host and port (%v)"

	probePayload = "GET / HTTP/1.1\r\nHost: khaos.confirm\r\nConnection: close\r\n\r\n"

	// Each of these names what khaos measured through its proxy AGAINST what the
	// same dependency gave it directly, because only the difference between the
	// two paths can be attributed to khaos's own fault.
	observedHang      = "the dependency answers khaos directly but never through its proxy"
	observedReset     = "the dependency answers khaos directly but resets through its proxy"
	observedEOF       = "the dependency answers khaos directly but closes without answering through its proxy"
	observedLatency   = "the first byte arrives %s later through khaos's proxy than directly"
	observedPartial   = "%d bytes arrive through khaos's proxy where the dependency answers %d directly"
	observedSlowClose = "the close arrives %s after the last byte, which it does not do directly"
	errWrongArmed     = "%w: the proxy holds %q but %q was expected"

	lowestUnprivilegedPort = 1024
	ephemeralPort          = 0

	sysClassNet  = "/sys/class/net"
	bridgeMarker = "bridge"

	errOffBox = "%w: %q is not on loopback or on a Docker bridge, so it is reachable from outside this host and a container cannot reach it anyway; bind the bridge gateway the daemon reports"
)

var ErrClosed = errors.New("the fault proxy is closed")

var ErrUnsafeBind = errors.New("khaos will not bind the fault proxy there")

// Proxy is a TCP man-in-the-middle between a target and one of its dependencies,
// modelled on Toxiproxy's per-connection pipeline and credited as such. It holds
// no capabilities and writes no kernel state, so the worst a total failure of it
// can leak is a listener on a high port, and there is nothing for bad targeting
// to reach.
//
// The armed fault is one value swapped atomically, so arming and disarming are
// indivisible and cannot half-apply. That is the property that makes this the
// primary tier rather than a convenience.
// armed is the whole mutable state of the proxy: the fault and the generation it
// belongs to, swapped as one value so a handler can never read a fault from one
// revert and a generation from another.
type armed struct {
	fault      Fault
	generation uint64
}

type Proxy struct {
	upstream string
	listener net.Listener
	state    atomic.Pointer[armed]

	// Both ends of every exchange are held, and the revert closes both. Closing
	// only the client cannot unblock a read parked on the DEPENDENCY, and a
	// dependency that accepts and never answers is precisely what research 06
	// section 6.1 measured for `docker pause` and `docker network disconnect`.
	mu   sync.Mutex
	held map[net.Conn]struct{}

	// inert makes the proxy forward normally while a fault is still armed. It
	// exists so the confirmation oracle has a negative control: without a way to
	// arm a fault that does NOT happen, every test can only assert that
	// confirmation SUCCEEDS, and a confirmation gutted to `return true` satisfies
	// all of them. Measured: that gut left all seventeen packages and the Docker
	// gate green.
	inert atomic.Bool

	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once

	accepted atomic.Int64
	severed  atomic.Int64
	relayed  atomic.Int64
	probes   atomic.Int64
}

// Open binds the proxy and refuses an address that would expose it. The
// containment property of this tier is that the listener answers containers and
// nothing else, and that is enforced here rather than left to callers: a
// wildcard bind puts a fault proxy for a dependency under test on the operator's
// network.
func Open(listenAddr, upstream string) (*Proxy, error) {
	if err := safeBind(listenAddr); err != nil {
		return nil, err
	}

	listener, err := net.Listen(network, listenAddr)
	if err != nil {
		return nil, err
	}

	p := &Proxy{
		upstream: upstream,
		listener: listener,
		held:     map[net.Conn]struct{}{},
		closed:   make(chan struct{}),
	}

	p.state.Store(&armed{fault: Fault{Kind: PassThrough}})

	p.wg.Add(1)
	go p.serve()

	return p, nil
}

// safeBind enforces the containment property instead of describing it. The
// earlier version refused only a wildcard, which let the proxy bind this host's
// own LAN address: exactly the off-box exposure its error message warns about,
// and useless besides, because a container cannot reach the LAN address anyway.
//
// The test is the routing property, measured rather than guessed from the
// address: the listener must sit on loopback, which is unreachable off the host by
// construction, or on a BRIDGE interface, which is what a container reaches the
// host through. A bridge is identified by its sysfs `bridge` directory, so this
// does not depend on interface naming.
func safeBind(listenAddr string) error {
	host, portText, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf(errBadAddr, ErrUnsafeBind, listenAddr, err)
	}

	// No name resolution. A hostname would mean an unbounded resolver lookup on a
	// safety check, and khaos is always handed a literal address the daemon
	// reported.
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return fmt.Errorf(errWildcard, ErrUnsafeBind, listenAddr)
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		return fmt.Errorf(errBadAddr, ErrUnsafeBind, listenAddr, err)
	}

	if port != ephemeralPort && port < lowestUnprivilegedPort {
		return fmt.Errorf(errPrivileged, ErrUnsafeBind, listenAddr)
	}

	if ip.IsLoopback() {
		return nil
	}

	onBridge, err := bridgeHosts(ip)
	if err != nil {
		return fmt.Errorf(errBadAddr, ErrUnsafeBind, listenAddr, err)
	}

	if !onBridge {
		return fmt.Errorf(errOffBox, ErrUnsafeBind, listenAddr)
	}

	return nil
}

// bridgeHosts reports whether an address belongs to a bridge interface on this
// host.
func bridgeHosts(ip net.IP) (bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			network, ok := addr.(*net.IPNet)
			if !ok || !network.IP.Equal(ip) {
				continue
			}

			_, err := os.Stat(filepath.Join(sysClassNet, iface.Name, bridgeMarker))

			return err == nil, nil
		}
	}

	return false, nil
}

func (p *Proxy) Addr() string { return p.listener.Addr().String() }

func (p *Proxy) Upstream() string { return p.upstream }

func (p *Proxy) Fault() Fault { return p.state.Load().fault }

// Arm swaps the fault in. It also drops every connection currently held open, so
// a target sitting on a pooled keepalive connection established before the fault
// does not keep sailing through it and report a clean survival.
func (p *Proxy) Arm(fault Fault) error {
	if err := fault.Validate(); err != nil {
		return err
	}

	select {
	case <-p.closed:
		return ErrClosed
	default:
	}

	p.swap(fault)

	return nil
}

// Disarm returns the proxy to pass-through and releases every connection the
// fault was holding. This is the whole revert.
func (p *Proxy) Disarm() {
	p.swap(Fault{Kind: PassThrough})
}

// swap replaces the armed state and releases everything held under the old one,
// as ONE transaction under the mutex.
//
// The fault and the generation have to move together. Storing the fault first and
// advancing the generation afterwards let a handler read the NEW fault with the
// OLD generation, which track then refused, so hold closed the client instead of
// holding it. Measured: 116 of 2000 armed hangs came out as a reset, which is the
// other fault in the catalogue and the one the design doc exists to distinguish
// from it.
func (p *Proxy) swap(fault Fault) {
	p.mu.Lock()

	previous := p.state.Load()
	p.state.Store(&armed{fault: fault, generation: previous.generation + 1})

	conns := make([]net.Conn, 0, len(p.held))
	for conn := range p.held {
		conns = append(conns, conn)
	}
	p.held = map[net.Conn]struct{}{}

	p.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}
}

// Counts is telemetry for the run record, never evidence that a fault landed.
// Probes are reported separately so khaos's own confirmation traffic is not
// mistaken for the target's.
type Counts struct {
	Accepted int64
	Severed  int64
	Relayed  int64
	Probes   int64
}

func (p *Proxy) Counts() Counts {
	return Counts{
		Accepted: p.accepted.Load(),
		Severed:  p.severed.Load(),
		Relayed:  p.relayed.Load(),
		Probes:   p.probes.Load(),
	}
}

func (p *Proxy) Close() error {
	var err error

	p.once.Do(func() {
		close(p.closed)
		err = p.listener.Close()
		p.swap(Fault{Kind: PassThrough})
	})

	p.wg.Wait()

	return err
}

func (p *Proxy) serve() {
	defer p.wg.Done()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Backing off matters: a persistent accept error that is neither of
			// the above would otherwise spin a core for the whole run.
			time.Sleep(drainWindow)
			continue
		}

		p.accepted.Add(1)
		p.wg.Add(1)

		go func() {
			defer p.wg.Done()
			p.handle(conn)
		}()
	}
}

// handle owns the client connection and re-reads the armed state until it finds
// one that is still current.
//
// A connection accepted just before a revert is handled under the state that was
// armed when it was accepted, and refusing it for staleness is not enough: the
// first attempt at this closed such a connection, and closing one with an unread
// request in its receive queue IS a reset. Measured: 81 of 2000 armed hangs
// arrived at the client as `connection reset by peer`, which is the other fault
// in the catalogue and the one the design doc exists to keep distinguishable.
// Retrying under the current state delivers the fault that is actually armed.
func (p *Proxy) handle(client net.Conn) {
	defer func() { _ = client.Close() }()

	for {
		select {
		case <-p.closed:
			return
		default:
		}

		// One load. The fault and the generation it belongs to arrive together, so
		// there is no interleaving that pairs a new fault with a stale generation.
		state := p.state.Load()

		if p.inert.Load() {
			if p.forward(client, Fault{Kind: PassThrough}, state.generation) {
				return
			}
			continue
		}

		if state.fault.Severs() {
			if p.sever(client, state.fault, state.generation) {
				return
			}
			continue
		}

		if p.forward(client, state.fault, state.generation) {
			return
		}
	}
}

// sever reports whether it handled the connection. False means the armed state
// moved underneath it and the caller must try again under the current one.
func (p *Proxy) sever(client net.Conn, fault Fault, generation uint64) bool {
	switch fault.Kind {
	case Reset:
		// SO_LINGER 0 is necessary AND sufficient: it forces RST whatever the
		// receive queue holds, and the reset surfaces at the target's connect or
		// at its first read, which are the same observable.
		//
		// This used to also wait for the target's request, on the theory that a
		// non-empty receive queue was needed to force RST on an empty-queue close.
		// Measured: deleting that wait leaves both reset controls green over 20
		// runs, including a target that sends nothing, while deleting SO_LINGER 0
		// turns them red immediately. The wait was inert, and an inert arm alibis
		// the live one's control, so it is gone rather than kept for symmetry. It
		// also cost every reset a quarter second it should not have.
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.SetLinger(noLinger)
		}
		_ = client.Close()
		p.severed.Add(1)
		return true
	case EOF:
		// The queue has to be drained to the deadline first. The kernel sends FIN
		// only when the receive queue is EMPTY and RST when it is not, so closing
		// on an unread request yields a reset and makes this a nondeterministic
		// duplicate of Reset. Measured: a request larger than one read produced
		// ECONNRESET on every attempt until the drain ran to its deadline.
		drain(client)
		_ = client.Close()
		p.severed.Add(1)
		return true
	default:
		return p.hold(client, generation)
	}
}

// drain empties the receive queue until the deadline expires. Returning on the
// first short read is wrong: a short read means "that is what had arrived by
// now", not "the queue is empty", so bytes still in flight land on a closed
// socket and the kernel answers RST.
func drain(client net.Conn) {
	if err := client.SetReadDeadline(time.Now().Add(drainWindow)); err != nil {
		return
	}

	buffer := make([]byte, copyBuffer)

	for {
		if _, err := client.Read(buffer); err != nil {
			return
		}
	}
}

// hold implements Hang: keep the connection open and answer nothing, until the
// revert drops it or the ceiling expires.
func (p *Proxy) hold(client net.Conn, generation uint64) bool {
	if !p.track(generation, client) {
		return false
	}
	defer p.untrack(client)

	p.severed.Add(1)

	timer := time.NewTimer(hangCeiling)
	defer timer.Stop()

	gone := make(chan struct{})

	go func() {
		defer close(gone)
		// The target may give up first. Reading tells us when, and a hang must
		// not interpret the target's own timeout as something it has to answer.
		_, _ = io.Copy(io.Discard, client)
	}()

	select {
	case <-gone:
	case <-timer.C:
	case <-p.closed:
	}

	return true
}

// forward reports whether it handled the connection. False means the armed state
// moved underneath it and the caller must try again under the current one.
func (p *Proxy) forward(client net.Conn, fault Fault, generation uint64) bool {
	upstream, err := net.DialTimeout(network, p.upstream, dialTimeout)
	if err != nil {
		// The dependency is genuinely unreachable. Passing that through as a
		// reset rather than inventing an answer keeps the proxy transparent when
		// the real fault is somewhere else, which is what lets a Docker-native
		// fault be measured THROUGH a pass-through proxy.
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.SetLinger(noLinger)
		}
		return true
	}
	defer func() { _ = upstream.Close() }()

	// BOTH ends are tracked, so the revert can close both. Tracking only the
	// client deadlocked against a dependency that accepts and never answers: the
	// answer leg sat in a read on the dependency, closing the client could not
	// unblock it, and nothing closed the dependency until this function returned.
	// `khaos run` defers this proxy's Close, so the whole command hung with a
	// fault's listener still bound.
	if !p.track(generation, client, upstream) {
		return false
	}
	defer p.untrack(client, upstream)

	// Only LATENCY delays the bytes. slow-close passed fault.Delay to both pumps
	// as well as holding the close, so a two second slow-close delayed the
	// request two seconds and every response chunk two seconds more, on top of
	// the hold. A client with a 500ms timeout then failed before the response
	// arrived — and failed for latency while khaos attributed it to the close.
	//
	// The two faults are supposed to be distinguishable: slow-close exists to
	// find a caller that waits for the connection to end instead of reading a
	// Content-Length, and that caller must receive its payload promptly or the
	// experiment is measuring `network.dependency_latency` under another name.
	chunkDelay := time.Duration(0)
	if fault.Kind == Latency {
		chunkDelay = fault.Delay
	}

	var relay sync.WaitGroup
	relay.Add(2)

	go func() {
		defer relay.Done()
		p.pump(upstream, client, chunkDelay, 0, true)
	}()

	go func() {
		defer relay.Done()

		p.pump(client, upstream, chunkDelay, limitFor(fault), false)

		// The hold belongs to the ANSWER, not to the exchange. Putting it after
		// both legs meant a client that keeps its write side open never reached
		// it, so the fault could not be confirmed at all; putting it before the
		// answer's own half-close is what makes it a slow CLOSE rather than a
		// slow everything.
		if fault.Kind == SlowClose {
			select {
			case <-time.After(fault.Delay):
			case <-p.closed:
			}
		}

		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()

	// Both directions have to finish, which is ordinary proxying. Returning on
	// the first one closed an answer still in flight, so a half-closing client
	// received nothing even through a pass-through proxy, and abandoning the
	// request leg delivered a TRUNCATED request to the dependency: measured, a
	// target sent 307200 bytes and the dependency received none of them.
	relay.Wait()

	return true
}

// pump copies one direction, optionally delaying each chunk, optionally stopping
// after a byte budget, and optionally half-closing the destination when the
// source ends. The delay is per chunk rather than once at the start, because a
// one-off delay is a slow connection and a per-chunk delay is a slow dependency,
// and only the second survives a client that retries.
func (p *Proxy) pump(dst, src net.Conn, delay time.Duration, limit int, halfClose bool) {
	if halfClose {
		defer func() {
			if tcp, ok := dst.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
		}()
	}

	var reader io.Reader = src
	if limit > 0 {
		reader = io.LimitReader(src, int64(limit))
	}

	if delay <= 0 {
		written, _ := io.Copy(dst, reader)
		if written > 0 {
			p.relayed.Add(1)
		}
		return
	}

	buffer := make([]byte, copyBuffer)

	for {
		read, err := reader.Read(buffer)
		if read > 0 {
			select {
			case <-time.After(delay):
			case <-p.closed:
				return
			}
			if _, writeErr := dst.Write(buffer[:read]); writeErr != nil {
				return
			}
			p.relayed.Add(1)
		}
		if err != nil {
			return
		}
	}
}

// limitFor applies Partial to the DEPENDENCY's answer only. Truncating what the
// target sends would be a different experiment: it would test the dependency,
// which is not the thing under test.
func limitFor(fault Fault) int {
	if fault.Kind == Partial {
		return fault.Bytes
	}
	return 0
}

func (p *Proxy) track(generation uint64, conns ...net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	select {
	case <-p.closed:
		return false
	default:
	}

	if p.state.Load().generation != generation {
		return false
	}

	for _, conn := range conns {
		p.held[conn] = struct{}{}
	}

	return true
}

func (p *Proxy) untrack(conns ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range conns {
		delete(p.held, conn)
	}
}
