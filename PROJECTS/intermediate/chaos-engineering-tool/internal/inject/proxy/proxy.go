// ©AngelaMos | 2026
// proxy.go

package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/bindguard"
)

const (
	dialTimeout = 5 * time.Second

	// Only a ceiling, so an unreverted hang cannot leak the goroutine forever.
	hangCeiling = 10 * time.Minute

	noLinger   = 0
	network    = "tcp"
	copyBuffer = 32 * 1024

	drainWindow = 250 * time.Millisecond

	settleWindow = 250 * time.Millisecond

	SubjectProxy = "a fault proxy in front of a dependency under test"

	probePayload = "GET / HTTP/1.1\r\nHost: khaos.confirm\r\nConnection: close\r\n\r\n"

	// RESP, for a dependency that speaks it. Measured on redis:7.4-alpine:
	// the HTTP payload above gets zero bytes and a close, while this gets
	// `+PONG\r\n`, and the oracle needs bytes on the direct path.
	ProbeRESP = "*1\r\n$4\r\nPING\r\n"

	observedHang      = "the dependency answers khaos directly but never through its proxy"
	observedReset     = "the dependency answers khaos directly but resets through its proxy"
	observedEOF       = "the dependency answers khaos directly but closes without answering through its proxy"
	observedLatency   = "the first byte arrives %s later through khaos's proxy than directly"
	observedPartial   = "%d bytes arrive through khaos's proxy where the dependency answers %d directly"
	observedSlowClose = "the close arrives %s after the last byte, which it does not do directly"
	errWrongArmed     = "%w: the proxy holds %q but %q was expected"
)

var ErrClosed = errors.New("the fault proxy is closed")

// ErrUnsafeBind is the shared sentinel. It stays spelled here because every
// caller and test in this tier asks about it by this name.
var ErrUnsafeBind = bindguard.ErrUnsafeBind

type armed struct {
	fault      Fault
	generation uint64
}

// Proxy is a TCP man-in-the-middle, modelled on Toxiproxy. It holds no
// capabilities and writes no kernel state, and the fault is one swapped value.
type Proxy struct {
	upstream string
	listener net.Listener
	state    atomic.Pointer[armed]

	// What the confirmation probe SAYS to the dependency. The differential
	// needs the dependency to answer on the direct path, and a dependency
	// that does not speak HTTP answers an HTTP request with nothing at all:
	// measured on Redis 7.4, which returns zero bytes and closes, so the
	// oracle reported the dependency unreachable and voided the run.
	probe string

	// Both ends are held; closing the client cannot unblock the dependency.
	mu           sync.Mutex
	held         map[net.Conn]struct{}
	sources      map[string]int64
	faultSources map[string]int64

	// inert forwards normally with a fault armed: a negative control.
	inert atomic.Bool

	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once

	accepted atomic.Int64
	severed  atomic.Int64
	relayed  atomic.Int64
	probes   atomic.Int64
}

// Open binds the proxy and refuses an address that would expose it. An empty
// probe keeps the HTTP request every dependency before Redis spoke.
func Open(listenAddr, upstream, probe string) (*Proxy, error) {
	if err := bindguard.Check(listenAddr, SubjectProxy); err != nil {
		return nil, err
	}

	listener, err := net.Listen(network, listenAddr)
	if err != nil {
		return nil, err
	}

	if probe == "" {
		probe = probePayload
	}

	p := &Proxy{
		upstream:     upstream,
		listener:     listener,
		probe:        probe,
		held:         map[net.Conn]struct{}{},
		closed:       make(chan struct{}),
		sources:      map[string]int64{},
		faultSources: map[string]int64{},
	}

	p.state.Store(&armed{fault: Fault{Kind: PassThrough}})

	p.wg.Add(1)
	go p.serve()

	return p, nil
}

func (p *Proxy) Addr() string { return p.listener.Addr().String() }

func (p *Proxy) Upstream() string { return p.upstream }

func (p *Proxy) Fault() Fault { return p.state.Load().fault }

// Arm swaps the fault in and drops held connections, pooled keepalives too.
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

// Disarm returns to pass-through and releases every held connection.
func (p *Proxy) Disarm() {
	p.swap(Fault{Kind: PassThrough})
}

// swap replaces the state and releases what the old one held, as ONE
// transaction: a new fault with a stale generation is one track refuses.
func (p *Proxy) swap(fault Fault) {
	p.mu.Lock()

	previous := p.state.Load()
	p.state.Store(&armed{fault: fault, generation: previous.generation + 1})
	for address := range p.faultSources {
		p.faultSources[address] = 0
	}

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
			// Or a persistent accept error spins a core for the whole run.
			time.Sleep(drainWindow)
			continue
		}

		p.accepted.Add(1)
		p.countSource(conn.RemoteAddr())
		p.wg.Add(1)

		go func() {
			defer p.wg.Done()
			p.handle(conn)
		}()
	}
}

// handle retries under the current armed state rather than closing a stale
// connection: closing one with an unread request in its queue IS a reset.
func (p *Proxy) handle(client net.Conn) {
	defer func() { _ = client.Close() }()

	for {
		select {
		case <-p.closed:
			return
		default:
		}

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

// sever reports whether it handled the connection; false means try again.
func (p *Proxy) sever(client net.Conn, fault Fault, generation uint64) bool {
	switch fault.Kind {
	case Reset:
		// SO_LINGER 0 forces the RST but does not decide who sees it: the
		// kernel delivers it once through sk_err and the first syscall to
		// touch the socket clears it, so this wait puts it on the READ.
		settle(client)

		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.SetLinger(noLinger)
		}
		_ = client.Close()
		p.severed.Add(1)
		return true
	case EOF:
		return p.eof(client, generation)
	default:
		return p.hold(client, generation)
	}
}

// settle waits for the target's first write, or for the window.
func settle(client net.Conn) {
	if err := client.SetReadDeadline(
		time.Now().Add(settleWindow),
	); err != nil {
		return
	}

	buffer := make([]byte, copyBuffer)
	_, _ = client.Read(buffer)
}

func (p *Proxy) eof(client net.Conn, generation uint64) bool {
	if !p.track(generation, client) {
		return false
	}
	defer p.untrack(client)
	p.severed.Add(1)
	if tcp, ok := client.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			return true
		}
	}
	if err := client.SetReadDeadline(time.Now().Add(hangCeiling)); err == nil {
		_, _ = io.Copy(io.Discard, client)
	}
	return true
}

// hold implements Hang: keep the connection open and answer nothing.
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
		_, _ = io.Copy(io.Discard, client)
	}()

	select {
	case <-gone:
	case <-timer.C:
	case <-p.closed:
	}

	return true
}

// forward reports whether it handled the connection; false means try again.
func (p *Proxy) forward(client net.Conn, fault Fault, generation uint64) bool {
	upstream, err := net.DialTimeout(network, p.upstream, dialTimeout)
	if err != nil {
		// Passing the real failure through keeps the proxy transparent.
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.SetLinger(noLinger)
		}
		return true
	}
	defer func() { _ = upstream.Close() }()

	if !p.track(generation, client, upstream) {
		return false
	}
	defer p.untrack(client, upstream)

	// Only LATENCY delays the bytes, or slow-close is latency by another name.
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

		// The hold belongs to the ANSWER's half-close, not to the exchange.
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

	// Both directions must finish, or an answer or a request is truncated.
	relay.Wait()

	return true
}

// pump delays per chunk, which is a slow dependency, not a slow connection.
func (p *Proxy) pump(
	dst, src net.Conn,
	delay time.Duration,
	limit int,
	halfClose bool,
) {
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

// limitFor applies Partial to the DEPENDENCY's answer only.
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
