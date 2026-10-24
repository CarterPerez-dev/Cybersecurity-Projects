// ©AngelaMos | 2026
// proxy_test.go

package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/bindguard"
)

const (
	loopback  = "127.0.0.1:0"
	body      = "the-dependency-answered-in-full"
	probeWait = 2 * time.Second
)

func upstreamServer(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			_, _ = io.WriteString(w, body)
		}),
	)
	t.Cleanup(server.Close)

	return server
}

func through(t *testing.T) *Proxy {
	t.Helper()

	server := upstreamServer(t)

	p, err := Open(loopback, strings.TrimPrefix(server.URL, "http://"), "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	return p
}

// get returns the body, or a description of how the attempt failed. Both are
// evidence: the whole point of these faults is that the failure SHAPE differs.
func get(p *Proxy) (string, error) {
	client := &http.Client{Timeout: probeWait}

	response, err := client.Get("http://" + p.Addr())
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()

	raw, err := io.ReadAll(response.Body)

	return string(raw), err
}

func TestPassThroughDeliversTheDependencyUntouched(t *testing.T) {
	p := through(t)

	got, err := get(p)
	if err != nil {
		t.Fatalf("pass-through failed: %v", err)
	}

	if got != body {
		t.Fatalf("pass-through delivered %q, want %q", got, body)
	}
}

// Every fault has to be distinguishable from pass-through. A fault that is not
// is a run that measures nothing and reports a clean survival, which is the
// single worst outcome this tool can produce.
func TestEveryFaultIsDistinguishableFromPassThrough(t *testing.T) {
	faults := []Fault{
		{Kind: Hang},
		{Kind: Reset},
		{Kind: EOF},
		{Kind: Latency, Delay: 3 * time.Second},
		{Kind: Partial, Bytes: 8},
		{Kind: SlowClose, Delay: 3 * time.Second},
	}

	if len(faults) != len(Kinds()) {
		t.Fatalf("this test covers %d faults but %d are registered: %v",
			len(faults), len(Kinds()), Kinds())
	}

	for _, fault := range faults {
		t.Run(string(fault.Kind), func(t *testing.T) {
			p := through(t)

			if err := p.Arm(fault); err != nil {
				t.Fatalf("arm: %v", err)
			}

			started := time.Now()
			got, err := get(p)
			took := time.Since(started)

			// slow-close is the one fault whose answer is supposed to arrive
			// INTACT. It exists to find a caller that waits for the connection
			// to end instead of reading a Content-Length, so the payload has to
			// be delivered and only the close held back. It is distinguished by
			// the clock, not by a damaged body.
			//
			// It used to be distinguishable by a damaged body, because the delay
			// was applied to the relay as well as the close — which made it
			// `network.dependency_latency` wearing a different name, and meant a
			// client that timed out mid-payload was reported as one that waits
			// for the close.
			if fault.Kind == SlowClose {
				if got != body {
					t.Fatalf(
						"slow-close delivered %q, want the answer intact; holding the "+
							"PAYLOAD back makes it indistinguishable from a latency fault",
						got,
					)
				}

				// Measured at the SOCKET, not through this HTTP client. Go's
				// client reads a Content-Length body and returns without ever
				// waiting for the close — measured here at 296µs against a three
				// second hold — so an HTTP GET cannot see this fault at all.
				//
				// That is the fault behaving correctly: it exists to find a
				// caller that waits for EOF instead of reading a length, and a
				// caller that reads the length is supposed to be unaffected.
				// Asserting otherwise would be asserting that slow-close breaks
				// clients it is not meant to break.
				observable, confirmed, err := p.Observe(t.Context(), SlowClose)
				if err != nil || !confirmed {
					t.Fatalf(
						"slow-close is not observable at the socket either (%v), so nothing "+
							"distinguishes it from no fault at all: %s",
						err,
						observable,
					)
				}

				t.Logf("slow-close -> body intact after %s, and %s",
					took.Round(time.Millisecond), observable)
				return
			}

			if err == nil && got == body {
				t.Fatalf(
					"%s delivered the dependency's answer intact, so it is "+
						"indistinguishable from no fault at all",
					fault.Kind,
				)
			}

			t.Logf("%s -> body=%q err=%v", fault.Kind, got, err)
		})
	}
}

func TestResetIsRefusedWhileHangIsSilence(t *testing.T) {
	p := through(t)

	if err := p.Arm(Fault{Kind: Reset}); err != nil {
		t.Fatalf("arm reset: %v", err)
	}

	start := time.Now()
	_, resetErr := get(p)
	resetTook := time.Since(start)

	if resetErr == nil {
		t.Fatal("reset was answered successfully")
	}

	if errors.Is(resetErr, http.ErrHandlerTimeout) || resetTook >= probeWait {
		t.Fatalf(
			"reset took %s, which is a timeout rather than a refusal; a client "+
				"cannot tell it from a hang and the two hit different branches",
			resetTook,
		)
	}

	if err := p.Arm(Fault{Kind: Hang}); err != nil {
		t.Fatalf("arm hang: %v", err)
	}

	start = time.Now()
	_, hangErr := get(p)
	hangTook := time.Since(start)

	if hangErr == nil {
		t.Fatal("hang was answered successfully")
	}

	if hangTook < probeWait {
		t.Fatalf(
			"hang failed after %s, before the client's own timeout; a hang the "+
				"client distinguishes from a refusal is the whole point of having both",
			hangTook,
		)
	}
}

// Reset and EOF are only two faults if the client can tell them apart. An
// ordinary close with an empty receive queue sends FIN, so without SO_LINGER 0
// "reset" is an EOF wearing a different name and the catalogue has two entries
// for one behaviour. Measured at the socket, not through net/http, because the
// transport rewrites both into its own errors.
func TestResetIsAnRSTAndEOFIsAFIN(t *testing.T) {
	cases := []struct {
		fault     Kind
		wantReset bool
	}{
		{fault: Reset, wantReset: true},
		{fault: EOF, wantReset: false},
	}

	for _, tc := range cases {
		t.Run(string(tc.fault), func(t *testing.T) {
			p := through(t)

			if err := p.Arm(Fault{Kind: tc.fault}); err != nil {
				t.Fatalf("arm: %v", err)
			}

			// A reset can surface at connect OR at the first read depending on
			// how fast the proxy gets to it, and both are the same observable.
			// Insisting on the read would make this test flaky rather than
			// strict.
			var readErr error

			conn, dialErr := net.DialTimeout(network, p.Addr(), probeWait)
			if dialErr != nil {
				readErr = dialErr
			} else {
				defer func() { _ = conn.Close() }()

				_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")

				if err := conn.SetReadDeadline(
					time.Now().Add(probeWait),
				); err != nil {
					t.Fatalf("deadline: %v", err)
				}

				buffer := make([]byte, 64)
				_, readErr = conn.Read(buffer)
			}

			gotReset := errors.Is(readErr, syscall.ECONNRESET)
			gotEOF := errors.Is(readErr, io.EOF)

			if tc.wantReset && !gotReset {
				t.Fatalf(
					"%s produced %v, not ECONNRESET; a client cannot tell it from an "+
						"orderly close, and the two hit different branches in almost every "+
						"HTTP client",
					tc.fault,
					readErr,
				)
			}

			if !tc.wantReset && !gotEOF {
				t.Fatalf("%s produced %v, not a clean EOF", tc.fault, readErr)
			}
		})
	}
}

func TestPartialDeliversAPrefixAndThenStops(t *testing.T) {
	const budget = 12

	p := through(t)

	if err := p.Arm(Fault{Kind: Partial, Bytes: budget}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	got, _ := get(p)

	if len(got) >= len(body) {
		t.Fatalf(
			"partial delivered %d bytes of a %d byte body, so nothing was truncated",
			len(got),
			len(body),
		)
	}

	if strings.Contains(got, body) {
		t.Fatalf("partial delivered the whole body: %q", got)
	}
}

func TestLatencyDelaysRatherThanFails(t *testing.T) {
	const delay = 300 * time.Millisecond

	p := through(t)

	if err := p.Arm(Fault{Kind: Latency, Delay: delay}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	start := time.Now()
	got, err := get(p)
	took := time.Since(start)

	if err != nil {
		t.Fatalf("latency broke the connection instead of slowing it: %v", err)
	}

	if got != body {
		t.Fatalf("latency altered the body: %q", got)
	}

	if took < delay {
		t.Fatalf(
			"latency of %s took only %s, so the delay is not being applied",
			delay,
			took,
		)
	}
}

// Disarm is the whole revert. If it does not fully restore pass-through, a
// recovery window reads as a target that never came back.
func TestDisarmRestoresPassThroughCompletely(t *testing.T) {
	for _, fault := range []Fault{
		{Kind: Hang},
		{Kind: Reset},
		{Kind: EOF},
		{Kind: Latency, Delay: 2 * time.Second},
		{Kind: Partial, Bytes: 4},
		{Kind: SlowClose, Delay: 2 * time.Second},
	} {
		t.Run(string(fault.Kind), func(t *testing.T) {
			p := through(t)

			if err := p.Arm(fault); err != nil {
				t.Fatalf("arm: %v", err)
			}
			_, _ = get(p)

			p.Disarm()

			if armed := p.Fault().Kind; armed != PassThrough {
				t.Fatalf("after disarm the proxy still reads %s", armed)
			}

			got, err := get(p)
			if err != nil {
				t.Fatalf(
					"after disarming %s the proxy still fails: %v",
					fault.Kind,
					err,
				)
			}
			if got != body {
				t.Fatalf(
					"after disarming %s the proxy delivered %q",
					fault.Kind,
					got,
				)
			}
		})
	}
}

// A target holding a pooled keepalive connection established BEFORE the fault
// would otherwise keep sailing through it, and a fault nothing experiences reads
// as a clean survival.
func TestArmingDropsConnectionsOpenedBeforeTheFault(t *testing.T) {
	p := through(t)

	client, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := io.WriteString(
		client,
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
	); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(probeWait)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	buffer := make([]byte, 128)
	if _, err := client.Read(buffer); err != nil {
		t.Fatalf(
			"the established connection never answered before the fault: %v",
			err,
		)
	}

	if err := p.Arm(Fault{Kind: Hang}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	// Reading once is not enough and the first attempt at this test was wrong
	// for exactly that reason: the response above was only partly consumed, so a
	// single Read returns the REMAINDER OF THE OLD ANSWER out of the socket
	// buffer and looks indistinguishable from a connection still being served.
	// The connection must be drained until it actually ends.
	if err := client.SetReadDeadline(time.Now().Add(probeWait)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	for {
		_, err = client.Read(buffer)
		if err == nil {
			continue
		}

		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf(
				"a connection established before the fault was neither dropped nor ended " +
					"after arming; a target on a pooled keepalive connection would sail straight " +
					"through the fault and the run would report a clean survival",
			)
		}

		return
	}
}

// Closing the proxy IS the rollback of last resort. The fault has to die with the
// process, because that is the tier's entire safety argument.
func TestClosingTheProxyRemovesTheFaultEntirely(t *testing.T) {
	p := through(t)

	if err := p.Arm(Fault{Kind: Hang}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	addr := p.Addr()

	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	conn, err := net.DialTimeout("tcp", addr, probeWait)
	if err == nil {
		_ = conn.Close()
		t.Fatal(
			"the proxy still accepts connections after Close, so the fault outlived it",
		)
	}

	if err := p.Arm(Fault{Kind: Reset}); !errors.Is(err, ErrClosed) {
		t.Fatalf("arming a closed proxy returned %v, want ErrClosed", err)
	}
}

// An incomplete fault is indistinguishable from pass-through at runtime, so it
// has to be refused at arm time rather than silently measured.
func TestAFaultThatCannotExpressItselfIsRefused(t *testing.T) {
	p := through(t)

	for _, fault := range []Fault{
		{Kind: Latency},
		{Kind: SlowClose},
		{Kind: Partial},
	} {
		t.Run(string(fault.Kind), func(t *testing.T) {
			if err := p.Arm(fault); !errors.Is(err, ErrFaultIncomplete) {
				t.Fatalf(
					"arm(%+v) = %v, want ErrFaultIncomplete; without a parameter this "+
						"fault forwards everything untouched and reports a clean survival",
					fault,
					err,
				)
			}

			if armed := p.Fault().Kind; armed != PassThrough {
				t.Fatalf(
					"a refused fault still changed the armed state to %s",
					armed,
				)
			}
		})
	}
}

func TestAnUnreachableDependencyIsNotMistakenForAFault(t *testing.T) {
	p, err := Open(loopback, "127.0.0.1:1", "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = p.Close() }()

	if _, err := get(p); err == nil {
		t.Fatal(
			"the proxy invented an answer for a dependency it could not reach",
		)
	}

	if counts := p.Counts(); counts.Relayed != 0 {
		t.Fatalf(
			"the proxy counted %d relayed chunks to a dead upstream",
			counts.Relayed,
		)
	}
}

func TestParseKindRefusesPassThroughAndNonsense(t *testing.T) {
	for _, name := range []string{string(PassThrough), "", "latencyy", "RESET"} {
		if _, err := ParseKind(name); !errors.Is(err, ErrUnknownKind) {
			t.Fatalf("ParseKind(%q) = %v, want ErrUnknownKind", name, err)
		}
	}

	for _, name := range Kinds() {
		if _, err := ParseKind(name); err != nil {
			t.Fatalf("ParseKind(%q) rejected a registered fault: %v", name, err)
		}
	}
}

func TestSeveringAndForwardingFaultsAreSeparated(t *testing.T) {
	severing := map[Kind]bool{Hang: true, Reset: true, EOF: true}

	for _, name := range Kinds() {
		kind := Kind(name)
		fault := Fault{Kind: kind, Delay: time.Second, Bytes: 1}

		if fault.Severs() != severing[kind] {
			t.Fatalf(
				"%s reports Severs()=%v; khaos confirms a severing fault by proving the "+
					"dependency is unreachable and a forwarding one by proving the stream was "+
					"altered, and one cannot stand in for the other",
				kind,
				fault.Severs(),
			)
		}
	}
}

func TestSlowCloseHoldsTheConnectionOpenAfterTheAnswer(t *testing.T) {
	const delay = 600 * time.Millisecond

	p := through(t)

	if err := p.Arm(Fault{Kind: SlowClose, Delay: delay}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	conn, err := net.DialTimeout(network, p.Addr(), probeWait)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Connection: close is load-bearing. Without it the upstream keeps the
	// connection alive, the answer leg never finishes, and the "hold" being
	// measured is the test's own read deadline rather than the fault.
	_, _ = io.WriteString(
		conn,
		"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
	)
	_ = conn.SetReadDeadline(time.Now().Add(probeWait * 4))

	buffer := make([]byte, 4096)
	var lastByte, ended time.Time

	for {
		read, err := conn.Read(buffer)
		if read > 0 {
			lastByte = time.Now()
		}
		if err != nil {
			ended = time.Now()
			break
		}
	}

	if lastByte.IsZero() {
		t.Fatal(
			"slow-close delivered nothing at all, so it is not a slow CLOSE",
		)
	}

	held := ended.Sub(lastByte)
	if held < delay {
		t.Fatalf(
			"the stream ended %s after the last byte, want at least %s; slow-close is not "+
				"holding the connection open and is only distinguishable from pass-through because "+
				"it also delays every chunk, which is what latency does",
			held,
			delay,
		)
	}
}

func TestEOFStaysAFINWhenTheRequestIsLargerThanOneRead(t *testing.T) {
	p := through(t)

	if err := p.Arm(Fault{Kind: EOF}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	for attempt := range 6 {
		conn, err := net.DialTimeout(network, p.Addr(), probeWait)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}

		body := strings.Repeat("x", 4<<20)
		go func() {
			_, _ = io.WriteString(
				conn,
				"POST / HTTP/1.1\r\nHost: x\r\n\r\n"+body,
			)
		}()

		_ = conn.SetReadDeadline(time.Now().Add(probeWait))
		_, readErr := conn.Read(make([]byte, 64))
		_ = conn.Close()

		if errors.Is(readErr, syscall.ECONNRESET) {
			t.Fatalf(
				"attempt %d: eof produced ECONNRESET on a request larger than one read, so "+
					"it is a nondeterministic duplicate of reset after all",
				attempt,
			)
		}
	}
}

func TestArmRefusesAFaultWhoseKindIsNotRegistered(t *testing.T) {
	p := through(t)

	for _, fault := range []Fault{
		{},
		{Kind: "not-a-fault"},
		{Kind: Kind(string(Hang) + " ")},
		{Kind: PassThrough},
	} {
		if err := p.Arm(fault); err == nil {
			t.Fatalf(
				"Arm(%+v) was accepted; an unrecognised kind forwards every byte untouched "+
					"and the run reports a clean survival",
				fault,
			)
		}

		if armed := p.Fault().Kind; armed != PassThrough {
			t.Fatalf("a refused fault changed the armed state to %q", armed)
		}
	}
}

// A client that half-closes after its request is an ordinary HTTP client shape.
// The baseline is measured through the proxy, so getting this wrong makes a
// healthy dependency read as a dead one before any fault is armed.
func TestAHalfClosingClientStillReceivesTheWholeAnswer(t *testing.T) {
	p := through(t)

	conn, err := net.DialTimeout(network, p.Addr(), probeWait)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("expected a TCP connection")
	}

	if _, err := io.WriteString(
		tcp,
		"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
	); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := tcp.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	_ = tcp.SetReadDeadline(time.Now().Add(probeWait * 2))

	answer, err := io.ReadAll(tcp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if !strings.Contains(string(answer), body) {
		t.Fatalf(
			"a half-closing client received %d bytes and never the answer; pass-through "+
				"dropped it: %q",
			len(answer),
			string(answer),
		)
	}
}

// The containment property is the tier's whole safety argument, so it needs an
// input it MUST refuse rather than a comment saying what callers should pass.
func TestOpenRefusesAnAddressThatWouldExposeTheProxy(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "[::]:0", "0.0.0.0:45001"} {
		p, err := Open(addr, "127.0.0.1:1", "")
		if err == nil {
			bound := p.Addr()
			_ = p.Close()
			t.Fatalf(
				"Open(%q) bound %s; a fault proxy in front of a deliberately vulnerable "+
					"dependency must not be reachable off the host",
				addr,
				bound,
			)
		}
	}
}

func TestDisarmReleasesAConnectionThatRacedTheRevert(t *testing.T) {
	p := through(t)

	for attempt := range 300 {
		if err := p.Arm(Fault{Kind: Hang}); err != nil {
			t.Fatalf("arm: %v", err)
		}

		conn, err := net.DialTimeout(network, p.Addr(), probeWait)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}

		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		p.Disarm()

		_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		_, readErr := conn.Read(make([]byte, 64))
		_ = conn.Close()

		var timeout net.Error
		if errors.As(readErr, &timeout) && timeout.Timeout() {
			t.Fatalf(
				"attempt %d: a hung connection was still held 400ms after Disarm. The "+
					"ceiling is %s against a %s recovery window, so the target reads as one that "+
					"never came back and khaos manufactures the verdict itself",
				attempt,
				hangCeiling,
				"5s",
			)
		}
	}
}

// The LAN address is the finding this exists for: the first version of safeBind
// refused only a wildcard, so it accepted this host's own routable address, which
// is both the off-box exposure its error warns about and useless, because a
// container cannot reach the LAN address at all.
func TestOpenRefusesThisHostsRoutableAddress(t *testing.T) {
	routable := ""

	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("interfaces: %v", err)
	}

	for _, iface := range interfaces {
		if _, err := os.Stat(
			filepath.Join(
				bindguard.SysClassNet,
				iface.Name,
				bindguard.BridgeMarker,
			),
		); err == nil {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			network, ok := addr.(*net.IPNet)
			if !ok || network.IP.IsLoopback() || network.IP.To4() == nil {
				continue
			}
			routable = network.IP.String()
		}
	}

	if routable == "" {
		t.Skip("this host has no non-bridge routable IPv4 address to try")
	}

	p, err := Open(net.JoinHostPort(routable, "45999"), "127.0.0.1:1", "")
	if err == nil {
		bound := p.Addr()
		_ = p.Close()
		t.Fatalf(
			"Open bound %s, which is reachable from outside this host",
			bound,
		)
	}

	if !errors.Is(err, ErrUnsafeBind) {
		t.Fatalf("err = %v, want ErrUnsafeBind", err)
	}
}

// The bridge gateway MUST be accepted, or the only address a container can reach
// khaos on is refused and the tier cannot run at all.
func TestOpenAcceptsABridgeAddress(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("interfaces: %v", err)
	}

	for _, iface := range interfaces {
		if _, err := os.Stat(
			filepath.Join(
				bindguard.SysClassNet,
				iface.Name,
				bindguard.BridgeMarker,
			),
		); err != nil {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			network, ok := addr.(*net.IPNet)
			if !ok || network.IP.To4() == nil {
				continue
			}

			p, err := Open(
				net.JoinHostPort(network.IP.String(), "0"),
				"127.0.0.1:1",
				"",
			)
			if err != nil {
				t.Fatalf(
					"Open refused the bridge address %s: %v",
					network.IP,
					err,
				)
			}
			_ = p.Close()

			return
		}
	}

	t.Skip("this host has no bridge interface with an IPv4 address")
}

// Reset has two mechanisms and each covers a case the other cannot, so each needs
// its own control or they alibi one another: with both present either alone
// usually produces RST and the gate stops detecting the loss of either.
//
// This is the SO_LINGER case specifically. A target that connects and sends
// nothing leaves an EMPTY receive queue, so awaitRequest has nothing to hold back
// and an ordinary close would send FIN, which is the eof fault wearing the wrong
// name.
func TestResetIsStillAnRSTWhenTheTargetSendsNothing(t *testing.T) {
	p := through(t)

	if err := p.Arm(Fault{Kind: Reset}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	for attempt := range 10 {
		conn, err := net.DialTimeout(network, p.Addr(), probeWait)
		if err != nil {
			if isReset(err) {
				continue
			}
			t.Fatalf("dial: %v", err)
		}

		// Deliberately no write. awaitRequest will time out on an empty queue and
		// only SO_LINGER 0 can still force a reset.
		_ = conn.SetReadDeadline(time.Now().Add(probeWait))
		_, readErr := conn.Read(make([]byte, 64))
		_ = conn.Close()

		if errors.Is(readErr, io.EOF) {
			t.Fatalf(
				"attempt %d: a target that sent nothing got a clean EOF, so reset degraded "+
					"into the eof fault",
				attempt,
			)
		}

		if !isReset(readErr) {
			t.Fatalf("attempt %d: got %v, want a reset", attempt, readErr)
		}
	}
}
