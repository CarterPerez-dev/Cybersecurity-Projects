// ©AngelaMos | 2026
// observe_test.go

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func armable() []Fault {
	return []Fault{
		{Kind: Hang},
		{Kind: Reset},
		{Kind: EOF},
		{Kind: Latency, Delay: 300 * time.Millisecond},
		{Kind: Partial, Bytes: 9},
		{Kind: SlowClose, Delay: 300 * time.Millisecond},
	}
}

// The failure this replaced: confirmation compared branch counters, so it
// reported a latency fault confirmed while the proxy was in pass-through and
// nothing was armed at all.
func TestObserveRefusesToConfirmWhenNothingIsArmed(t *testing.T) {
	p := through(t)

	method, confirmed, err := p.Observe(context.Background(), "")

	if confirmed {
		t.Fatalf("a pass-through proxy confirmed a fault (%q)", method)
	}

	if !errors.Is(err, ErrNothingArmed) {
		t.Fatalf("err = %v, want ErrNothingArmed", err)
	}
}

func TestObserveConfirmsEveryFaultAndStopsAfterTheRevert(t *testing.T) {
	if len(armable()) != len(Kinds()) {
		t.Fatalf(
			"this test covers %d faults but %d are registered",
			len(armable()),
			len(Kinds()),
		)
	}

	for _, fault := range armable() {
		t.Run(string(fault.Kind), func(t *testing.T) {
			p := through(t)

			if err := p.Arm(fault); err != nil {
				t.Fatalf("arm: %v", err)
			}

			method, confirmed, err := p.Observe(
				context.Background(),
				fault.Kind,
			)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			if !confirmed {
				t.Fatalf(
					"%s was armed and the proxy could not observe it; a fault khaos "+
						"cannot confirm voids the run",
					fault.Kind,
				)
			}
			if method == "" {
				t.Fatal(
					"the confirmation reported no method, so the run record cannot say how",
				)
			}

			p.Disarm()

			if _, confirmed, _ := p.Observe(
				context.Background(),
				"",
			); confirmed {
				t.Fatalf("%s still confirmed after the revert", fault.Kind)
			}
		})
	}
}

// THE negative control for the oracle. Every other test asserts confirmation
// SUCCEEDS for a correctly armed fault, which a confirmation gutted to
// `return true` also satisfies — measured, that gut left all seventeen packages
// and the Docker gate green. This arms each fault and makes the proxy forward
// anyway, so confirmation MUST refuse.
func TestObserveRefusesAFaultThatIsArmedButDoesNotHappen(t *testing.T) {
	for _, fault := range armable() {
		t.Run(string(fault.Kind), func(t *testing.T) {
			p := through(t)

			if err := p.Arm(fault); err != nil {
				t.Fatalf("arm: %v", err)
			}

			p.inert.Store(true)

			method, confirmed, _ := p.Observe(context.Background(), fault.Kind)

			if confirmed {
				t.Fatalf(
					"%s was confirmed (%q) while the proxy forwarded normally. The oracle "+
						"cannot tell an applied fault from an unapplied one, so a run would record "+
						"that the fault landed, the probes would see a healthy dependency, and the "+
						"verdict would be a clean survival",
					fault.Kind,
					method,
				)
			}
		})
	}
}

// An absolute threshold cannot tell khaos's fault from a slow dependency. The
// oracle measures the dependency on both paths and requires them to disagree.
func TestASlowDependencyDoesNotConfirmAFaultThatIsNotHappening(t *testing.T) {
	const dependencyDelay = 1200 * time.Millisecond

	slow := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(dependencyDelay)
			_, _ = io.WriteString(w, body)
		}),
	)
	defer slow.Close()

	for _, fault := range []Fault{
		{Kind: Hang},
		{Kind: Latency, Delay: 300 * time.Millisecond},
	} {
		t.Run(string(fault.Kind), func(t *testing.T) {
			p, err := Open(
				loopback,
				strings.TrimPrefix(slow.URL, "http://"),
				"",
			)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer func() { _ = p.Close() }()

			if err := p.Arm(fault); err != nil {
				t.Fatalf("arm: %v", err)
			}

			p.inert.Store(true)

			_, confirmed, _ := p.Observe(context.Background(), fault.Kind)

			if confirmed {
				t.Fatalf(
					"a dependency that takes %s to answer confirmed %s while the proxy "+
						"forwarded it untouched; khaos would credit itself for someone else's "+
						"slowness",
					dependencyDelay,
					fault.Kind,
				)
			}
		})
	}
}

// A dependency khaos cannot reach at all is not a confirmation, it is an
// unattributable observation, and saying so voids the run instead of crediting
// khaos for an outage it did not cause.
func TestAnUnreachableDependencyCannotConfirmAnything(t *testing.T) {
	p, err := Open(loopback, "127.0.0.1:1", "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = p.Close() }()

	for _, fault := range armable() {
		t.Run(string(fault.Kind), func(t *testing.T) {
			if err := p.Arm(fault); err != nil {
				t.Fatalf("arm: %v", err)
			}

			_, confirmed, err := p.Observe(context.Background(), fault.Kind)

			if confirmed {
				t.Fatalf(
					"%s was confirmed against a dependency khaos cannot reach",
					fault.Kind,
				)
			}

			if !errors.Is(err, ErrDependencyUnreachable) {
				t.Fatalf(
					"err = %v, want ErrDependencyUnreachable so the operator learns why "+
						"the run is void",
					err,
				)
			}
		})
	}
}

// A proxy that no longer exists must not confirm its own fault. Dialling a closed
// listener gives ECONNREFUSED, and accepting that as a reset let a dead proxy
// report the fault it was holding when it died.
func TestAClosedProxyDoesNotConfirmItsFault(t *testing.T) {
	p := through(t)

	if err := p.Arm(Fault{Kind: Reset}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	method, confirmed, err := p.Observe(context.Background(), Reset)

	if confirmed {
		t.Fatalf("a closed proxy confirmed %q", method)
	}

	if !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}

// A byte count that merely MATCHES the budget is what pass-through delivers when
// the answer happens to be that long. Truncation means the answer was CUT.
func TestPartialDoesNotConfirmWhenNothingWasTruncated(t *testing.T) {
	const answer = "exactly-this"

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(len(answer)))
			_, _ = io.WriteString(w, answer)
		}),
	)
	defer server.Close()

	p, err := Open(loopback, strings.TrimPrefix(server.URL, "http://"), "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = p.Close() }()

	// A complete answer always ends in an error, because that is what the peer
	// closing looks like to a reader. The byte count is the measurement.
	full, _ := p.measure(context.Background(), p.upstream, observeGrace)
	if full.total == 0 {
		t.Fatal("the control path measured nothing")
	}

	// A budget equal to the dependency's whole answer truncates nothing.
	if err := p.Arm(Fault{Kind: Partial, Bytes: int(full.total)}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	_, confirmed, _ := p.Observe(context.Background(), Partial)

	if confirmed {
		t.Fatalf(
			"a budget of %d bytes against a %d byte answer confirmed truncation; the "+
				"target received the dependency's complete answer",
			full.total,
			full.total,
		)
	}
}

// Confirmation must respect cancellation. A long delay otherwise blocks khaos
// uninterruptibly, and the design doc is explicit that a tool which LOOKS hung is
// what makes an operator reach for kill -9.
func TestObserveHonoursCancellation(t *testing.T) {
	p := through(t)

	if err := p.Arm(Fault{Kind: Hang}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	_, confirmed, _ := p.Observe(ctx, Hang)
	took := time.Since(started)

	if confirmed {
		t.Fatal("a cancelled confirmation still reported a verdict")
	}

	if took >= observeGrace {
		t.Fatalf(
			"a cancelled confirmation took %s; it ignored the context",
			took,
		)
	}
}

// The oracle must also catch the wrong fault being armed, which is the other
// thing a confirmation step is for.
func TestObserveRefusesWhenADifferentFaultIsArmed(t *testing.T) {
	p := through(t)

	if err := p.Arm(Fault{Kind: Reset}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	_, confirmed, err := p.Observe(context.Background(), Hang)

	if confirmed {
		t.Fatal("the oracle confirmed a hang while a reset was armed")
	}

	if !errors.Is(err, ErrFaultNotObserved) {
		t.Fatalf("err = %v, want ErrFaultNotObserved", err)
	}
}

// Probe traffic is khaos's own and must not be reported as the target's.
func TestConfirmationTrafficIsCountedSeparately(t *testing.T) {
	p := through(t)

	if err := p.Arm(Fault{Kind: Hang}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	before := p.Counts()

	if _, _, err := p.Observe(context.Background(), Hang); err != nil {
		t.Fatalf("observe: %v", err)
	}

	if after := p.Counts(); after.Probes <= before.Probes {
		t.Fatal(
			"a confirmation dial was not recorded as khaos's own probe, so the run record " +
				"reports it as the target's traffic",
		)
	}
}

func TestMeasureReadsBothPathsOfTheDifferential(t *testing.T) {
	p := through(t)

	direct, _ := p.measure(context.Background(), p.upstream, observeGrace)
	if direct.total == 0 {
		t.Fatal(
			"the control path measured nothing, so no differential is possible",
		)
	}

	proxied, _ := p.measure(context.Background(), p.Addr(), observeGrace)

	if proxied.total != direct.total {
		t.Fatalf(
			"pass-through delivered %d bytes where the dependency answers %d",
			proxied.total,
			direct.total,
		)
	}
}

// The oracle needs the dependency to ANSWER on the direct path, and an HTTP
// request is not something every dependency answers. Measured on
// redis:7.4-alpine: the HTTP payload gets zero bytes and a close, so the
// oracle reported the datastore unreachable and voided the limiter's run.
func TestTheConfirmationProbeSpeaksTheDependencysProtocol(t *testing.T) {
	// A dependency that answers RESP and nothing else, which is what the
	// limiter's datastore is.
	listener, err := net.Listen("tcp", loopback)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer func() { _ = conn.Close() }()

				buffer := make([]byte, 64)

				read, err := conn.Read(buffer)
				if err != nil || !strings.Contains(
					string(buffer[:read]),
					"PING",
				) {
					return
				}

				_, _ = io.WriteString(conn, "+PONG\r\n")
			}()
		}
	}()

	upstream := listener.Addr().String()

	for _, row := range []struct {
		name   string
		probe  string
		answer bool
	}{
		{"the default HTTP request", "", false},
		{"RESP", ProbeRESP, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			p, err := Open(loopback, upstream, row.probe)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer func() { _ = p.Close() }()

			direct, _ := p.measure(
				context.Background(),
				p.upstream,
				observeGrace,
			)

			if answered := direct.total > 0; answered != row.answer {
				t.Fatalf(
					"%s measured %d bytes on the direct path, want answered=%v",
					row.name,
					direct.total,
					row.answer,
				)
			}
		})
	}
}
