// ©AngelaMos | 2026
// helpers_test.go

package dnsrv

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

const (
	testHost     = "dependency.khaos.test."
	testControl  = "control.khaos.test."
	testAddress  = "10.77.77.7"
	testNonce    = "test-nonce-0123456789abcdef"
	testUpstream = "upstream.elsewhere.test."
	testUpAddr   = "10.88.88.8"
	loopbackAny  = "127.0.0.1:0"

	// Distinct from DefaultWrongAddress so the oracle census can tell an armed
	// rotation from an armed redirect.
	testRotatedAddress = "10.99.99.9"
)

// testUpstreamServer is a resolver khaos is NOT authoritative for, so the
// forwarding path can be exercised without reaching anything real. It answers
// exactly one name, which is what makes "khaos forwarded this" distinguishable
// from "khaos invented an answer".
func testUpstreamServer(t *testing.T) string {
	t.Helper()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)

		if len(req.Question) > 0 &&
			dns.CanonicalName(req.Question[0].Name) == testUpstream &&
			req.Question[0].Qtype == dns.TypeA {
			rr, err := dns.NewRR(
				fmt.Sprintf("%s 42 IN A %s", testUpstream, testUpAddr),
			)
			if err == nil {
				reply.Answer = append(reply.Answer, rr)
			}
		} else {
			reply.SetRcode(req, dns.RcodeNameError)
		}

		_ = w.WriteMsg(reply)
	})

	conn, listener, err := bindBoth(loopbackAny)
	if err != nil {
		t.Fatalf("bind test upstream: %v", err)
	}

	udp := &dns.Server{PacketConn: conn, Handler: mux}
	tcp := &dns.Server{Listener: listener, Handler: mux}

	started := make(chan struct{}, 2)
	udp.NotifyStartedFunc = func() { started <- struct{}{} }
	tcp.NotifyStartedFunc = func() { started <- struct{}{} }

	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()

	<-started
	<-started

	t.Cleanup(func() {
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
	})

	return conn.LocalAddr().String()
}

// startResolver brings up a resolver and its control surface on loopback high
// ports and returns a client pointed at both.
//
// Nothing here needs port 53 or a container, which is the property that makes
// the whole tier testable: the container exists because khaos cannot BIND 53,
// not because the resolver needs one.
func startResolver(t *testing.T) (*Resolver, *Client) {
	t.Helper()

	upstream := testUpstreamServer(t)

	resolver, err := New(Config{
		Listen:   loopbackAny,
		Upstream: upstream,
		Nonce:    testNonce,
		Control:  testControl,
		Zone: map[string]string{
			testHost:    testAddress,
			testControl: testAddress,
		},
	})
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}

	if err := resolver.Serve(); err != nil {
		t.Fatalf("serve: %v", err)
	}

	if err := resolver.ServeControl(loopbackAny); err != nil {
		t.Fatalf("serve control: %v", err)
	}

	t.Cleanup(func() { _ = resolver.Shutdown() })

	client := NewClient(
		resolver.Addr(),
		"http://"+resolver.ControlAddr(),
		testNonce,
		testControl,
	)

	// The zone SNAPSHOT, taken before any fault, exactly as the CLI takes it
	// when it attaches to a running resolver. Without it the oracle has no
	// record of what a name answered before khaos touched it, which the
	// rotation's confirmation needs and which wrong-address's observable has
	// been printing as "unknown" in every test until now.
	client.Zone = resolver.Zone()

	return resolver, client
}

// ask is the test's own exchange, used where a test needs to see the raw reply
// rather than the oracle's verdict.
func ask(t *testing.T, client *Client, name, proto string) answer {
	t.Helper()
	return client.ask(name, proto)
}

func mustArm(t *testing.T, client *Client, trap Trap) {
	t.Helper()

	if _, err := client.Arm(t.Context(), trap); err != nil {
		t.Fatalf("arm %s: %v", trap.Kind, err)
	}
}

// deliverableKinds is every fault khaos actually serves. Tests iterate it so a
// new kind cannot be added without the controls below covering it.
func deliverableKinds() []Kind {
	out := make([]Kind, 0, len(Kinds()))
	for _, name := range Kinds() {
		kind := Kind(name)
		if Deliverable(kind) {
			out = append(out, kind)
		}
	}
	return out
}

// trapFor builds a minimal valid trap for a kind, so a table-driven control can
// cover every kind without restating magnitudes.
func trapFor(kind Kind) Trap {
	trap := Trap{Kind: kind, Host: testHost}

	// A rotation needs a destination, and a DIFFERENT one from wrong-address's
	// default: asking the wrong-address oracle about an armed rotation has to
	// REFUTE, and it cannot if both move the name to the same place.
	if kind == AddressRotated {
		trap.Address = testRotatedAddress
	}

	if kind == SlowResponse {
		// Well above the oracle's differential margin and well under the
		// embedded resolver's ceiling, so the control is not deciding on noise.
		trap.Delay = slowMargin * 2
	}

	return trap
}
