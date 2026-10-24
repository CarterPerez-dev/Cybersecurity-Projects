// ©AngelaMos | 2026
// proxyfault_test.go

package inject

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/inject/proxy"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const (
	loopback = "127.0.0.1:0"
	answer   = "the-dependency-answered"
)

func armed(t *testing.T, fault proxy.Fault) Env {
	t.Helper()

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, answer)
		}),
	)
	t.Cleanup(server.Close)

	p, err := proxy.Open(
		loopback,
		strings.TrimPrefix(server.URL, "http://"),
		"",
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	return Env{Proxy: p, ProxyFault: fault}
}

func kinds() []proxy.Fault {
	return []proxy.Fault{
		{Kind: proxy.Hang},
		{Kind: proxy.Reset},
		{Kind: proxy.EOF},
		{Kind: proxy.Latency, Delay: 300 * time.Millisecond},
		{Kind: proxy.Partial, Bytes: 9},
		{Kind: proxy.SlowClose, Delay: 300 * time.Millisecond},
	}
}

// The whole mutation, end to end, for every registered proxy fault: journal the
// fault, arm it, confirm it by socket read-back, revert it, and prove the
// dependency is reachable again afterwards.
func TestEveryProxyFaultAppliesConfirmsAndReverts(t *testing.T) {
	// Counted by the PROXY prefix, not by "not direct". The identity provider
	// tier is also not direct, so the looser count started reporting 23 the
	// moment that tier landed and this census would have had to be weakened to
	// pass rather than tightened.
	registered := 0
	for _, kind := range Kinds() {
		if strings.HasPrefix(kind, KindProxyPrefix) {
			registered++
		}
	}

	if registered != len(kinds()) {
		t.Fatalf(
			"this test covers %d proxy faults but %d are registered",
			len(kinds()),
			registered,
		)
	}

	for _, fault := range kinds() {
		t.Run(string(fault.Kind), func(t *testing.T) {
			env := armed(t, fault)
			ctx := context.Background()
			target := dockerx.Target{ID: "abc", Name: "a-dependency"}

			mutator, err := Lookup(ProxyKind(fault.Kind))
			if err != nil {
				t.Fatalf("lookup: %v", err)
			}

			payload, err := mutator.Plan(ctx, env, target)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}

			var journaled proxy.Fault
			if err := json.Unmarshal(payload, &journaled); err != nil {
				t.Fatalf(
					"the journalled payload does not describe the fault: %v",
					err,
				)
			}
			if journaled != fault {
				t.Fatalf(
					"journalled %+v, armed %+v; the journal is the only durable record of "+
						"what this run did, because the proxy dies with the process",
					journaled,
					fault,
				)
			}

			if err := mutator.Apply(ctx, env, target, payload); err != nil {
				t.Fatalf("apply: %v", err)
			}

			if got := env.Proxy.Fault(); got != fault {
				t.Fatalf(
					"after apply the proxy holds %+v, want %+v",
					got,
					fault,
				)
			}

			method, confirmed, err := mutator.Confirm(ctx, env, target)
			if err != nil {
				t.Fatalf("confirm: %v", err)
			}
			if !confirmed {
				t.Fatalf(
					"%s applied but could not be confirmed, so every run of it is void",
					fault.Kind,
				)
			}

			// The run record has to carry what was MEASURED. A constant naming the
			// technique is not evidence a reader can audit.
			if method == "" || method == confirmProxy {
				t.Fatalf(
					"%s confirmed with %q rather than the observable it measured",
					fault.Kind,
					method,
				)
			}

			if err := mutator.Revert(ctx, env, journal.Record{}); err != nil {
				t.Fatalf("revert: %v", err)
			}

			if got := env.Proxy.Fault().Kind; got != proxy.PassThrough {
				t.Fatalf("after revert the proxy holds %s", got)
			}

			if body := reach(
				t,
				env.Proxy.Addr(),
			); !strings.Contains(
				body,
				answer,
			) {
				t.Fatalf(
					"after reverting %s the dependency is still not reachable through the "+
						"proxy, got %q",
					fault.Kind,
					body,
				)
			}
		})
	}
}

func reach(t *testing.T, addr string) string {
	t.Helper()

	client := &http.Client{Timeout: 3 * time.Second}

	response, err := client.Get("http://" + addr)
	if err != nil {
		return err.Error()
	}
	defer func() { _ = response.Body.Close() }()

	raw, _ := io.ReadAll(response.Body)

	return string(raw)
}

func TestAProxyMutationWithoutAProxyIsRefusedByName(t *testing.T) {
	ctx := context.Background()
	target := dockerx.Target{ID: "abc", Name: "dep"}

	mutator, err := Lookup(ProxyKind(proxy.Hang))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	empty := Env{}

	if _, err := mutator.Plan(ctx, empty, target); !errors.Is(err, ErrNoProxy) {
		t.Fatalf("plan without a proxy returned %v, want ErrNoProxy", err)
	}

	if err := mutator.Apply(
		ctx,
		empty,
		target,
		nil,
	); !errors.Is(
		err,
		ErrNoProxy,
	) {
		t.Fatalf("apply without a proxy returned %v, want ErrNoProxy", err)
	}

	if _, _, err := mutator.Confirm(
		ctx,
		empty,
		target,
	); !errors.Is(
		err,
		ErrNoProxy,
	) {
		t.Fatalf("confirm without a proxy returned %v, want ErrNoProxy", err)
	}
}

// A run cannot arm one fault and journal another.
func TestPlanRefusesAFaultTheRunDidNotArm(t *testing.T) {
	env := armed(t, proxy.Fault{Kind: proxy.Reset})

	mutator, err := Lookup(ProxyKind(proxy.Hang))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	_, err = mutator.Plan(
		context.Background(),
		env,
		dockerx.Target{ID: "a", Name: "dep"},
	)
	if !errors.Is(err, ErrProxyFaultMismatch) {
		t.Fatalf("err = %v, want ErrProxyFaultMismatch", err)
	}
}

// A cold start has no proxy, and the fault provably died with the process that
// held it. Reporting that as a failure would wedge the journal record forever,
// and `khaos reap` stops on a sweep error, which disables the dead man's switch
// for every other fault on the machine.
func TestRevertingWithoutAProxyIsResolvedRatherThanFailed(t *testing.T) {
	mutator, err := Lookup(ProxyKind(proxy.Hang))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if err := mutator.Revert(
		context.Background(),
		Env{},
		journal.Record{},
	); err != nil {
		t.Fatalf(
			"revert on a cold start returned %v; it must resolve, because the proxy died "+
				"with the process and the fault went with it",
			err,
		)
	}
}

// khaos inject acts on containers. A proxy fault acts on a path and an identity
// provider trap acts on a goroutine inside the run; both exist only while the
// run that owns them does, so neither may be offered there.
//
// The exclusion is asserted PER PREFIX rather than in aggregate. Checking only
// that something is excluded lets one tier's exclusion alibi the other's: this
// test passed the whole time the identity tier was unreachable from DirectKinds
// by accident rather than by the registry knowing about it.
func TestInProcessKindsAreNotOfferedForDirectInjection(t *testing.T) {
	prefixes := PerRunPrefixes()

	if len(prefixes) == 0 {
		t.Fatal(
			"no tier declares a per-run prefix, so this test asserts nothing",
		)
	}

	// Obligations are the third category and are DERIVED too: khaos's own
	// recovery bookkeeping, resolvable by Lookup and never offered.
	obligations := ObligationKinds()

	for _, kind := range Kinds() {
		wantDirect := !slices.Contains(obligations, kind)
		for _, prefix := range prefixes {
			if strings.HasPrefix(kind, prefix) {
				wantDirect = false
			}
		}

		if IsDirect(kind) != wantDirect {
			t.Errorf(
				"%s: IsDirect reports %v, want %v",
				kind,
				IsDirect(kind),
				wantDirect,
			)
		}
	}

	for _, prefix := range prefixes {
		excluded := 0

		for _, kind := range Kinds() {
			if strings.HasPrefix(kind, prefix) {
				excluded++
			}
		}

		if excluded == 0 {
			t.Errorf(
				"no kind carries the %q prefix, so excluding it proves nothing",
				prefix,
			)
		}

		for _, kind := range DirectKinds() {
			if strings.HasPrefix(kind, prefix) {
				t.Errorf("DirectKinds offers %s", kind)
			}
		}
	}

	if len(DirectKinds()) >= len(Kinds()) {
		t.Fatal("DirectKinds excludes nothing, so the distinction is inert")
	}
}

func TestTheProxyBindRefusesAnExposedAddress(t *testing.T) {
	if _, err := proxy.Open("0.0.0.0:0", "127.0.0.1:1", ""); err == nil {
		t.Fatal("the fault proxy bound every address on the host")
	}

	listener, err := net.Listen("tcp", loopback)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_ = listener.Close()
}
