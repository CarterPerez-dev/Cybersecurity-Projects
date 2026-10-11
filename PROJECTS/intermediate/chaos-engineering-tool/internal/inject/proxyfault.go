// ©AngelaMos | 2026
// proxyfault.go

package inject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/inject/proxy"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const (
	KindProxyPrefix = "proxy-"

	errNoProxy    = "%w: %s needs khaos's fault proxy, and this run did not start one"
	errWrongFault = "%w: this run armed %q but the mutation is %q"

	confirmProxy = "dialling khaos's own fault proxy and asserting the observable the armed fault is"

	describeProxy = "%s, through khaos's own proxy, which holds no capabilities and cannot reach the host"
)

var ErrNoProxy = errors.New("this mutation needs a fault proxy that is not running")

var ErrProxyFaultMismatch = errors.New("the armed proxy fault does not match the mutation being applied")

// ProxyKind names the mutation that arms one proxy fault. The proxy fault kinds
// and the mutation kinds are deliberately one-to-one, so `khaos catalog` names
// the actual fault rather than a generic "proxy" entry.
func ProxyKind(kind proxy.Kind) string {
	return KindProxyPrefix + string(kind)
}

// proxyMutator arms a fault on khaos's in-process proxy. The whole mutation is a
// single atomic pointer swap, which is why this tier cannot half-apply and why
// its rollback cannot partially fail.
type proxyMutator struct {
	kind proxy.Kind
}

func init() {
	for _, name := range proxy.Kinds() {
		kind := proxy.Kind(name)
		registry[ProxyKind(kind)] = proxyMutator{kind: kind}
	}
}

// Describe states the fault the operator is about to consent to, with its actual
// magnitude. Reading the kind alone and leaving the parameters at zero printed
// "delay every byte ... by 0s" for a three second latency fault, which is the
// plan line understating the fault it is asking permission for.
func (m proxyMutator) Describe(env Env, target dockerx.Target) string {
	fault := env.ProxyFault
	if fault.Kind != m.kind {
		fault = proxy.Fault{Kind: m.kind}
	}

	return fmt.Sprintf(describeProxy, fault.Describe(target.Name))
}

// Plan journals the fault that is about to be armed. For every other tier the
// payload is what the revert needs; here it is also the only durable record of
// what the run actually did, since the proxy itself dies with the process.
func (m proxyMutator) Plan(_ context.Context, env Env, _ dockerx.Target) (json.RawMessage, error) {
	if env.Proxy == nil {
		return nil, fmt.Errorf(errNoProxy, ErrNoProxy, ProxyKind(m.kind))
	}

	if env.ProxyFault.Kind != m.kind {
		return nil, fmt.Errorf(errWrongFault, ErrProxyFaultMismatch, env.ProxyFault.Kind, m.kind)
	}

	if err := env.ProxyFault.Validate(); err != nil {
		return nil, err
	}

	return journal.EncodePayload(env.ProxyFault)
}

func (m proxyMutator) Apply(_ context.Context, env Env, _ dockerx.Target, raw json.RawMessage) error {
	if env.Proxy == nil {
		return fmt.Errorf(errNoProxy, ErrNoProxy, ProxyKind(m.kind))
	}

	var fault proxy.Fault
	if err := json.Unmarshal(raw, &fault); err != nil {
		return err
	}

	return env.Proxy.Arm(fault)
}

// Revert disarms. A cold start has no proxy to disarm, and that is RESOLVED
// rather than failed: the proxy died with the process that held it, so the fault
// provably went with it. Reporting that as a failure would wedge the journal
// record forever and, because `khaos reap` stops on a sweep error, would disable
// the dead man's switch for every other fault on the machine.
func (m proxyMutator) Revert(_ context.Context, env Env, _ journal.Record) error {
	if env.Proxy == nil {
		return nil
	}

	env.Proxy.Disarm()

	return nil
}

// Confirm delegates to the proxy's own socket-level read-back and returns the
// specific observable it measured, so the run record says what was actually seen
// rather than a constant describing the technique. It deliberately does NOT
// compare counters: a counter incremented by the dispatcher records which branch
// was chosen, not what reached the wire, so counter comparison confirms a fault
// that is not armed and confirms a severing fault while the dependency is fully
// reachable.
func (m proxyMutator) Confirm(ctx context.Context, env Env, _ dockerx.Target) (string, bool, error) {
	if env.Proxy == nil {
		return "", false, fmt.Errorf(errNoProxy, ErrNoProxy, ProxyKind(m.kind))
	}

	return env.Proxy.Observe(ctx, m.kind)
}
