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

var ErrNoProxy = errors.New(
	"this mutation needs a fault proxy that is not running",
)

var ErrProxyFaultMismatch = errors.New(
	"the armed proxy fault does not match the mutation being applied",
)

// ProxyKind is one-to-one with the proxy fault kinds, so the catalogue names
// the actual fault rather than a generic "proxy" entry.
func ProxyKind(kind proxy.Kind) string {
	return KindProxyPrefix + string(kind)
}

// proxyMutator's whole mutation is a single atomic pointer swap, which is why
// this tier cannot half-apply and its rollback cannot partially fail.
type proxyMutator struct {
	kind proxy.Kind
}

func init() {
	for _, name := range proxy.Kinds() {
		kind := proxy.Kind(name)
		registry[ProxyKind(kind)] = proxyMutator{kind: kind}
	}
}

// Describe carries the actual magnitude; the kind alone prints a zero where the
// magnitude belongs and understates what it asks permission for.
func (m proxyMutator) Describe(env Env, target dockerx.Target) string {
	fault := env.ProxyFault
	if fault.Kind != m.kind {
		fault = proxy.Fault{Kind: m.kind}
	}

	return fmt.Sprintf(describeProxy, fault.Describe(target.Name))
}

// Plan's payload is also the only durable record of what the run did, since
// the proxy itself dies with the process.
func (m proxyMutator) Plan(
	_ context.Context,
	env Env,
	_ dockerx.Target,
) (json.RawMessage, error) {
	if env.Proxy == nil {
		return nil, fmt.Errorf(errNoProxy, ErrNoProxy, ProxyKind(m.kind))
	}

	if env.ProxyFault.Kind != m.kind {
		return nil, fmt.Errorf(
			errWrongFault,
			ErrProxyFaultMismatch,
			env.ProxyFault.Kind,
			m.kind,
		)
	}

	if err := env.ProxyFault.Validate(); err != nil {
		return nil, err
	}

	return journal.EncodePayload(env.ProxyFault)
}

func (m proxyMutator) Apply(
	_ context.Context,
	env Env,
	_ dockerx.Target,
	raw json.RawMessage,
) error {
	if env.Proxy == nil {
		return fmt.Errorf(errNoProxy, ErrNoProxy, ProxyKind(m.kind))
	}

	var fault proxy.Fault
	if err := json.Unmarshal(raw, &fault); err != nil {
		return err
	}

	return env.Proxy.Arm(fault)
}

// Revert on a cold start has no proxy to disarm, and that is RESOLVED rather
// than failed: the proxy died with the process, so the fault went with it.
func (m proxyMutator) Revert(
	_ context.Context,
	env Env,
	_ journal.Record,
) error {
	if env.Proxy == nil {
		return nil
	}

	env.Proxy.Disarm()

	return nil
}

// Confirm returns what the proxy's socket-level read-back measured, never a
// counter: a counter records which branch the dispatcher chose, so it would
// confirm a severing fault while the dependency is fully reachable.
func (m proxyMutator) Confirm(
	ctx context.Context,
	env Env,
	_ dockerx.Target,
) (string, bool, error) {
	if env.Proxy == nil {
		return "", false, fmt.Errorf(errNoProxy, ErrNoProxy, ProxyKind(m.kind))
	}

	return env.Proxy.Observe(ctx, m.kind)
}

// Prefix declares this tier's kinds to the registry, which is how `khaos
// inject` knows not to offer a fault that only exists inside a run.
func (proxyMutator) Prefix() string { return KindProxyPrefix }
