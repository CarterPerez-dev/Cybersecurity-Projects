// ©AngelaMos | 2026
// dnsfault.go

package inject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const (
	KindDNSPrefix = "dns-"

	errNoResolver = "%w: %s needs khaos's chaos resolver, and this run has none"

	describeDNS = "%s, at khaos's own chaos resolver, which serves DNS inside its own container with nothing published to the host"
)

var ErrNoResolver = errors.New(
	"this mutation needs khaos's chaos resolver, which is not running",
)

// DNSKind names the mutation that arms one fault on khaos's chaos resolver. The
// fault kinds and the mutation kinds are one-to-one, so `khaos catalog` names
// the actual defect being provoked rather than a generic "DNS" entry.
func DNSKind(kind dnsrv.Kind) string {
	return KindDNSPrefix + string(kind)
}

// dnsMutator arms a fault on khaos's chaos resolver.
//
// This is a FIFTH tier, and the reason it is its own tier rather than a fourth
// authority is measured rather than architectural taste. Every other authority
// khaos plays — the identity provider, the certificate authority — is a
// goroutine in khaos's own process, bound on a high host port the target was
// told to dial. A DNS resolver cannot be: `--dns` carries an address and no
// port, the daemon rejects one at container start, and an unprivileged process
// gets `bind: permission denied` on port 53 at every address including
// loopback. So this authority lives in a container, which is the only place a
// process can hold port 53 without khaos holding a capability.
//
// The fault it injects is also unlike the others. The dependency is healthy and
// reachable; the target cannot FIND it, or finds something else. That is a third
// branch of the target's code, distinct from both an unreachable dependency and
// one whose certificate will not verify.
type dnsMutator struct {
	kind dnsrv.Kind
}

func init() {
	for _, name := range dnsrv.Kinds() {
		kind := dnsrv.Kind(name)
		registry[DNSKind(kind)] = dnsMutator{kind: kind}
	}
}

func (m dnsMutator) Describe(env Env, target dockerx.Target) string {
	trap := env.DNSTrap
	if trap.Kind != m.kind {
		trap = dnsrv.Trap{Kind: m.kind}
	}

	return fmt.Sprintf(describeDNS, trap.Describe(target.Name))
}

// dnsPayload is what the journal carries. It records how to reach the resolver
// as well as the fault, because the revert has to work from a COLD START where
// khaos remembers nothing — and unlike every other in-process tier, this one's
// authority outlives the khaos process that armed it. A fault left armed by a
// killed khaos is a target whose dependency stays unresolvable, so the record
// has to be enough to undo it without the run that made it.
type dnsPayload struct {
	Trap    dnsrv.Trap `json:"trap"`
	Network string     `json:"network"`
	Address string     `json:"address"`
	Control string     `json:"control"`
}

func (m dnsMutator) Plan(
	_ context.Context,
	env Env,
	_ dockerx.Target,
) (json.RawMessage, error) {
	if env.Resolver == nil {
		return nil, fmt.Errorf(errNoResolver, ErrNoResolver, DNSKind(m.kind))
	}

	if env.DNSTrap.Kind != m.kind {
		return nil, fmt.Errorf(
			errWrongTrapKind,
			ErrTrapMismatch,
			env.DNSTrap.Kind,
			m.kind,
		)
	}

	trap := env.DNSTrap

	if err := trap.Validate(); err != nil {
		return nil, err
	}

	return journal.EncodePayload(dnsPayload{
		Trap:    trap,
		Network: env.ResolverNetwork,
		Address: env.Resolver.DNS,
		Control: env.Resolver.Control,
	})
}

func (m dnsMutator) Apply(
	ctx context.Context,
	env Env,
	_ dockerx.Target,
	raw json.RawMessage,
) error {
	if env.Resolver == nil {
		return fmt.Errorf(errNoResolver, ErrNoResolver, DNSKind(m.kind))
	}

	var payload dnsPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}

	_, err := env.Resolver.Arm(ctx, payload.Trap)

	return err
}

// Revert disarms, which restores khaos's own honest answer so the recovery
// window is measured through a WORKING resolver rather than through no
// resolution at all.
//
// A cold start rebuilds the client from the daemon rather than giving up, and
// that is the difference between this tier and the in-process ones. An identity
// provider or a certificate authority dies with the khaos process that held it,
// so the fault provably went with it and there is nothing to undo. A resolver
// container does not die: it keeps serving NXDOMAIN for the target's dependency
// until something disarms it. The nonce is read off the container's own label,
// so the revert needs nothing khaos remembered.
func (m dnsMutator) Revert(
	ctx context.Context,
	env Env,
	record journal.Record,
) error {
	client := env.Resolver

	if client == nil {
		var payload dnsPayload
		if len(record.Payload) > 0 {
			if err := record.DecodePayload(&payload); err != nil {
				return err
			}
		}

		client = reconnectResolver(ctx, env, payload)
	}

	// Nothing left to disarm, which is SUCCESS rather than a failure to report.
	// The resolver the record named is gone, so it took the fault with it, and
	// reporting that as an error would wedge the record forever and, because
	// `khaos reap` stops on a sweep error, disable the dead man's switch for
	// every other fault on the machine.
	if client == nil {
		return nil
	}

	_, err := client.Disarm(ctx)

	return err
}

// reconnectResolver finds the resolver a journal record names and builds a
// client for it, or nil if there is none to find.
//
// It returns no error ON PURPOSE, and the single return is the honest signature
// rather than a convenience. Every way this can fail to produce a client means
// the same thing: the resolver that held the fault is not there, so the fault is
// not there either. A record with no network, a daemon khaos cannot reach from a
// cold start, a container somebody already removed -- each of those is a revert
// that has nothing left to do, and the caller treats nil as done.
func reconnectResolver(
	ctx context.Context,
	env Env,
	payload dnsPayload,
) *dnsrv.Client {
	if env.Docker == nil || payload.Network == "" {
		return nil
	}

	resolver, err := env.Docker.FindResolver(ctx, payload.Network)
	if err != nil {
		return nil
	}

	return dnsrv.NewClient(
		resolver.Address,
		dockerx.ResolverControlURL(resolver.Address),
		resolver.Nonce,
		payload.Control,
	)
}

// Confirm delegates to the resolver client's own read-back, which asks the
// resolver the same question the target asks and reports what came off the
// wire.
//
// It deliberately does not read the armed state back. The control surface
// answers /arm with the resolver's state, which would be the easy thing to
// check and would confirm a fault against a resolver whose serving path is
// broken. The PKI tier's inert-authority control caught fifteen traps doing
// exactly that, every one of them reading the trap RECORD instead of what was
// served.
func (m dnsMutator) Confirm(
	_ context.Context,
	env Env,
	target dockerx.Target,
) (string, bool, error) {
	if env.Resolver == nil {
		return "", false, fmt.Errorf(
			errNoResolver,
			ErrNoResolver,
			DNSKind(m.kind),
		)
	}

	trap := env.DNSTrap
	if trap.Kind != m.kind {
		trap = dnsrv.Trap{Kind: m.kind, Host: target.Name}
	}

	return env.Resolver.Observe(trap)
}

// NeedsResolver reports whether this mutation arms khaos's chaos resolver, so
// the run knows to find one before the baseline. It is derived from the registry
// rather than from the kind's spelling, for the same reason NeedsProxy is.
func NeedsResolver(kind string) bool {
	mutator, ok := registry[kind]
	if !ok {
		return false
	}

	_, isDNS := mutator.(dnsMutator)

	return isDNS
}

// Prefix declares this tier's kinds to the registry. The chaos resolver outlives
// the khaos process, but it is still per-RUN state: `khaos inject` neither
// stands one up nor knows which network it would serve.
func (dnsMutator) Prefix() string { return KindDNSPrefix }
