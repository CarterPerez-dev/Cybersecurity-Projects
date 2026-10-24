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

// DNSKind is one-to-one with the fault kinds, so the catalogue names the actual
// defect rather than a generic "DNS" entry.
func DNSKind(kind dnsrv.Kind) string {
	return KindDNSPrefix + string(kind)
}

// dnsMutator's authority is a CONTAINER, not a goroutine like the others:
// `--dns` carries no port and an unprivileged process cannot bind 53. The
// dependency also stays healthy here; the target simply cannot find it.
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

// dnsPayload records how to reach the resolver as well as the fault, because
// this tier's authority outlives the khaos process that armed it.
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

// Revert disarms, so recovery is measured through a WORKING resolver rather
// than no resolution at all. The container does not die with khaos, so a cold
// start rebuilds the client and reads the nonce off the container's own label.
func (m dnsMutator) Revert(
	ctx context.Context,
	env Env,
	record journal.Record,
) error {
	client := env.Resolver

	if client == nil {
		var payload dnsPayload
		if err := record.DecodePayload(&payload); err != nil {
			return err
		}

		var err error
		client, err = reconnectResolver(ctx, env, payload)
		if err != nil {
			return err
		}
	}

	// Nothing left to disarm is SUCCESS: the resolver named is gone, so it took
	// the fault with it.
	if client == nil {
		return nil
	}

	_, err := client.Disarm(ctx)

	return err
}

func reconnectResolver(
	ctx context.Context,
	env Env,
	payload dnsPayload,
) (*dnsrv.Client, error) {
	if env.Docker == nil || payload.Network == "" {
		return nil, ErrNoResolver
	}

	resolver, err := env.Docker.FindResolver(ctx, payload.Network)
	if err != nil {
		if errors.Is(err, dockerx.ErrResolverNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return dnsrv.NewClient(
		resolver.Address,
		dockerx.ResolverControlURL(resolver.Address),
		resolver.Nonce,
		payload.Control,
	), nil
}

// Confirm asks the resolver the same question the target asks, never reading
// the armed state back, which would confirm against a broken serving path.
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

// NeedsResolver tells the run to find a resolver before the baseline, derived
// from the registry rather than from the kind's spelling.
func NeedsResolver(kind string) bool {
	mutator, ok := registry[kind]
	if !ok {
		return false
	}

	_, isDNS := mutator.(dnsMutator)

	return isDNS
}

// Prefix declares this tier's kinds to the registry.
func (dnsMutator) Prefix() string { return KindDNSPrefix }
