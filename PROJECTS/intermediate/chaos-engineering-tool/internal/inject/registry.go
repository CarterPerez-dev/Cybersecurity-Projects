// ©AngelaMos | 2026
// registry.go

package inject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/inject/proxy"
	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/pki"
	"github.com/moby/moby/api/types/network"
)

const (
	KindPause      = "container-pause"
	KindDisconnect = "network-disconnect"

	errUnknownKind   = "%w: %q (known kinds: %s)"
	errAlreadyPaused = "%w: %s was paused before khaos was asked to pause it, so khaos has no fault to apply and will not unpause a container it did not freeze"
	errNoNetworks    = "%s is not attached to any network, so there is nothing to disconnect"

	confirmPause      = "reading the container back as paused"
	confirmDisconnect = "reading the container back as detached from every network"

	describePause      = "freeze every process in %s so it stops answering without closing its connections"
	describeDisconnect = "detach %s from every network it is on, then reattach it with the same aliases, addresses and driver options"
)

var ErrAlreadyPaused = errors.New("that container is already paused")

var ErrUnknownKind = errors.New(
	"no injector is registered for this mutation kind",
)

// Env carries per-run, in-process state, nil and zero for every tier that does
// not use it, because none of it exists outside the run that owns it.
type Env struct {
	Docker     *dockerx.Client
	Proxy      *proxy.Proxy
	ProxyFault proxy.Fault
	IdP        *idp.Provider
	IdPTrap    idp.Trap

	Authority *pki.Authority
	PKITrap   pki.Trap

	// The one authority NOT in khaos's process, so khaos holds a CLIENT for a
	// container. ResolverNetwork travels so a cold-start revert finds it.
	Resolver        *dnsrv.Client
	ResolverNetwork string
	DNSTrap         dnsrv.Trap
}

// Mutator is one injectable fault. Plan returns what the revert needs so the
// caller can journal it BEFORE Apply runs, and Apply consumes that payload, so
// a process killed mid-apply still leaves a record that undoes the fault.
type Mutator interface {
	Describe(Env, dockerx.Target) string
	Plan(context.Context, Env, dockerx.Target) (json.RawMessage, error)
	Apply(context.Context, Env, dockerx.Target, json.RawMessage) error
	// Confirm returns the observable it measured; a constant describing the
	// technique is not evidence.
	Confirm(context.Context, Env, dockerx.Target) (string, bool, error)
	Revert(context.Context, Env, journal.Record) error
}

var registry = map[string]Mutator{
	KindPause:      pauseMutator{},
	KindDisconnect: disconnectMutator{},
}

// Lookup names only the kinds the operator can ask for directly; listing the
// per-run kinds would make one typo produce two different refusals.
func Lookup(kind string) (Mutator, error) {
	mutator, ok := registry[kind]
	if !ok {
		return nil, fmt.Errorf(
			errUnknownKind,
			ErrUnknownKind,
			kind,
			strings.Join(DirectKinds(), ", "),
		)
	}
	return mutator, nil
}

func Kinds() []string {
	kinds := make([]string, 0, len(registry))
	for kind := range registry {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	return kinds
}

// DirectKinds are the mutations whose whole subject is a container the daemon
// can be told about. A proxy fault or provider trap only exists inside its own
// run, so advertising one would offer a command that cannot work.
func DirectKinds() []string {
	kinds := make([]string, 0, len(registry))
	for kind, mutator := range registry {
		if inProcess(mutator) {
			continue
		}
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	return kinds
}

// perRun is an interface rather than a type switch, so a new tier declares
// itself by implementing one method instead of by being remembered.
type perRun interface {
	Prefix() string
}

// inProcess reads the mutator's TYPE, not the kind's spelling, so an
// in-process-shaped name cannot be quietly offered under `khaos inject`.
func inProcess(mutator Mutator) bool {
	_, ok := mutator.(perRun)
	return ok
}

// PerRunPrefixes is every prefix belonging to a tier that lives inside a run,
// read out of the registry rather than restated.
func PerRunPrefixes() []string {
	seen := map[string]bool{}

	for _, mutator := range registry {
		tier, ok := mutator.(perRun)
		if !ok {
			continue
		}
		seen[tier.Prefix()] = true
	}

	prefixes := make([]string, 0, len(seen))
	for prefix := range seen {
		prefixes = append(prefixes, prefix)
	}
	slices.Sort(prefixes)

	return prefixes
}

func IsDirect(kind string) bool {
	return slices.Contains(DirectKinds(), kind)
}

// NeedsProxy is derived from the registry rather than from the kind's
// spelling, so a proxy-shaped name cannot quietly fail to get one.
func NeedsProxy(kind string) bool {
	mutator, ok := registry[kind]
	if !ok {
		return false
	}
	_, isProxy := mutator.(proxyMutator)
	return isProxy
}

// NeedsIdP reports whether a mutation requires khaos's own identity provider.
func NeedsIdP(kind string) bool {
	mutator, ok := registry[kind]
	if !ok {
		return false
	}
	_, isIdP := mutator.(idpMutator)
	return isIdP
}

// NeedsPKI reports whether this mutation arms khaos's certificate authority, so
// the run knows to stand one up before the baseline.
func NeedsPKI(kind string) bool {
	mutator, ok := registry[kind]
	if !ok {
		return false
	}

	_, isPKI := mutator.(pkiMutator)

	return isPKI
}

type pauseMutator struct{}

func (pauseMutator) Describe(_ Env, t dockerx.Target) string {
	return fmt.Sprintf(describePause, t.Name)
}

// pausePayload records the state the target was in BEFORE khaos touched it.
type pausePayload struct {
	AlreadyPaused bool `json:"already_paused"`
}

// Plan refuses a target that is already paused. A paused container still
// reports Running, so it passes every refusal predicate, and the revert would
// then unpause a container the OPERATOR had paused.
func (pauseMutator) Plan(
	ctx context.Context,
	env Env,
	t dockerx.Target,
) (json.RawMessage, error) {
	paused, err := env.Docker.Paused(ctx, t.ID)
	if err != nil {
		return nil, err
	}

	if paused {
		return nil, fmt.Errorf(errAlreadyPaused, ErrAlreadyPaused, t.Name)
	}

	return journal.EncodePayload(pausePayload{})
}

func (pauseMutator) Apply(
	ctx context.Context,
	env Env,
	t dockerx.Target,
	_ json.RawMessage,
) error {
	return env.Docker.Pause(ctx, t.ID)
}

// Revert unpauses only what khaos paused, which the journaled precondition
// makes knowable from a cold start.
func (pauseMutator) Revert(
	ctx context.Context,
	env Env,
	record journal.Record,
) error {
	var payload pausePayload
	if len(record.Payload) > 0 {
		if err := record.DecodePayload(&payload); err != nil {
			return err
		}
	}

	if payload.AlreadyPaused {
		return nil
	}

	paused, err := env.Docker.Paused(ctx, record.TargetID)
	if err != nil {
		return err
	}
	if !paused {
		return nil
	}
	return env.Docker.Unpause(ctx, record.TargetID)
}

type attachment struct {
	Network    string                      `json:"network"`
	IPAMConfig *network.EndpointIPAMConfig `json:"ipam_config,omitempty"`
	Aliases    []string                    `json:"aliases,omitempty"`
	Links      []string                    `json:"links,omitempty"`
	DriverOpts map[string]string           `json:"driver_opts,omitempty"`
	MacAddress string                      `json:"mac_address,omitempty"`
	GwPriority int                         `json:"gw_priority,omitempty"`
}

type disconnectPayload struct {
	Attachments []attachment `json:"attachments"`
}

func (a attachment) settings() *network.EndpointSettings {
	settings := &network.EndpointSettings{
		IPAMConfig: a.IPAMConfig,
		Aliases:    a.Aliases,
		Links:      a.Links,
		DriverOpts: a.DriverOpts,
		GwPriority: a.GwPriority,
	}

	if a.MacAddress != "" {
		var mac network.HardwareAddr
		if err := mac.UnmarshalText([]byte(a.MacAddress)); err == nil {
			settings.MacAddress = mac
		}
	}

	return settings
}

type disconnectMutator struct{}

func (disconnectMutator) Describe(_ Env, t dockerx.Target) string {
	return fmt.Sprintf(describeDisconnect, t.Name)
}

func (disconnectMutator) Plan(
	ctx context.Context,
	env Env,
	t dockerx.Target,
) (json.RawMessage, error) {
	endpoints, err := env.Docker.Endpoints(ctx, t.ID)
	if err != nil {
		return nil, err
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf(errNoNetworks, t.Name)
	}

	names := make([]string, 0, len(endpoints))
	for name := range endpoints {
		names = append(names, name)
	}
	slices.Sort(names)

	payload := disconnectPayload{Attachments: make([]attachment, 0, len(names))}
	for _, name := range names {
		settings := endpoints[name]
		entry := attachment{Network: name}
		if settings != nil {
			entry.IPAMConfig = settings.IPAMConfig
			entry.Aliases = settings.Aliases
			entry.Links = settings.Links
			entry.DriverOpts = settings.DriverOpts
			entry.GwPriority = settings.GwPriority
			if mac := settings.MacAddress.String(); mac != "" {
				entry.MacAddress = mac
			}
		}
		payload.Attachments = append(payload.Attachments, entry)
	}

	return journal.EncodePayload(payload)
}

func (disconnectMutator) Apply(
	ctx context.Context,
	env Env,
	t dockerx.Target,
	raw json.RawMessage,
) error {
	var payload disconnectPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}

	for _, entry := range payload.Attachments {
		if err := env.Docker.Disconnect(ctx, entry.Network, t.ID); err != nil {
			return err
		}
	}

	return nil
}

func (disconnectMutator) Revert(
	ctx context.Context,
	env Env,
	record journal.Record,
) error {
	var payload disconnectPayload
	if err := record.DecodePayload(&payload); err != nil {
		return err
	}

	endpoints, err := env.Docker.Endpoints(ctx, record.TargetID)
	if err != nil {
		return err
	}

	// Every attachment is attempted and the failures joined, because returning
	// on the first one leaves the container detached from all the rest.
	var failures []error

	for _, entry := range payload.Attachments {
		if _, attached := endpoints[entry.Network]; attached {
			continue
		}
		if err := env.Docker.Connect(
			ctx,
			entry.Network,
			record.TargetID,
			entry.settings(),
		); err != nil {
			failures = append(failures, err)
		}
	}

	return errors.Join(failures...)
}

func (pauseMutator) Confirm(
	ctx context.Context,
	env Env,
	t dockerx.Target,
) (string, bool, error) {
	paused, err := env.Docker.Paused(ctx, t.ID)
	if err != nil || !paused {
		return "", false, err
	}
	return confirmPause, true, nil
}

func (disconnectMutator) Confirm(
	ctx context.Context,
	env Env,
	t dockerx.Target,
) (string, bool, error) {
	endpoints, err := env.Docker.Endpoints(ctx, t.ID)
	if err != nil {
		return "", false, err
	}
	if len(endpoints) != 0 {
		return "", false, nil
	}
	return confirmDisconnect, true, nil
}
