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

// Proxy, ProxyFault, IdP and IdPTrap are nil and zero for every tier that does
// not use them. Both the fault proxy and khaos's identity provider are per-run,
// in-process state rather than something addressable through the daemon, so they
// travel with the environment a mutation is applied in. Nothing else can hand
// either one to a mutator, because they do not exist until the run that owns
// them starts and they stop existing when that run ends.
type Env struct {
	Docker     *dockerx.Client
	Proxy      *proxy.Proxy
	ProxyFault proxy.Fault
	IdP        *idp.Provider
	IdPTrap    idp.Trap

	// Authority and PKITrap are the FOURTH injection tier: khaos's own
	// certificate authority, playing the dependency whose certificate is under
	// test. Like the identity provider it holds no capabilities and serves
	// nothing but the target.
	Authority *pki.Authority
	PKITrap   pki.Trap
}

// Plan discovers everything the revert will need and returns it so the caller
// can journal it BEFORE Apply runs. Apply consumes that payload rather than
// re-deriving it, so a process killed mid-apply still leaves a journal record
// that fully describes how to put the target back.
type Mutator interface {
	Describe(Env, dockerx.Target) string
	Plan(context.Context, Env, dockerx.Target) (json.RawMessage, error)
	Apply(context.Context, Env, dockerx.Target, json.RawMessage) error
	// Confirm returns the observable it actually measured along with the verdict.
	// A constant describing the technique is not evidence, and the run record has
	// to carry what was seen or a reader cannot audit the run.
	Confirm(context.Context, Env, dockerx.Target) (string, bool, error)
	Revert(context.Context, Env, journal.Record) error
}

var registry = map[string]Mutator{
	KindPause:      pauseMutator{},
	KindDisconnect: disconnectMutator{},
}

// Lookup names only the kinds the operator can ask for directly. Listing the
// proxy kinds here sends a typo straight to a kind that a different message then
// refuses, which is two refusals for one mistake.
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

// DirectKinds are the mutations `khaos inject` can apply on its own: the ones
// whose whole subject is a container the daemon can be told about. A proxy fault
// is not one, because it acts on the PATH between a target and its dependency
// and only exists for as long as the run that owns the proxy. An identity
// provider trap is not one either, for the same reason: the provider is a
// goroutine inside the run. Advertising either under `khaos inject` would offer
// a command that cannot succeed.
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

// inProcess reports whether a mutation acts on state that lives inside the run
// rather than in the daemon. It is derived from the mutator's TYPE rather than
// from the kind's spelling, so a mutation cannot be given an in-process-shaped
// name and then quietly be offered under `khaos inject`, or the reverse.
func inProcess(mutator Mutator) bool {
	switch mutator.(type) {
	case proxyMutator, idpMutator:
		return true
	default:
		return false
	}
}

func IsDirect(kind string) bool {
	return slices.Contains(DirectKinds(), kind)
}

// NeedsProxy reports whether a mutation requires the run to stand up khaos's
// in-process fault proxy. It is derived from the registry rather than from the
// kind's spelling, so a mutation cannot be given a proxy-shaped name and then
// quietly fail to get one, or the reverse.
func NeedsProxy(kind string) bool {
	mutator, ok := registry[kind]
	if !ok {
		return false
	}
	_, isProxy := mutator.(proxyMutator)
	return isProxy
}

// NeedsIdP reports whether a mutation requires the run to stand up khaos's own
// identity provider, derived from the registry rather than from the kind's
// spelling for the same reason NeedsProxy is.
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

// Plan refuses a target that is already paused.
//
// A paused container still reports Running, so it passes every refusal
// predicate. Docker then rejects the second pause, the session records a failed
// mutation and immediately reverts it, and the revert sees a paused container
// and unpauses it — khaos resuming a container the OPERATOR had paused, as
// cleanup for a fault khaos never applied.
//
// Refusing here rather than recording the precondition is deliberate: khaos
// cannot pause something already paused, so there is no experiment to run, and
// a fault that cannot be applied should be refused by name before anything is
// journaled.
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

// Revert unpauses only what khaos paused. The journaled precondition is what
// makes that knowable from a cold start, where khaos has no memory of the run.
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

	// Every attachment is attempted, and the failures are joined. Returning on
	// the first one abandoned the rest: a container on three networks that lost
	// one of them stayed detached from the other two as well, because the first
	// failure ended the loop.
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
