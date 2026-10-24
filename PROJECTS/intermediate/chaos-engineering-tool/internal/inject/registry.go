// ©AngelaMos | 2026
// registry.go

package inject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/CarterPerez-dev/khaos/internal/authz"
	"github.com/CarterPerez-dev/khaos/internal/dbx"
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
	KindRestart    = "container-restart"
	KindDisconnect = "network-disconnect"

	errUnknownKind   = "%w: %q (known kinds: %s)"
	errAlreadyPaused = "%w: %s was paused before khaos was asked to pause it, so khaos has no fault to apply and will not unpause a container it did not freeze"
	errNoNetworks    = "%s is not attached to any network, so there is nothing to disconnect"

	confirmPause      = "reading the container back as paused"
	confirmDisconnect = "reading the container back as detached from every network"

	describePause      = "freeze every process in %s so it stops answering without closing its connections"
	describeRestart    = "stop %s and start it again, so it initialises without a dependency it already had"
	confirmRestart     = "%s is stopped, read back off the daemon"
	describeDisconnect = "detach %s from every network, then restore its addresses, aliases, links, gateway priority and driver options; Docker may allocate a new MAC when recreating an endpoint"
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

	// The authority khaos plays so that a dependency can answer a definitive
	// DENY while staying perfectly reachable, which no network fault can
	// produce and no correct dependency will do on request.
	Authz     *authz.Dependency
	AuthzTrap authz.Trap

	// The one authority NOT in khaos's process, so khaos holds a CLIENT for a
	// container. ResolverNetwork travels so a cold-start revert finds it.
	Resolver        *dnsrv.Client
	ResolverNetwork string
	DNSTrap         dnsrv.Trap

	// The one authority that behaves CORRECTLY, so khaos drives a stock engine
	// instead of replacing it. CredPlan is how a cold start reaches it again,
	// and it names where each credential is read from rather than carrying one.
	Cred     *dbx.Tier
	CredTrap dbx.Trap
	CredPlan CredPlan

	// The only tier that REPLACES the target, so its plan carries the identity
	// handover invariant 8 needs.
	EnvPlan *EnvPlan

	// A POINTER, like every other tier's per-run state: Plan measures the size
	// the target had and Confirm reads it back, and a copy would hand
	// Confirm a zero - which read as "the file did not shrink" and aborted
	// every truncation run before it measured anything.
	SecretPlan *SecretPlan
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
	KindRestart:    restartMutator{},
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
		if inProcess(mutator) || internal(mutator) {
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

// obligation is a mutation khaos records so its OWN recovery can undo it,
// never one an operator asks for. Declared by the same self-identifying
// shape as perRun rather than by a list somebody has to remember.
type obligation interface {
	Obligation()
}

func internal(mutator Mutator) bool {
	_, ok := mutator.(obligation)
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

// ObligationKinds are khaos's own recovery bookkeeping, DERIVED from the
// registry so the exclusion cannot drift from the mutators that declare it.
// A hand-written list is how thirty-six pki- kinds once shipped as offerable.
func ObligationKinds() []string {
	kinds := make([]string, 0, len(registry))

	for kind, mutator := range registry {
		if internal(mutator) {
			kinds = append(kinds, kind)
		}
	}

	slices.Sort(kinds)

	return kinds
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
	EndpointID string                      `json:"endpoint_id,omitempty"`
	IPAMConfig *network.EndpointIPAMConfig `json:"ipam_config,omitempty"`
	Aliases    []string                    `json:"aliases,omitempty"`
	Links      []string                    `json:"links,omitempty"`
	DriverOpts map[string]string           `json:"driver_opts,omitempty"`
	MacAddress string                      `json:"mac_address,omitempty"`
	GwPriority int                         `json:"gw_priority,omitempty"`
	Address    netip.Addr                  `json:"address,omitzero"`
	IPv6       netip.Addr                  `json:"ipv6,omitzero"`
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
			entry.EndpointID = settings.EndpointID
			entry.IPAMConfig = settings.IPAMConfig
			entry.Aliases = settings.Aliases
			entry.Links = settings.Links
			entry.DriverOpts = settings.DriverOpts
			entry.GwPriority = settings.GwPriority
			if settings.IPAddress.IsValid() {
				entry.Address = settings.IPAddress
			}
			if settings.GlobalIPv6Address.IsValid() {
				entry.IPv6 = settings.GlobalIPv6Address
			}
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
		if current, attached := endpoints[entry.Network]; attached {
			failures = append(failures, entry.verify(current))
			continue
		}
		if err := env.Docker.Connect(
			ctx,
			entry.Network,
			record.TargetID,
			entry.settings(),
		); err != nil {
			failures = append(failures, err)
			continue
		}
		current, err := env.Docker.Endpoints(ctx, record.TargetID)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		failures = append(failures, entry.verify(current[entry.Network]))
	}

	return errors.Join(failures...)
}

func (a attachment) verify(current *network.EndpointSettings) error {
	if current == nil {
		return fmt.Errorf("network %s has no restored endpoint", a.Network)
	}
	fields := map[string]bool{
		"aliases":          sameNames(a.Aliases, current.Aliases),
		"links":            sameNames(a.Links, current.Links),
		"driver options":   maps.Equal(a.DriverOpts, current.DriverOpts),
		"gateway priority": a.GwPriority == current.GwPriority,
		"MAC address": a.MacAddress == "" || a.recreated(current) ||
			strings.EqualFold(a.MacAddress, current.MacAddress.String()),
		"IPv4 address": !a.Address.IsValid() ||
			a.Address == current.IPAddress,
		"IPv6 address": !a.IPv6.IsValid() ||
			a.IPv6 == current.GlobalIPv6Address,
		"IPAM": a.IPAMConfig == nil ||
			reflect.DeepEqual(a.IPAMConfig, current.IPAMConfig),
	}
	var failures []error
	for field, matches := range fields {
		if !matches {
			failures = append(failures, fmt.Errorf(
				"network %s restored with different %s; reconcile the endpoint before reclaiming",
				a.Network,
				field,
			))
		}
	}
	return errors.Join(failures...)
}

func (a attachment) recreated(current *network.EndpointSettings) bool {
	return a.EndpointID != "" && current.EndpointID != "" &&
		a.EndpointID != current.EndpointID && current.MacAddress.String() != ""
}

func sameNames(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
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

// restartMutator carries the obligation a cold start creates between its stop
// and its start. The pair is not a fault -- it leaves the container where it
// was -- but only once BOTH halves complete, and a stop whose start never
// follows leaves the operator's target down with nothing owed to anyone.
type restartMutator struct{}

func (restartMutator) Describe(_ Env, t dockerx.Target) string {
	return fmt.Sprintf(describeRestart, t.Name)
}

// RestartPayload records the state the target was in BEFORE khaos stopped it,
// so recovery starts only what khaos took down.
type RestartPayload struct {
	WasRunning bool `json:"was_running"`
}

func (restartMutator) Plan(
	ctx context.Context,
	env Env,
	t dockerx.Target,
) (json.RawMessage, error) {
	running, err := env.Docker.Running(ctx, t.ID)
	if err != nil {
		return nil, err
	}

	return journal.EncodePayload(RestartPayload{WasRunning: running})
}

func (restartMutator) Apply(
	ctx context.Context,
	env Env,
	t dockerx.Target,
	_ json.RawMessage,
) error {
	return env.Docker.Stop(ctx, t.ID)
}

// Revert puts back only a container khaos stopped and that is still down.
func (restartMutator) Revert(
	ctx context.Context,
	env Env,
	record journal.Record,
) error {
	var payload RestartPayload
	if len(record.Payload) > 0 {
		if err := record.DecodePayload(&payload); err != nil {
			return err
		}
	}

	if !payload.WasRunning {
		return nil
	}

	running, err := env.Docker.Running(ctx, record.TargetID)
	if err != nil {
		return err
	}

	if running {
		return nil
	}

	return env.Docker.Start(ctx, record.TargetID)
}

// Confirm reads back that the target is down, which is the only observable
// half of a restart that a reclaim can act on.
func (restartMutator) Confirm(
	ctx context.Context,
	env Env,
	t dockerx.Target,
) (string, bool, error) {
	running, err := env.Docker.Running(ctx, t.ID)
	if err != nil || running {
		return "", false, err
	}

	return fmt.Sprintf(confirmRestart, t.Name), true, nil
}

// Obligation marks this as khaos's own bookkeeping: it is resolvable by
// Lookup so a reclaim can revert it, and absent from `khaos inject`.
func (restartMutator) Obligation() {}
