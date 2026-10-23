// ©AngelaMos | 2026
// recreate.go

package dockerx

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

const (
	// HeldSuffix is where the ORIGINAL container goes while a replacement runs
	// under its name. khaos never destroys it: a recreate from an inspection
	// loses the anonymous volume with its data stranded, every prior log line,
	// and the container id that invariant 8 re-verifies against. A rename
	// keeps all three and makes the revert a rename back.
	HeldSuffix = "-khaos-held"

	// HeldVarPrefix carries a variable's original value inside the container
	// while khaos is pretending it is absent, so the value never reaches
	// khaos's journal or its state directory. Same rule as the secret tier's
	// aside copy.
	HeldVarPrefix = "KHAOS_HELD_"

	envAssign = "="

	errCapture         = "read %s back before replacing it: %w"
	errNoConfig        = "%w: the daemon returned no configuration for %s, so khaos cannot build a replacement for it"
	errRename          = "rename %s to %s: %w"
	errRecreate        = "create the replacement for %s: %w"
	errStartReplaced   = "start the replacement for %s: %w"
	errStopContainer   = "stop %s before replacing it: %w"
	errStartContainer  = "start %s: %w"
	errRemoveContainer = "remove %s: %w"

	errImageEnv     = "read the environment %s bakes into its own image: %w"
	errNoVariable   = "%w: %s does not carry %s in its environment, so there is nothing for khaos to take away"
	errImageDefines = "%w: %s is defined by the IMAGE %s as well as by the container, so a replacement created without it gets the image's value back and khaos would report a fault the daemon had undone. Shadow it with the empty-value fault instead, or target a service that does not bake it in"
)

var ErrNoContainerConfig = errors.New(
	"the daemon returned no configuration to rebuild from",
)

var ErrVariableAbsent = errors.New(
	"that variable is not in the target's environment",
)

var ErrImageDefinesVariable = errors.New(
	"the image defines that variable, so removing the container's copy changes nothing",
)

// Spec is everything needed to recreate one container. It is captured from the
// daemon rather than assembled, so nothing khaos forgot to copy can go missing.
type Spec struct {
	Name       string
	Config     *container.Config
	HostConfig *container.HostConfig
	Networks   map[string]*network.EndpointSettings
}

// Capture reads a container back. The per-network EndpointSettings travel whole
// and are cleaned of the daemon's own identifiers: reconnecting with only a
// network NAME silently drops the static address, the MAC and every alias, and
// on a compose project the service name lives in the aliases, so every peer
// addressing it by name would get NXDOMAIN forever.
func (c *Client) Capture(
	ctx context.Context,
	containerID string,
) (Spec, error) {
	result, err := c.api.ContainerInspect(
		ctx,
		containerID,
		client.ContainerInspectOptions{},
	)
	if err != nil {
		return Spec{}, fmt.Errorf(
			errCapture,
			ShortID(containerID),
			c.classify(err),
		)
	}

	raw := result.Container

	if raw.Config == nil || raw.HostConfig == nil {
		return Spec{}, fmt.Errorf(
			errNoConfig,
			ErrNoContainerConfig,
			ShortID(containerID),
		)
	}

	spec := Spec{
		Name:       strings.TrimPrefix(raw.Name, namePrefix),
		Config:     raw.Config,
		HostConfig: raw.HostConfig,
		Networks:   map[string]*network.EndpointSettings{},
	}

	if raw.NetworkSettings == nil {
		return spec, nil
	}

	for name, settings := range raw.NetworkSettings.Networks {
		if settings == nil {
			continue
		}

		// Deep-copied through the API's own helper, then cleaned of the
		// daemon's operational fields. IPAMConfig, Aliases and MacAddress are
		// kept: those are what the replacement has to be created WITH, and
		// reconnecting with only a network name drops all three.
		copied := settings.Copy()
		copied.EndpointID = ""
		copied.NetworkID = ""
		copied.Gateway = netip.Addr{}
		copied.IPAddress = netip.Addr{}
		copied.IPv6Gateway = netip.Addr{}
		copied.GlobalIPv6Address = netip.Addr{}
		copied.IPPrefixLen = 0
		copied.GlobalIPv6PrefixLen = 0

		// The short id is in here and it is about to change.
		copied.DNSNames = nil

		spec.Networks[name] = copied
	}

	return spec, nil
}

// Identify resolves a name to the IMMUTABLE container id behind it, or
// ErrContainerGone when nothing answers to it. A name is a label the daemon
// lets any container hold, and the environment tier hands one container's
// name to another on purpose, so anything destructive resolves first.
func (c *Client) Identify(ctx context.Context, ref string) (string, error) {
	result, err := c.api.ContainerInspect(
		ctx,
		ref,
		client.ContainerInspectOptions{},
	)
	if err != nil {
		return "", c.classify(err)
	}

	return result.Container.ID, nil
}

// Rename is how the original is kept. The replacement takes the name, so every
// peer addressing the service by name reaches the replacement.
func (c *Client) Rename(ctx context.Context, containerID, name string) error {
	if _, err := c.api.ContainerRename(
		ctx,
		containerID,
		client.ContainerRenameOptions{NewName: name},
	); err != nil {
		return fmt.Errorf(
			errRename,
			ShortID(containerID),
			name,
			c.classify(err),
		)
	}

	return nil
}

// Recreate creates and starts a container from a captured spec with a replaced
// environment, and returns its id. The caller has already renamed the original
// aside, so this is additive: nothing has been destroyed when it fails.
func (c *Client) Recreate(
	ctx context.Context,
	spec Spec,
	environ []string,
) (string, error) {
	config := *spec.Config
	config.Env = environ

	created, err := c.api.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:       spec.Name,
		Config:     &config,
		HostConfig: spec.HostConfig,
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: spec.Networks,
		},
	})
	if err != nil {
		return "", fmt.Errorf(errRecreate, spec.Name, c.classify(err))
	}

	if _, err := c.api.ContainerStart(
		ctx,
		created.ID,
		client.ContainerStartOptions{},
	); err != nil {
		return created.ID, fmt.Errorf(
			errStartReplaced,
			spec.Name,
			c.classify(err),
		)
	}

	return created.ID, nil
}

// ImageEnv is what the IMAGE bakes in, which is not the same question as what
// the container carries. The daemon merges the image's environment into any key
// a create request omits, so a variable defined in both places cannot be taken
// away by omission.
func (c *Client) ImageEnv(ctx context.Context, image string) ([]string, error) {
	result, err := c.api.ImageInspect(ctx, image)
	if err != nil {
		return nil, fmt.Errorf(errImageEnv, image, c.classify(err))
	}

	if result.Config == nil {
		return nil, nil
	}

	return result.Config.Env, nil
}

// EnvValue reads one variable out of a captured environment, taking the LAST
// occurrence. Docker deduplicates on the whole `KEY=VALUE` string rather than
// on the key, so a shadowed variable appears twice and the last one is what the
// process sees - khaos has to read it the same way or it mis-reports its own
// fault.
func EnvValue(environ []string, name string) (string, bool) {
	value := ""
	found := false

	for _, pair := range environ {
		key, rest, ok := strings.Cut(pair, envAssign)
		if !ok || key != name {
			continue
		}

		value = rest
		found = true
	}

	return value, found
}

// WithoutVariable removes every occurrence of a key, which is what an unset
// needs: leaving one behind would shadow the removal.
func WithoutVariable(environ []string, name string) []string {
	out := make([]string, 0, len(environ))

	for _, pair := range environ {
		if key, _, ok := strings.Cut(pair, envAssign); ok && key == name {
			continue
		}

		out = append(out, pair)
	}

	return out
}

// ShadowedEmpty appends `NAME=` rather than replacing the original entry, which
// is what makes the fault reversible without khaos holding the value: the
// revert removes the LAST occurrence and the original is still underneath.
func ShadowedEmpty(environ []string, name string) []string {
	return append(slices.Clone(environ), name+envAssign)
}

// HeldFor is where an unset keeps the original value: inside the replacement's
// own environment, under a name the target does not read.
func HeldFor(name string) string {
	return HeldVarPrefix + name
}

// ImageDefines reports whether the image bakes this variable in, which is the
// one precondition `env_unset` cannot work around.
func ImageDefines(imageEnv []string, name string) bool {
	_, found := EnvValue(imageEnv, name)

	return found
}

// HeldName is the name the original container is renamed to.
func HeldName(name string) string {
	return name + HeldSuffix
}

// Variables is every key a captured environment carries, for a refusal that
// names what IS there rather than only what is not.
func Variables(environ []string) []string {
	seen := map[string]bool{}

	for _, pair := range environ {
		if key, _, ok := strings.Cut(pair, envAssign); ok {
			seen[key] = true
		}
	}

	return slices.Sorted(maps.Keys(seen))
}

// Stop stops a container before it is renamed aside, because two containers
// cannot both hold a network's static address and a service's aliases. A
// container that is already stopped is success.
func (c *Client) Stop(ctx context.Context, containerID string) error {
	if _, err := c.api.ContainerStop(
		ctx,
		containerID,
		client.ContainerStopOptions{},
	); err != nil {
		return fmt.Errorf(
			errStopContainer,
			ShortID(containerID),
			c.classify(err),
		)
	}

	return nil
}

// Start brings the original back after a revert has renamed it into place.
func (c *Client) Start(ctx context.Context, containerID string) error {
	if _, err := c.api.ContainerStart(
		ctx,
		containerID,
		client.ContainerStartOptions{},
	); err != nil {
		return fmt.Errorf(
			errStartContainer,
			ShortID(containerID),
			c.classify(err),
		)
	}

	return nil
}

// Remove removes a container khaos CREATED, and only ever the replacement it
// made itself. A container that is already gone is success, because a revert
// runs again after a reclaim.
func (c *Client) Remove(ctx context.Context, containerID string) error {
	_, err := c.api.ContainerRemove(
		ctx,
		containerID,
		client.ContainerRemoveOptions{Force: true},
	)
	if err == nil {
		return nil
	}

	classified := c.classify(err)
	if errors.Is(classified, ErrContainerGone) {
		return nil
	}

	return fmt.Errorf(errRemoveContainer, ShortID(containerID), classified)
}
