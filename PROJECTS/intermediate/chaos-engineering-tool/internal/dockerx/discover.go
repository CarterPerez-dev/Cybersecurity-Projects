// ©AngelaMos | 2026
// discover.go

package dockerx

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

const (
	filterLabel  = "label"
	namePrefix   = "/"
	minIDPrefix  = 4
	errListFmt   = "list containers: %w"
	errInspect   = "inspect %s: %w"
	errNoMatch   = "no consenting target named %q (run `khaos targets` to see what is available)"
	errAmbiguous = "%q matches %d targets, name one exactly: %s"
	errShortName = "a target name must be at least %d characters"
)

var (
	ErrNoHostConfig = errors.New(
		"the daemon returned a container with no host configuration, so khaos cannot tell whether it is safe to touch",
	)
	ErrEmptyName = errors.New("a target name is required")
)

func (c *Client) Targets(ctx context.Context, filter Filter) ([]Target, error) {
	consenting, err := c.list(
		ctx,
		make(client.Filters).Add(filterLabel, LabelConsent),
	)
	if err != nil {
		return nil, err
	}

	peers, err := c.namespacePeers(ctx)
	if err != nil {
		return nil, err
	}

	targets := make([]Target, 0, len(consenting))
	for _, summary := range consenting {
		target, err := c.inspect(ctx, summary.ID)
		if err != nil {
			return nil, err
		}
		if filter.Project != "" && target.Project != filter.Project {
			continue
		}
		target.NamespacePeers = peers[target.ID]
		targets = append(targets, target)
	}

	slices.SortFunc(targets, func(a, b Target) int {
		return cmp.Or(
			cmp.Compare(a.Project, b.Project),
			cmp.Compare(a.Name, b.Name),
		)
	})

	return targets, nil
}

func (c *Client) Lookup(
	ctx context.Context,
	name string,
	filter Filter,
) (Target, error) {
	if strings.TrimSpace(name) == "" {
		return Target{}, ErrEmptyName
	}

	if len(name) < minIDPrefix {
		return Target{}, fmt.Errorf(errShortName, minIDPrefix)
	}

	targets, err := c.Targets(ctx, filter)
	if err != nil {
		return Target{}, err
	}

	var matches []Target
	for _, t := range targets {
		if t.Name == name || t.Service == name ||
			strings.HasPrefix(t.ID, name) {
			matches = append(matches, t)
		}
	}

	switch len(matches) {
	case 0:
		return Target{}, fmt.Errorf(errNoMatch, name)
	case 1:
		return matches[0], nil
	default:
		return Target{}, fmt.Errorf(
			errAmbiguous,
			name,
			len(matches),
			joinNames(matches),
		)
	}
}

func (c *Client) Accept(
	ctx context.Context,
	name string,
	filter Filter,
	guard Guard,
) (Target, error) {
	target, err := c.Lookup(ctx, name, filter)
	if err != nil {
		return Target{}, err
	}

	if refusal := Refuse(target, guard); refusal != nil {
		return Target{}, refusal
	}

	return target, nil
}

func (c *Client) list(
	ctx context.Context,
	filters client.Filters,
) ([]container.Summary, error) {
	listed, err := c.api.ContainerList(
		ctx,
		client.ContainerListOptions{All: true, Filters: filters},
	)
	if err != nil {
		return nil, fmt.Errorf(errListFmt, err)
	}
	return listed.Items, nil
}

func (c *Client) namespacePeers(
	ctx context.Context,
) (map[string][]string, error) {
	all, err := c.list(ctx, nil)
	if err != nil {
		return nil, err
	}

	return namespacePeersOf(all), nil
}

func namespacePeersOf(all []container.Summary) map[string][]string {
	byName := make(map[string]string, len(all))
	for _, summary := range all {
		for _, name := range summary.Names {
			byName[strings.TrimPrefix(name, namePrefix)] = summary.ID
		}
	}

	peers := make(map[string][]string)
	for _, summary := range all {
		if summary.State != container.StateRunning ||
			summary.Labels[LabelConsent] == ConsentValue {
			continue
		}
		reference, ok := strings.CutPrefix(
			summary.HostConfig.NetworkMode,
			NetworkModeContainerPfx,
		)
		if !ok {
			continue
		}

		host := reference
		if resolved, found := byName[reference]; found {
			host = resolved
		} else {
			for _, candidate := range all {
				if strings.HasPrefix(candidate.ID, reference) {
					host = candidate.ID
					break
				}
			}
		}

		peers[host] = append(peers[host], displayName(summary))
	}

	return peers
}

func (c *Client) inspect(ctx context.Context, id string) (Target, error) {
	result, err := c.api.ContainerInspect(
		ctx,
		id,
		client.ContainerInspectOptions{},
	)
	if err != nil {
		return Target{}, fmt.Errorf(errInspect, ShortID(id), err)
	}

	target, err := targetFrom(result.Container)
	if err != nil {
		return Target{}, fmt.Errorf(errInspect, ShortID(id), err)
	}

	return target, nil
}

func targetFrom(raw container.InspectResponse) (Target, error) {
	if raw.HostConfig == nil {
		return Target{}, ErrNoHostConfig
	}

	target := Target{
		ID:          raw.ID,
		ImageID:     raw.Image,
		Name:        strings.TrimPrefix(raw.Name, namePrefix),
		Running:     raw.State != nil && raw.State.Running,
		Labels:      map[string]string{},
		NetworkMode: string(raw.HostConfig.NetworkMode),
		PidMode:     string(raw.HostConfig.PidMode),
		IpcMode:     string(raw.HostConfig.IpcMode),
		UsernsMode:  string(raw.HostConfig.UsernsMode),
		Privileged:  raw.HostConfig.Privileged,
		SecurityOpt: raw.HostConfig.SecurityOpt,
		Inspected:   true,
	}

	target.Capabilities = append(target.Capabilities, raw.HostConfig.CapAdd...)

	for _, device := range raw.HostConfig.Devices {
		target.Devices = append(target.Devices, device.PathOnHost)
	}

	if raw.Config != nil {
		target.Image = raw.Config.Image
		for key, value := range raw.Config.Labels {
			target.Labels[key] = value
		}
	}

	target.Project = target.Labels[LabelComposeProject]
	target.Service = target.Labels[LabelComposeService]

	// A tmpfs declared the SHORT way - compose's `tmpfs:` key, or `--tmpfs` -
	// lands in HostConfig and leaves Mounts EMPTY, measured on the range's own
	// postgres: `.Mounts` was `[]` while `.HostConfig.Tmpfs` carried the path.
	// The long form (`--mount type=tmpfs`) does appear in Mounts. Two shapes,
	// one meaning, and khaos has to see both or it refuses a secret on a tmpfs
	// for the wrong reason.
	if raw.HostConfig != nil {
		for destination := range raw.HostConfig.Tmpfs {
			target.Mounts = append(target.Mounts, Mount{
				Type:        tmpfsType,
				Destination: destination,
				ReadWrite:   true,
			})
		}
	}

	for _, point := range raw.Mounts {
		if point.Source != "" {
			target.BindSources = append(target.BindSources, point.Source)
		}

		target.Mounts = append(target.Mounts, Mount{
			Type:        string(point.Type),
			Source:      point.Source,
			Destination: point.Destination,
			ReadWrite:   point.RW,
			Name:        point.Name,
		})
	}

	return target, nil
}

func displayName(summary container.Summary) string {
	if len(summary.Names) > 0 {
		return strings.TrimPrefix(summary.Names[0], namePrefix)
	}
	return ShortID(summary.ID)
}

func joinNames(targets []Target) string {
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = t.Name
	}
	return strings.Join(names, ", ")
}
