// ©AngelaMos | 2026
// actions.go

package dockerx

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

const (
	errPause      = "pause %s: %w"
	errUnpause    = "unpause %s: %w"
	errDisconnect = "disconnect %s from %s: %w"
	errConnect    = "reconnect %s to %s: %w"
	errEndpoints  = "read network endpoints of %s: %w"
	errState      = "read state of %s: %w"
	errPorts      = "read published ports of %s: %w"
	errNoPort     = "nothing is published for container port %d on %s"
	errEnv        = "read the environment of %s: %w"
	errAddress    = "read the address of %s on network %s: %w"
	errNoAddress  = "%s has no address on network %s"
	errNoNetwork  = "%s has no network address at all, so khaos has nothing to dial it on"
	errBridge     = "read the gateway of the default bridge network: %w"
	errNoBridge   = "the default bridge network reports no gateway address, so khaos cannot find an address a container can reach it on"
	errGateways   = "list the networks the daemon manages, to find the addresses khaos may bind a listener on: %w"

	bridgeNetwork = "bridge"
	envPairParts  = 2
	envPairSep    = "="
)

var ErrContainerGone = errors.New("the container no longer exists")

var ErrNetworkGone = errors.New(
	"the network no longer exists, so the container could not be reattached to it",
)

func (c *Client) Pause(ctx context.Context, containerID string) error {
	if _, err := c.api.ContainerPause(
		ctx,
		containerID,
		client.ContainerPauseOptions{},
	); err != nil {
		return fmt.Errorf(errPause, ShortID(containerID), c.classify(err))
	}
	return nil
}

func (c *Client) Unpause(ctx context.Context, containerID string) error {
	if _, err := c.api.ContainerUnpause(
		ctx,
		containerID,
		client.ContainerUnpauseOptions{},
	); err != nil {
		return fmt.Errorf(errUnpause, ShortID(containerID), c.classify(err))
	}
	return nil
}

func (c *Client) Disconnect(
	ctx context.Context,
	networkID, containerID string,
) error {
	_, err := c.api.NetworkDisconnect(
		ctx,
		networkID,
		client.NetworkDisconnectOptions{Container: containerID},
	)
	if err != nil {
		return fmt.Errorf(
			errDisconnect,
			ShortID(containerID),
			networkID,
			c.classify(err),
		)
	}
	return nil
}

func (c *Client) Connect(
	ctx context.Context,
	networkID, containerID string,
	settings *network.EndpointSettings,
) error {
	_, err := c.api.NetworkConnect(ctx, networkID, client.NetworkConnectOptions{
		Container:      containerID,
		EndpointConfig: settings,
	})
	if err != nil {
		return fmt.Errorf(
			errConnect,
			ShortID(containerID),
			networkID,
			c.classifyNetwork(ctx, containerID, err),
		)
	}
	return nil
}

func (c *Client) Endpoints(
	ctx context.Context,
	containerID string,
) (map[string]*network.EndpointSettings, error) {
	result, err := c.api.ContainerInspect(
		ctx,
		containerID,
		client.ContainerInspectOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			errEndpoints,
			ShortID(containerID),
			c.classify(err),
		)
	}

	if result.Container.NetworkSettings == nil {
		return nil, nil
	}

	return result.Container.NetworkSettings.Networks, nil
}

// Running reports whether the container is up, which is how a restart
// obligation knows there is still something to put back.
func (c *Client) Running(
	ctx context.Context,
	containerID string,
) (bool, error) {
	result, err := c.api.ContainerInspect(
		ctx,
		containerID,
		client.ContainerInspectOptions{},
	)
	if err != nil {
		return false, fmt.Errorf(
			errState,
			ShortID(containerID),
			c.classify(err),
		)
	}

	return result.Container.State != nil && result.Container.State.Running, nil
}

func (c *Client) Paused(ctx context.Context, containerID string) (bool, error) {
	result, err := c.api.ContainerInspect(
		ctx,
		containerID,
		client.ContainerInspectOptions{},
	)
	if err != nil {
		return false, fmt.Errorf(
			errState,
			ShortID(containerID),
			c.classify(err),
		)
	}
	return result.Container.State != nil && result.Container.State.Paused, nil
}

// ContainerEnv reads where a target is ALREADY addressing its dependency.
// Environment is fixed at creation, so the container is the only authority on
// what it will dial.
func (c *Client) ContainerEnv(
	ctx context.Context,
	containerID string,
) (map[string]string, error) {
	result, err := c.api.ContainerInspect(
		ctx,
		containerID,
		client.ContainerInspectOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf(errEnv, ShortID(containerID), c.classify(err))
	}

	environ := map[string]string{}

	if result.Container.Config == nil {
		return environ, nil
	}

	for _, pair := range result.Container.Config.Env {
		name, value, found := strings.Cut(pair, envPairSep)
		if !found {
			continue
		}
		environ[name] = value
	}

	return environ, nil
}

func (c *Client) NetworkAddress(
	ctx context.Context,
	containerID, networkName string,
) (string, error) {
	endpoints, err := c.Endpoints(ctx, containerID)
	if err != nil {
		return "", fmt.Errorf(
			errAddress,
			ShortID(containerID),
			networkName,
			err,
		)
	}

	settings, attached := endpoints[networkName]
	if !attached || settings == nil || !settings.IPAddress.IsValid() {
		return "", fmt.Errorf(errNoAddress, ShortID(containerID), networkName)
	}

	return settings.IPAddress.String(), nil
}

// OwnAddress is where khaos dials a target DIRECTLY, on the container's own
// address rather than on a published host port. The host routes to a bridge
// network's addresses, which is what makes a stateful dependency reachable with
// nothing published, and the network with the lowest name is chosen so two runs
// against a multi-homed container agree.
func (c *Client) OwnAddress(
	ctx context.Context,
	containerID string,
) (string, string, error) {
	endpoints, err := c.Endpoints(ctx, containerID)
	if err != nil {
		return "", "", err
	}

	names := make([]string, 0, len(endpoints))
	for name := range endpoints {
		names = append(names, name)
	}
	slices.Sort(names)

	for _, name := range names {
		settings := endpoints[name]
		if settings == nil || !settings.IPAddress.IsValid() {
			continue
		}

		return name, settings.IPAddress.String(), nil
	}

	return "", "", fmt.Errorf(errNoNetwork, ShortID(containerID))
}

// BridgeGateway is the address a container reaches the host on: the DEFAULT
// bridge's gateway, discovered rather than assumed, since it is not 172.17.0.1
// on every host. A user-defined network's own gateway is that network's default
// route and answers a ping, but a HOST LISTENER bound on it is refused from
// containers on the network, which is why this is not that address.
func (c *Client) BridgeGateway(ctx context.Context) (string, error) {
	result, err := c.api.NetworkInspect(
		ctx,
		bridgeNetwork,
		client.NetworkInspectOptions{},
	)
	if err != nil {
		return "", fmt.Errorf(errBridge, err)
	}

	for _, config := range result.Network.IPAM.Config {
		if config.Gateway.IsValid() {
			return config.Gateway.String(), nil
		}
	}

	return "", errors.New(errNoBridge)
}

// Gateways is every address DOCKER manages as a network gateway, which is a
// narrower question than "is this a bridge". `/sys/class/net/<if>/bridge`
// exists for every kernel bridge device: measured on this host, that includes
// a CNI pod bridge, a swarm overlay's gateway bridge and forty-nine
// user-defined ones carrying unrelated projects' containers -- and on a host
// whose LAN interface is enslaved to a bridge, the routable LAN address itself.
// khaos binds listeners that answer whatever asks them, so the allowed set has
// to come from the daemon rather than from sysfs.
func (c *Client) Gateways(ctx context.Context) ([]string, error) {
	networks, err := c.api.NetworkList(ctx, client.NetworkListOptions{})
	if err != nil {
		return nil, fmt.Errorf(errGateways, err)
	}

	addresses := []string{}

	for _, network := range networks.Items {
		for _, config := range network.IPAM.Config {
			if config.Gateway.IsValid() {
				addresses = append(addresses, config.Gateway.String())
			}
		}
	}

	return addresses, nil
}

// classify turns a daemon NotFound into ErrContainerGone, so it is only valid
// where the MISSING THING IS THE CONTAINER; NetworkConnect returns NotFound for
// a missing NETWORK, so see classifyNetwork.
//
// The daemon's error is formatted with %v and NOT wrapped, here and in
// classifyNetwork: wrapping would let callers match on the Docker SDK's own
// error taxonomy, which is the coupling this translation exists to remove.
func (c *Client) classify(err error) error {
	if errdefs.IsNotFound(err) {
		//nolint:errorlint // %v is deliberate: see above
		return fmt.Errorf("%w: %v", ErrContainerGone, err)
	}
	return err
}

// classifyNetwork resolves the ambiguity by ASKING, because only the
// container's absence makes the fault moot: if the container still exists, the
// network was the missing resource and khaos still owes a restore.
func (c *Client) classifyNetwork(
	ctx context.Context,
	containerID string,
	err error,
) error {
	if !errdefs.IsNotFound(err) {
		return err
	}

	if _, alive := c.api.ContainerInspect(
		ctx,
		containerID,
		client.ContainerInspectOptions{},
	); alive == nil {
		//nolint:errorlint // %v is deliberate: see classify
		return fmt.Errorf("%w: %v", ErrNetworkGone, err)
	}

	//nolint:errorlint // %v is deliberate: see classify
	return fmt.Errorf("%w: %v", ErrContainerGone, err)
}

func (c *Client) PublishedPort(
	ctx context.Context,
	containerID string,
	internal int,
) (int, error) {
	result, err := c.api.ContainerInspect(
		ctx,
		containerID,
		client.ContainerInspectOptions{},
	)
	if err != nil {
		return 0, fmt.Errorf(errPorts, ShortID(containerID), c.classify(err))
	}

	if result.Container.NetworkSettings == nil {
		return 0, fmt.Errorf(errNoPort, internal, ShortID(containerID))
	}

	for port, bindings := range result.Container.NetworkSettings.Ports {
		if int(port.Num()) != internal {
			continue
		}
		for _, binding := range bindings {
			if published, err := strconv.Atoi(
				binding.HostPort,
			); err == nil &&
				published > 0 {
				return published, nil
			}
		}
	}

	return 0, fmt.Errorf(errNoPort, internal, ShortID(containerID))
}
