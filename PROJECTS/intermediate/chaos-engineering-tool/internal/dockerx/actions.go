// ©AngelaMos | 2026
// actions.go

package dockerx

import (
	"context"
	"errors"
	"fmt"
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
	errBridge     = "read the gateway of the default bridge network: %w"
	errNoBridge   = "the default bridge network reports no gateway address, so khaos cannot find an address a container can reach it on"

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

// BridgeGateway is the address a container reaches the host on: the DEFAULT
// bridge's gateway, discovered rather than assumed, since it is not 172.17.0.1
// on every host and a user-defined network's own gateway is not reachable.
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
