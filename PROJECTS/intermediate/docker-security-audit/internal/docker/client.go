/*
CarterPerez-dev | 2026
client.go
*/

package docker

import (
	"context"
	"fmt"
	"sync"

	"github.com/CarterPerez-dev/docksec/internal/config"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/client"
)

type Client struct {
	api *client.Client
}

var (
	instance *Client
	once     sync.Once
	initErr  error
)

func NewClient() (*Client, error) {
	once.Do(func() {
		cli, err := client.NewClientWithOpts(
			client.FromEnv,
			client.WithAPIVersionNegotiation(),
		)
		if err != nil {
			initErr = fmt.Errorf("creating docker client: %w", err)
			return
		}
		instance = &Client{api: cli}
	})

	if initErr != nil {
		return nil, initErr
	}
	return instance, nil
}

func (c *Client) Close() error {
	if c.api != nil {
		return c.api.Close()
	}
	return nil
}

func (c *Client) Ping(ctx context.Context) error {
	pingCtx, cancel := context.WithTimeout(ctx, config.ConnectionTimeout)
	defer cancel()

	_, err := c.api.Ping(pingCtx)
	if err != nil {
		return fmt.Errorf("pinging docker daemon: %w", err)
	}
	return nil
}

func (c *Client) Info(ctx context.Context) (system.Info, error) {
	infoCtx, cancel := context.WithTimeout(ctx, config.DefaultTimeout)
	defer cancel()

	info, err := c.api.Info(infoCtx)
	if err != nil {
		return system.Info{}, fmt.Errorf("getting docker info: %w", err)
	}
	return info, nil
}

func (c *Client) ServerVersion(ctx context.Context) (types.Version, error) {
	versionCtx, cancel := context.WithTimeout(ctx, config.ConnectionTimeout)
	defer cancel()

	version, err := c.api.ServerVersion(versionCtx)
	if err != nil {
		return types.Version{}, fmt.Errorf("getting docker version: %w", err)
	}
	return version, nil
}

func (c *Client) ListContainers(
	ctx context.Context,
	all bool,
) ([]types.Container, error) {
	listCtx, cancel := context.WithTimeout(ctx, config.DefaultTimeout)
	defer cancel()

	containers, err := c.api.ContainerList(
		listCtx,
		container.ListOptions{All: all},
	)
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}
	return containers, nil
}

func (c *Client) InspectContainer(
	ctx context.Context,
	containerID string,
) (types.ContainerJSON, error) {
	inspectCtx, cancel := context.WithTimeout(ctx, config.InspectTimeout)
	defer cancel()

	info, err := c.api.ContainerInspect(inspectCtx, containerID)
	if err != nil {
		return types.ContainerJSON{}, fmt.Errorf(
			"inspecting container %s: %w",
			containerID,
			err,
		)
	}
	return info, nil
}

func (c *Client) ListImages(ctx context.Context) ([]image.Summary, error) {
	listCtx, cancel := context.WithTimeout(ctx, config.DefaultTimeout)
	defer cancel()

	images, err := c.api.ImageList(listCtx, image.ListOptions{All: false})
	if err != nil {
		return nil, fmt.Errorf("listing images: %w", err)
	}
	return images, nil
}

func (c *Client) InspectImage(
	ctx context.Context,
	imageID string,
) (types.ImageInspect, error) {
	inspectCtx, cancel := context.WithTimeout(ctx, config.InspectTimeout)
	defer cancel()

	info, _, err := c.api.ImageInspectWithRaw(inspectCtx, imageID)
	if err != nil {
		return types.ImageInspect{}, fmt.Errorf(
			"inspecting image %s: %w",
			imageID,
			err,
		)
	}
	return info, nil
}

func (c *Client) ImageHistory(
	ctx context.Context,
	imageID string,
) ([]image.HistoryResponseItem, error) {
	historyCtx, cancel := context.WithTimeout(ctx, config.InspectTimeout)
	defer cancel()

	history, err := c.api.ImageHistory(historyCtx, imageID)
	if err != nil {
		return nil, fmt.Errorf("getting image history %s: %w", imageID, err)
	}
	return history, nil
}
