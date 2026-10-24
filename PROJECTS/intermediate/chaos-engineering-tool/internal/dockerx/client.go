// ©AngelaMos | 2026
// client.go

package dockerx

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"

	"github.com/moby/moby/client"
)

var (
	ErrNoEndpoint       = errors.New("no Docker endpoint found")
	ErrSocketMissing    = errors.New("the Docker socket does not exist")
	ErrSocketDenied     = errors.New("permission denied on the Docker socket")
	ErrNotASocket       = errors.New("the Docker endpoint path is not a socket")
	ErrNothingListening = errors.New(
		"the Docker socket exists but nothing is listening on it",
	)
	ErrDaemonSilent = errors.New(
		"the Docker endpoint is reachable but the daemon did not answer",
	)
)

const (
	dialTimeout   = 3 * time.Second
	unixNetwork   = "unix"
	errClientFmt  = "docker client: %w"
	errWrapPath   = "%w: %s"
	errWrapDetail = "%w: %v"
)

type Client struct {
	api           *client.Client
	endpoint      Endpoint
	version       string
	daemon        string
	serverVersion string
}

func Connect(ctx context.Context, endpoint Endpoint) (*Client, error) {
	if endpoint.Host == "" {
		return nil, ErrNoEndpoint
	}

	if path, ok := endpoint.SocketPath(); ok {
		if err := probeSocket(path); err != nil {
			return nil, err
		}
	}

	api, err := client.New(client.WithHost(endpoint.Host))
	if err != nil {
		return nil, fmt.Errorf(errClientFmt, err)
	}

	ping, err := api.Ping(ctx, client.PingOptions{})
	if err != nil {
		_ = api.Close()
		return nil, fmt.Errorf(errWrapDetail, ErrDaemonSilent, err)
	}

	c := &Client{api: api, endpoint: endpoint, version: ping.APIVersion}

	// The daemon's own ID, read from the daemon rather than derived from the
	// endpoint string: one daemon is reachable as a socket path, a TCP address
	// and an SSH context, and all three are the same place.
	if info, err := api.Info(ctx, client.InfoOptions{}); err == nil {
		c.daemon = info.Info.ID
		c.serverVersion = info.Info.ServerVersion
	}

	return c, nil
}

// Daemon is a stable identity for the daemon this client is attached to, empty
// when the daemon would not say, which callers must treat as unknown rather
// than as a match.
func (c *Client) Daemon() string {
	return c.daemon
}

func (c *Client) ServerVersion() string {
	return c.serverVersion
}

func Open(ctx context.Context) (*Client, error) {
	endpoint, err := ResolveEndpoint(os.Getenv, homeDir())
	if err != nil {
		return nil, err
	}
	return Connect(ctx, endpoint)
}

func (c *Client) Close() error {
	return c.api.Close()
}

func (c *Client) Endpoint() Endpoint {
	return c.endpoint
}

func (c *Client) APIVersion() string {
	return c.version
}

func probeSocket(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf(errWrapPath, ErrSocketMissing, path)
	}
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf(errWrapPath, ErrSocketDenied, path)
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	if info.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf(errWrapPath, ErrNotASocket, path)
	}

	conn, err := net.DialTimeout(unixNetwork, path, dialTimeout)
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf(errWrapPath, ErrSocketDenied, path)
	}
	if err != nil {
		return fmt.Errorf(errWrapPath, ErrNothingListening, path)
	}

	return conn.Close()
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}
