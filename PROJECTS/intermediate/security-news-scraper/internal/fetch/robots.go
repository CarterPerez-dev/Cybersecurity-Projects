// ©AngelaMos | 2026
// robots.go

package fetch

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/temoto/robotstxt"
)

const (
	robotsPath     = "/robots.txt"
	maxRobotsBytes = 512 << 10
	robotsRootPath = "/"
)

type robotsEntry struct {
	once sync.Once
	data *robotstxt.RobotsData
}

type robotsCache struct {
	client *Client

	mu      sync.Mutex
	entries map[string]*robotsEntry
}

func newRobotsCache(client *Client) *robotsCache {
	return &robotsCache{
		client:  client,
		entries: make(map[string]*robotsEntry),
	}
}

func (rc *robotsCache) allowed(ctx context.Context, u *url.URL) (bool, error) {
	rc.mu.Lock()
	e, ok := rc.entries[u.Host]
	if !ok {
		e = &robotsEntry{}
		rc.entries[u.Host] = e
	}
	rc.mu.Unlock()

	e.once.Do(func() {
		data, err := rc.load(ctx, u)
		if err != nil {
			data, _ = robotstxt.FromStatusAndBytes(http.StatusOK, nil)
		}
		e.data = data
	})

	path := u.EscapedPath()
	if path == "" {
		path = robotsRootPath
	}
	return e.data.FindGroup(rc.client.ua).Test(path), nil
}

func (rc *robotsCache) load(ctx context.Context, u *url.URL) (*robotstxt.RobotsData, error) {
	robotsURL := u.Scheme + "://" + u.Host + robotsPath
	if err := rc.client.limiterFor(u.Host).Wait(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(headerUserAgent, rc.client.ua)

	resp, err := rc.client.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRobotsBytes))
	if err != nil {
		return nil, err
	}
	return robotstxt.FromStatusAndBytes(resp.StatusCode, body)
}
