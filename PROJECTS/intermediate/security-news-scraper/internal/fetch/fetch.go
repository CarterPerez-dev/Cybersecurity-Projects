// ©AngelaMos | 2026
// fetch.go

package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	headerUserAgent       = "User-Agent"
	headerAccept          = "Accept"
	headerIfNoneMatch     = "If-None-Match"
	headerIfModifiedSince = "If-Modified-Since"
	headerETag            = "ETag"
	headerLastModified    = "Last-Modified"
	headerRetryAfter      = "Retry-After"

	acceptFeed = "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8"

	defaultBackoffBase = 500 * time.Millisecond
	maxBodyBytes       = 16 << 20
	maxRetryAfter      = 60 * time.Second
)

type Options struct {
	UserAgent    string
	PerHostRate  float64
	PerHostBurst int
	Timeout      time.Duration
	MaxRetries   int
}

type Request struct {
	URL          string
	ETag         string
	LastModified string
}

type Result struct {
	Status       int
	Body         []byte
	ETag         string
	LastModified string
	NotModified  bool
}

type Client struct {
	http        *http.Client
	ua          string
	rate        rate.Limit
	burst       int
	maxRetries  int
	backoffBase time.Duration

	mu       sync.Mutex
	limiters map[string]*rate.Limiter

	robots *robotsCache
}

func New(opts Options) *Client {
	c := &Client{
		http:        &http.Client{Timeout: opts.Timeout},
		ua:          opts.UserAgent,
		rate:        rate.Limit(opts.PerHostRate),
		burst:       opts.PerHostBurst,
		maxRetries:  opts.MaxRetries,
		backoffBase: defaultBackoffBase,
		limiters:    make(map[string]*rate.Limiter),
	}
	c.robots = newRobotsCache(c)
	return c
}

func (c *Client) limiterFor(host string) *rate.Limiter {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.limiters[host]
	if !ok {
		l = rate.NewLimiter(c.rate, c.burst)
		c.limiters[host] = l
	}
	return l
}

func (c *Client) Fetch(ctx context.Context, req Request) (Result, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return Result{}, fmt.Errorf("fetch: parse url %q: %w", req.URL, err)
	}

	var lastErr error
	var override time.Duration
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := c.backoff(attempt)
			if override > 0 {
				delay = override
			}
			if err := sleep(ctx, delay); err != nil {
				return Result{}, err
			}
		}
		if err := c.limiterFor(u.Host).Wait(ctx); err != nil {
			return Result{}, err
		}
		res, retryAfter, retry, err := c.do(ctx, req)
		if err == nil {
			return res, nil
		}
		lastErr = err
		override = retryAfter
		if !retry {
			return Result{}, err
		}
	}
	return Result{}, fmt.Errorf("fetch %s: exhausted %d retries: %w", req.URL, c.maxRetries, lastErr)
}

func (c *Client) Allowed(ctx context.Context, rawURL string) (bool, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false, fmt.Errorf("fetch: parse url %q: %w", rawURL, err)
	}
	return c.robots.allowed(ctx, u)
}

func (c *Client) do(ctx context.Context, req Request) (Result, time.Duration, bool, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return Result{}, 0, false, fmt.Errorf("fetch %s: build request: %w", req.URL, err)
	}
	httpReq.Header.Set(headerUserAgent, c.ua)
	httpReq.Header.Set(headerAccept, acceptFeed)
	if req.ETag != "" {
		httpReq.Header.Set(headerIfNoneMatch, req.ETag)
	}
	if req.LastModified != "" {
		httpReq.Header.Set(headerIfModifiedSince, req.LastModified)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Result{}, 0, false, fmt.Errorf("fetch %s: %w", req.URL, err)
		}
		return Result{}, 0, true, fmt.Errorf("fetch %s: %w", req.URL, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return Result{
			Status:       resp.StatusCode,
			NotModified:  true,
			ETag:         req.ETag,
			LastModified: req.LastModified,
		}, 0, false, nil
	case resp.StatusCode == http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		if err != nil {
			return Result{}, 0, true, fmt.Errorf("fetch %s: read body: %w", req.URL, err)
		}
		return Result{
			Status:       resp.StatusCode,
			Body:         body,
			ETag:         resp.Header.Get(headerETag),
			LastModified: resp.Header.Get(headerLastModified),
		}, 0, false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError:
		drain(resp.Body)
		return Result{}, retryAfter(resp), true, fmt.Errorf("fetch %s: server status %d", req.URL, resp.StatusCode)
	default:
		drain(resp.Body)
		return Result{}, 0, false, fmt.Errorf("fetch %s: status %d", req.URL, resp.StatusCode)
	}
}

func drain(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxBodyBytes))
}

func retryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get(headerRetryAfter)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		d := time.Duration(secs) * time.Second
		if d > maxRetryAfter {
			return maxRetryAfter
		}
		if d < 0 {
			return 0
		}
		return d
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d <= 0 {
			return 0
		}
		if d > maxRetryAfter {
			return maxRetryAfter
		}
		return d
	}
	return 0
}

func (c *Client) backoff(attempt int) time.Duration {
	return c.backoffBase * time.Duration(1<<(attempt-1))
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
