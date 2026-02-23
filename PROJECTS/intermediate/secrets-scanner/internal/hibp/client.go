// ©AngelaMos | 2026
// client.go

package hibp

import (
	"bufio"
	"context"
	"crypto/sha1"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sony/gobreaker/v2"
	"golang.org/x/time/rate"
)

type Result struct {
	Breached bool
	Count    int
}

type Client struct {
	httpClient *http.Client
	baseURL    string
	cache      *lru.Cache[string, Result]
	breaker    *gobreaker.CircuitBreaker[Result]
	limiter    *rate.Limiter
}

func NewClient() *Client {
	cache, err := lru.New[string, Result](10000)
	if err != nil {
		panic(fmt.Errorf("create HIBP cache: %w", err))
	}

	breaker := gobreaker.NewCircuitBreaker[Result](
		gobreaker.Settings{
			Name:        "hibp",
			MaxRequests: 3,
			Interval:    30 * time.Second,
			Timeout:     60 * time.Second,
			ReadyToTrip: func(
				counts gobreaker.Counts,
			) bool {
				return counts.ConsecutiveFailures > 5
			},
		},
	)

	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		baseURL: "https://api.pwnedpasswords.com/range/",
		cache:   cache,
		breaker: breaker,
		limiter: rate.NewLimiter(rate.Every(200*time.Millisecond), 5),
	}
}

func (c *Client) Check(
	ctx context.Context, secret string,
) (Result, error) {
	hash := sha1Hash(secret)
	prefix := hash[:5]
	suffix := hash[5:]

	if cached, ok := c.cache.Get(hash); ok {
		return cached, nil
	}

	if err := c.limiter.Wait(ctx); err != nil {
		return Result{}, fmt.Errorf("rate limit: %w", err)
	}

	result, err := c.breaker.Execute(func() (Result, error) {
		return c.queryAPI(ctx, prefix, suffix)
	})
	if err != nil {
		return Result{}, err
	}

	c.cache.Add(hash, result)
	return result, nil
}

const maxRetries = 3

func (c *Client) queryAPI(
	ctx context.Context, prefix, suffix string,
) (Result, error) {
	url := c.baseURL + prefix

	for attempt := range maxRetries {
		if attempt > 0 {
			backoff := time.Duration(attempt) * 2 * time.Second
			select {
			case <-ctx.Done():
				return Result{}, ctx.Err()
			case <-time.After(backoff):
			}
		}

		result, retry, err := c.doQuery(ctx, url, suffix)
		if !retry {
			return result, err
		}
	}

	return Result{}, fmt.Errorf("HIBP API: retries exhausted (429)")
}

func (c *Client) doQuery(
	ctx context.Context, url, suffix string,
) (Result, bool, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, url, nil,
	)
	if err != nil {
		return Result{}, false,
			fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "portia-secrets-scanner/1.0")
	req.Header.Set("Add-Padding", "true")

	resp, err := c.httpClient.Do(req) //nolint:gosec
	if err != nil {
		return Result{}, false,
			fmt.Errorf("HIBP request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusTooManyRequests {
		return Result{}, true, nil
	}

	if resp.StatusCode != http.StatusOK {
		return Result{}, false, fmt.Errorf(
			"HIBP API status: %d", resp.StatusCode,
		)
	}

	scanner := bufio.NewScanner(resp.Body)
	upperSuffix := strings.ToUpper(suffix)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] == upperSuffix {
			trimmed := strings.TrimSpace(parts[1])
			count, err := strconv.Atoi(trimmed)
			if err != nil {
				return Result{}, false, fmt.Errorf(
					"parse breach count %q: %w",
					trimmed,
					err,
				)
			}
			return Result{Breached: true, Count: count},
				false, nil
		}
	}

	return Result{Breached: false, Count: 0}, false, nil
}

func sha1Hash(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	return fmt.Sprintf("%X", h.Sum(nil))
}
