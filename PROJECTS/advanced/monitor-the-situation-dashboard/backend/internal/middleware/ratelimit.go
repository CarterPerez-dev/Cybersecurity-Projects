// AngelaMos | 2026
// ratelimit.go

package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	redis_rate "github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

type RateLimitConfig struct {
	Limit      redis_rate.Limit
	KeyFunc    func(*http.Request) string
	FailOpen   bool
	BypassFunc func(*http.Request) bool
	OnLimited  func(http.ResponseWriter, *http.Request, *redis_rate.Result)
}

type RateLimiter struct {
	limiter  *redis_rate.Limiter
	fallback *localLimiter
	config   RateLimitConfig
}

func NewRateLimiter(rdb *redis.Client, cfg RateLimitConfig) *RateLimiter {
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = KeyByIP
	}

	return &RateLimiter{
		limiter:  redis_rate.NewLimiter(rdb),
		fallback: newLocalLimiter(),
		config:   cfg,
	}
}

func (rl *RateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rl.config.BypassFunc != nil && rl.config.BypassFunc(r) {
			next.ServeHTTP(w, r)
			return
		}

		key := rl.config.KeyFunc(r)
		res, err := rl.allow(r.Context(), key)
		if err != nil {
			if rl.config.FailOpen {
				slog.Warn("rate limiter error, failing open",
					"error", err,
					"key", key,
				)
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		setRateLimitHeaders(w, res, rl.config.Limit)

		if res.Allowed == 0 {
			if rl.config.OnLimited != nil {
				rl.config.OnLimited(w, r, res)
				return
			}
			writeRateLimitExceeded(w, res)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allow(
	ctx context.Context,
	key string,
) (*redis_rate.Result, error) {
	res, err := rl.limiter.Allow(ctx, key, rl.config.Limit)
	if err != nil {
		return rl.fallback.allow(key, rl.config.Limit)
	}
	return res, nil
}

// KeyByIP keys requests by their RemoteAddr only — does NOT trust
// X-Forwarded-For. Use KeyByClientIP(trustedHops) when you have a known
// proxy chain to peel back.
func KeyByIP(r *http.Request) string {
	return "ratelimit:ip:" + ClientIP(r, 0)
}

// KeyByClientIP returns a KeyFunc that honors trustedHops of X-Forwarded-For.
func KeyByClientIP(trustedHops int) func(*http.Request) string {
	return func(r *http.Request) string {
		return "ratelimit:ip:" + ClientIP(r, trustedHops)
	}
}

func KeyByUser(r *http.Request) string {
	if userID := GetUserID(r.Context()); userID != "" {
		return "ratelimit:user:" + userID
	}
	return KeyByIP(r)
}

func KeyByUserAndEndpoint(r *http.Request) string {
	userKey := KeyByUser(r)
	endpoint := normalizeEndpoint(r.URL.Path)
	return fmt.Sprintf("%s:endpoint:%s", userKey, endpoint)
}

func normalizeEndpoint(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	normalized := make([]string, 0, len(parts))

	for _, part := range parts {
		if isUUID(part) || isNumeric(part) {
			normalized = append(normalized, "{id}")
		} else {
			normalized = append(normalized, part)
		}
	}

	return "/" + strings.Join(normalized, "/")
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	return s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func setRateLimitHeaders(
	w http.ResponseWriter,
	res *redis_rate.Result,
	limit redis_rate.Limit,
) {
	h := w.Header()

	h.Set("X-RateLimit-Limit", strconv.Itoa(limit.Rate))
	h.Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))
	h.Set("X-RateLimit-Reset", strconv.FormatInt(
		time.Now().Add(res.ResetAfter).Unix(), 10,
	))

	windowSecs := int(limit.Period.Seconds())
	h.Set("RateLimit-Policy", fmt.Sprintf(`%d;w=%d`, limit.Rate, windowSecs))
	h.Set(
		"RateLimit",
		fmt.Sprintf(`%d;t=%d`, res.Remaining, int(res.ResetAfter.Seconds())),
	)
}

func writeRateLimitExceeded(w http.ResponseWriter, res *redis_rate.Result) {
	retryAfter := int(res.RetryAfter.Seconds())
	if retryAfter < 1 {
		retryAfter = 1
	}

	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)

	response := map[string]any{
		"success": false,
		"error": map[string]any{
			"code": "RATE_LIMITED",
			"message": fmt.Sprintf(
				"Rate limit exceeded. Retry after %d seconds.",
				retryAfter,
			),
		},
	}

	//nolint:errcheck // best-effort response write
	_ = json.NewEncoder(w).Encode(response)
}

type limiterEntry struct {
	limiter    *rate.Limiter
	lastAccess int64
}

type localLimiter struct {
	limiters sync.Map
}

const (
	cleanupInterval = 5 * time.Minute
	entryTTL        = 10 * time.Minute
)

func newLocalLimiter() *localLimiter {
	l := &localLimiter{}
	go l.cleanup()
	return l
}

func (l *localLimiter) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-entryTTL).Unix()
		l.limiters.Range(func(key, value any) bool {
			entry, ok := value.(*limiterEntry)
			if ok && entry.lastAccess < cutoff {
				l.limiters.Delete(key)
			}
			return true
		})
	}
}

func (l *localLimiter) allow(
	key string,
	limit redis_rate.Limit,
) (*redis_rate.Result, error) {
	ratePerSec := float64(limit.Rate) / limit.Period.Seconds()
	now := time.Now().Unix()

	entryI, loaded := l.limiters.Load(key)
	if !loaded {
		newEntry := &limiterEntry{
			limiter: rate.NewLimiter(
				rate.Limit(ratePerSec),
				limit.Burst,
			),
			lastAccess: now,
		}
		entryI, _ = l.limiters.LoadOrStore(key, newEntry)
	}

	entry, ok := entryI.(*limiterEntry)
	if !ok {
		return nil, fmt.Errorf("invalid limiter entry type")
	}
	entry.lastAccess = now

	allowed := entry.limiter.Allow()

	remaining := int(entry.limiter.Tokens())
	if remaining < 0 {
		remaining = 0
	}

	var retryAfter time.Duration
	if !allowed {
		retryAfter = time.Duration(float64(time.Second) / ratePerSec)
	} else {
		retryAfter = -1
	}

	allowedInt := 0
	if allowed {
		allowedInt = 1
	}

	return &redis_rate.Result{
		Limit:      limit,
		Allowed:    allowedInt,
		Remaining:  remaining,
		RetryAfter: retryAfter,
		ResetAfter: time.Duration(float64(time.Second) / ratePerSec),
	}, nil
}

type TierConfig struct {
	RequestsPerMinute int
	BurstSize         int
}

var DefaultTiers = map[string]TierConfig{
	"free":       {RequestsPerMinute: 60, BurstSize: 10},
	"pro":        {RequestsPerMinute: 600, BurstSize: 100},
	"enterprise": {RequestsPerMinute: 6000, BurstSize: 1000},
}

func TieredRateLimiter(
	rdb *redis.Client,
	tiers map[string]TierConfig,
) func(http.Handler) http.Handler {
	limiter := redis_rate.NewLimiter(rdb)
	fallback := newLocalLimiter()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := GetUserID(r.Context())
			tier := GetUserTier(r.Context())

			if tier == "" {
				tier = "free"
			}

			config, ok := tiers[tier]
			if !ok {
				config = tiers["free"]
			}

			limit := redis_rate.Limit{
				Rate:   config.RequestsPerMinute,
				Burst:  config.BurstSize,
				Period: time.Minute,
			}

			key := fmt.Sprintf("ratelimit:user:%s", userID)

			res, err := limiter.Allow(r.Context(), key, limit)
			if err != nil {
				//nolint:errcheck // fallback never fails
				res, _ = fallback.allow(key, limit)
			}

			w.Header().Set("X-RateLimit-Tier", tier)
			setRateLimitHeaders(w, res, limit)

			if res.Allowed == 0 {
				writeRateLimitExceeded(w, res)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func PerMinute(rate, burst int) redis_rate.Limit {
	return PerWindow(rate, burst, time.Minute)
}

func PerSecond(rate, burst int) redis_rate.Limit {
	return PerWindow(rate, burst, time.Second)
}

func PerHour(rate, burst int) redis_rate.Limit {
	return PerWindow(rate, burst, time.Hour)
}

func PerWindow(rate, burst int, window time.Duration) redis_rate.Limit {
	if window <= 0 {
		window = time.Minute
	}
	return redis_rate.Limit{
		Rate:   rate,
		Burst:  burst,
		Period: window,
	}
}
