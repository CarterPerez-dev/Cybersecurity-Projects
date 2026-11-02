// ©AngelaMos | 2026
// ratelimit.go

package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
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

func KeyByIP(r *http.Request) string {
	return "ratelimit:ip:" + RealIP(r)
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

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("failed to encode rate-limit response", "error", err)
	}
}

type limiterEntry struct {
	limiter    *rate.Limiter
	lastAccess atomic.Int64
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
			if ok && entry.lastAccess.Load() < cutoff {
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
		}
		newEntry.lastAccess.Store(now)
		entryI, _ = l.limiters.LoadOrStore(key, newEntry)
	}

	entry, ok := entryI.(*limiterEntry)
	if !ok {
		return nil, fmt.Errorf("invalid limiter entry type")
	}
	entry.lastAccess.Store(now)

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

func PerMinute(rate, burst int) redis_rate.Limit {
	return redis_rate.Limit{
		Rate:   rate,
		Burst:  burst,
		Period: time.Minute,
	}
}

func PerSecond(rate, burst int) redis_rate.Limit {
	return redis_rate.Limit{
		Rate:   rate,
		Burst:  burst,
		Period: time.Second,
	}
}

func PerHour(rate, burst int) redis_rate.Limit {
	return redis_rate.Limit{
		Rate:   rate,
		Burst:  burst,
		Period: time.Hour,
	}
}
