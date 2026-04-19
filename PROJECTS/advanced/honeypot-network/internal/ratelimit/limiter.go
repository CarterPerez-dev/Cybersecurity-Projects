/*
©AngelaMos | 2026
limiter.go

Per-IP token bucket rate limiter with automatic cleanup

Each unique IP gets its own rate.Limiter. A background goroutine
periodically evicts entries that have not been seen recently to
prevent unbounded memory growth from scanning traffic.
*/

package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/CarterPerez-dev/hive/internal/config"
)

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type IPLimiter struct {
	mu       sync.Mutex
	limiters map[string]*entry
	rate     rate.Limit
	burst    int
	stop     chan struct{}
}

func NewIPLimiter(
	r rate.Limit, burst int,
) *IPLimiter {
	l := &IPLimiter{
		limiters: make(map[string]*entry),
		rate:     r,
		burst:    burst,
		stop:     make(chan struct{}),
	}

	go l.cleanup()

	return l
}

func (l *IPLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, exists := l.limiters[ip]
	if !exists {
		e = &entry{
			limiter: rate.NewLimiter(l.rate, l.burst),
		}
		l.limiters[ip] = e
	}

	e.lastSeen = time.Now()
	return e.limiter.Allow()
}

func (l *IPLimiter) Stop() {
	close(l.stop)
}

func (l *IPLimiter) cleanup() {
	ticker := time.NewTicker(config.DefaultRateLimitCleanup)
	defer ticker.Stop()

	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			l.evictStale()
		}
	}
}

func (l *IPLimiter) evictStale() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-config.DefaultRateLimitCleanup)
	for ip, e := range l.limiters {
		if e.lastSeen.Before(cutoff) {
			delete(l.limiters, ip)
		}
	}
}

func (l *IPLimiter) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.limiters)
}
