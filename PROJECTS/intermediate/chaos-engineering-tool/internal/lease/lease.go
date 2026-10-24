// ©AngelaMos | 2026
// lease.go

package lease

import (
	"context"
	"sync"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const (
	DefaultTTL     = 30 * time.Second
	MinimumTTL     = 2 * time.Second
	renewalDivisor = 3
	minimumTick    = 250 * time.Millisecond
)

type Lease struct {
	id  string
	ttl time.Duration

	mu        sync.RWMutex
	expiresAt time.Time
}

func New(ttl time.Duration) *Lease {
	if ttl < MinimumTTL {
		ttl = MinimumTTL
	}

	l := &Lease{id: journal.NewID(), ttl: ttl}
	l.Renew()

	return l
}

func (l *Lease) ID() string {
	return l.id
}

func (l *Lease) TTL() time.Duration {
	return l.ttl
}

func (l *Lease) ExpiresAt() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.expiresAt
}

func (l *Lease) Renew() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expiresAt = time.Now().UTC().Add(l.ttl)
	return l.expiresAt
}

func (l *Lease) Expired(now time.Time) bool {
	return now.After(l.ExpiresAt())
}

func (l *Lease) RenewalInterval() time.Duration {
	interval := l.ttl / renewalDivisor
	if interval < minimumTick {
		interval = minimumTick
	}
	return interval
}

func (l *Lease) Keep(ctx context.Context, onRenew func(time.Time) error) error {
	ticker := time.NewTicker(l.RenewalInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			expiry := l.Renew()
			if onRenew == nil {
				continue
			}
			if err := onRenew(expiry); err != nil {
				return err
			}
		}
	}
}
