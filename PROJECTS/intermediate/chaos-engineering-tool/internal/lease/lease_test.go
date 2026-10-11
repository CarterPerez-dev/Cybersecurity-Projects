// ©AngelaMos | 2026
// lease_test.go

package lease

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewLeaseIsAliveImmediately(t *testing.T) {
	l := New(time.Minute)

	if l.Expired(time.Now().UTC()) {
		t.Fatal("a freshly issued lease was already expired")
	}

	if l.ID() == "" {
		t.Fatal(
			"a lease was issued with no identifier, so the journal cannot attribute a fault to it",
		)
	}
}

func TestTTLIsClampedToAFloor(t *testing.T) {
	l := New(time.Millisecond)

	if l.TTL() != MinimumTTL {
		t.Fatalf(
			"TTL %v was accepted; a lease shorter than %v would expire mid-injection",
			l.TTL(),
			MinimumTTL,
		)
	}
}

func TestLeaseExpiresWithoutRenewal(t *testing.T) {
	l := New(MinimumTTL)

	if l.Expired(time.Now().UTC()) {
		t.Fatal("expired too early")
	}

	if !l.Expired(time.Now().UTC().Add(MinimumTTL + time.Second)) {
		t.Fatal(
			"a lease that is never renewed must expire, or the dead man's switch never fires",
		)
	}
}

func TestRenewPushesExpiryOut(t *testing.T) {
	l := New(time.Minute)
	first := l.ExpiresAt()

	time.Sleep(10 * time.Millisecond)

	if second := l.Renew(); !second.After(first) {
		t.Fatalf("renew did not extend the lease: %v then %v", first, second)
	}
}

func TestRenewalAlwaysFitsTwiceInsideTheTTL(t *testing.T) {
	ttls := []time.Duration{
		time.Millisecond, MinimumTTL, 3 * time.Second, 10 * time.Second,
		DefaultTTL, time.Minute, 10 * time.Minute, time.Hour,
	}

	for _, ttl := range ttls {
		t.Run(ttl.String(), func(t *testing.T) {
			l := New(ttl)

			if l.RenewalInterval() >= l.TTL() {
				t.Fatalf(
					"renewal interval %v is not shorter than TTL %v, so one missed tick drops the fault",
					l.RenewalInterval(),
					l.TTL(),
				)
			}

			if l.TTL()/l.RenewalInterval() < 2 {
				t.Fatalf(
					"only %v fits inside TTL %v; a single hiccup would expire a live fault",
					l.TTL()/l.RenewalInterval(),
					l.TTL(),
				)
			}
		})
	}
}

func TestKeepRenewsUntilCancelled(t *testing.T) {
	l := New(MinimumTTL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var renewals atomic.Int64
	done := make(chan error, 1)

	go func() {
		done <- l.Keep(ctx, func(time.Time) error {
			renewals.Add(1)
			return nil
		})
	}()

	// Read the lease concurrently with the keeper, so -race is the negative
	// control for the mutex guarding expiresAt.
	deadline := time.Now().Add(l.RenewalInterval() * 2)
	for time.Now().Before(deadline) {
		_ = l.ExpiresAt()
		_ = l.Expired(time.Now().UTC())
	}
	cancel()

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Keep returned %v, want context.Canceled", err)
	}

	if renewals.Load() == 0 {
		t.Fatal(
			"Keep never renewed, so a held fault would expire under a live khaos",
		)
	}
}

func TestKeepStopsWhenRenewalFails(t *testing.T) {
	l := New(MinimumTTL)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// The sentinel must be distinct from any error the context itself can
	// produce. An earlier version of this test returned context.DeadlineExceeded
	// from the callback under a short deadline, so a Keep that ignored the
	// callback entirely still returned the expected value and the test passed.
	want := errors.New("journal write failed")

	started := time.Now()
	got := l.Keep(ctx, func(time.Time) error { return want })
	elapsed := time.Since(started)

	if !errors.Is(got, want) {
		t.Fatalf(
			"Keep returned %v; a journal write failure during renewal must surface, "+
				"not be swallowed while the fault stays applied",
			got,
		)
	}

	if elapsed > l.RenewalInterval()*3 {
		t.Fatalf(
			"Keep took %v to notice a failing renewal, which is longer than it should wait",
			elapsed,
		)
	}
}

func TestLeaseIDsAreDistinct(t *testing.T) {
	seen := make(map[string]bool, 64)

	for range 64 {
		id := New(time.Minute).ID()
		if seen[id] {
			t.Fatalf(
				"duplicate lease id %q; two runs would reclaim each other's faults",
				id,
			)
		}
		seen[id] = true
	}
}
