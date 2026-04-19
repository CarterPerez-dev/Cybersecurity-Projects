/*
©AngelaMos | 2026
limiter_test.go
*/

package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestAllowWithinBurst(t *testing.T) {
	l := NewIPLimiter(rate.Every(time.Hour), 3)
	defer l.Stop()

	assert.True(t, l.Allow("10.0.0.1"))
	assert.True(t, l.Allow("10.0.0.1"))
	assert.True(t, l.Allow("10.0.0.1"))
}

func TestAllowExceedsBurst(t *testing.T) {
	l := NewIPLimiter(rate.Every(time.Hour), 2)
	defer l.Stop()

	assert.True(t, l.Allow("10.0.0.1"))
	assert.True(t, l.Allow("10.0.0.1"))
	assert.False(t, l.Allow("10.0.0.1"))
}

func TestDifferentIPsIndependent(t *testing.T) {
	l := NewIPLimiter(rate.Every(time.Hour), 1)
	defer l.Stop()

	assert.True(t, l.Allow("10.0.0.1"))
	assert.False(t, l.Allow("10.0.0.1"))

	assert.True(t, l.Allow("10.0.0.2"))
}

func TestCountTracksUniqueIPs(t *testing.T) {
	l := NewIPLimiter(rate.Every(time.Hour), 5)
	defer l.Stop()

	l.Allow("10.0.0.1")
	l.Allow("10.0.0.2")
	l.Allow("10.0.0.3")
	assert.Equal(t, 3, l.Count())

	l.Allow("10.0.0.1")
	assert.Equal(t, 3, l.Count())
}

func TestAllowConcurrent(t *testing.T) {
	l := NewIPLimiter(rate.Every(time.Hour), 100)
	defer l.Stop()

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.%d.%d", idx/256, idx%256)
			l.Allow(ip)
		}(i)
	}
	wg.Wait()

	assert.Equal(t, 50, l.Count())
}

func TestStopLifecycle(t *testing.T) {
	l := NewIPLimiter(rate.Every(time.Hour), 5)
	l.Allow("10.0.0.1")
	l.Stop()

	assert.Equal(t, 1, l.Count())
}
