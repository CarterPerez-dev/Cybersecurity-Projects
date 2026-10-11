// ©AngelaMos | 2026
// sampling_test.go

package experiment

import (
	"context"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

type slowProbe struct {
	credential probe.Credential
	delay      time.Duration
}

func (p slowProbe) Name() string { return "slow" }

func (p slowProbe) Describe() string             { return "a probe that takes its time" }
func (p slowProbe) Credential() probe.Credential { return p.credential }

func (p slowProbe) Run(ctx context.Context) probe.Outcome {
	select {
	case <-ctx.Done():
	case <-time.After(p.delay):
	}

	return probe.Outcome{
		At:          time.Now().UTC(),
		Credential:  p.credential,
		Disposition: probe.Accepted,
	}
}

func pairOf(delay time.Duration) probe.Pair {
	return probe.Pair{
		Valid:   slowProbe{probe.Valid, delay},
		Invalid: slowProbe{probe.Invalid, delay},
	}
}

// A slow target must cost latency headroom, not sample count. Before the
// interval became a true period, a target that hung under the fault produced
// one paired sample where twenty-one were nominal, so the only verdict khaos
// could reach was probe-error.
func TestASlowProbeDoesNotCollapseTheSampleCount(t *testing.T) {
	cases := []struct {
		name     string
		duration time.Duration
		interval time.Duration
		delay    time.Duration
		atLeast  int
	}{
		{"instant probes", 200 * time.Millisecond, 20 * time.Millisecond, 0, 6},
		{
			"probe costs most of the period",
			200 * time.Millisecond,
			20 * time.Millisecond,
			15 * time.Millisecond,
			5,
		},
		{
			"probe costs more than the period",
			200 * time.Millisecond,
			10 * time.Millisecond,
			25 * time.Millisecond,
			3,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := Engine{}

			window := engine.sample(
				context.Background(),
				pairOf(tc.delay),
				tc.duration,
				tc.interval,
			)

			if got := window.Paired(); got < tc.atLeast {
				t.Fatalf(
					"collected %d paired samples in %v at a %v period with a %v probe, "+
						"want at least %d; a slow target must not silently drop the run below the "+
						"evidence floor",
					got,
					tc.duration,
					tc.interval,
					tc.delay,
					tc.atLeast,
				)
			}
		})
	}
}

func TestSamplingAlwaysProducesAtLeastOnePair(t *testing.T) {
	engine := Engine{}

	window := engine.sample(context.Background(), pairOf(0), 0, time.Second)

	if window.Paired() < 1 {
		t.Fatal(
			"a zero-length phase produced no samples at all, so every verdict built on it " +
				"would be an artefact of the timing rather than the target",
		)
	}
}

func TestSamplingHonoursTheRequestedDuration(t *testing.T) {
	engine := Engine{}

	started := time.Now()
	engine.sample(
		context.Background(),
		pairOf(0),
		150*time.Millisecond,
		10*time.Millisecond,
	)
	elapsed := time.Since(started)

	if elapsed < 150*time.Millisecond {
		t.Fatalf(
			"sampling returned after %v for a 150ms phase; the phase was cut short",
			elapsed,
		)
	}

	if elapsed > time.Second {
		t.Fatalf("sampling took %v for a 150ms phase", elapsed)
	}
}

func TestSamplingStopsPromptlyOnCancellation(t *testing.T) {
	engine := Engine{}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	started := time.Now()
	engine.sample(ctx, pairOf(0), 10*time.Second, 10*time.Millisecond)
	elapsed := time.Since(started)

	if elapsed > time.Second {
		t.Fatalf(
			"sampling ran for %v after cancellation; a cancelled run must stop measuring",
			elapsed,
		)
	}
}

func TestAnIntervalLongerThanThePhaseDoesNotOverrun(t *testing.T) {
	engine := Engine{}

	started := time.Now()
	engine.sample(
		context.Background(),
		pairOf(0),
		20*time.Millisecond,
		time.Second,
	)
	elapsed := time.Since(started)

	if elapsed > 500*time.Millisecond {
		t.Fatalf(
			"a 20ms phase with a 1s period took %v; the phase deadline must win",
			elapsed,
		)
	}
}
