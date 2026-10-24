// ©AngelaMos | 2026
// health.go

package experiment

import (
	"context"
	"fmt"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

type healthStop struct {
	limit  int
	streak int
	reason string
}

func (h *healthStop) reached(unhealthy bool) bool {
	if h.limit <= 0 {
		return false
	}
	if !unhealthy {
		h.streak = 0
		return false
	}
	h.streak++
	if h.streak < h.limit {
		return false
	}
	h.reason = fmt.Sprintf(
		"stopped after %d consecutive samples where the valid probe was not accepted or the invalid probe was accepted",
		h.streak,
	)
	return true
}

func (e Engine) sampleFault(
	ctx context.Context,
	spec Experiment,
	timing Timing,
	observation *Observation,
) (probe.Window, time.Duration) {
	stop := &healthStop{limit: spec.AbortAfter}
	started := e.now()
	window := e.sample(
		ctx, spec.Probes, timing.FaultFor, timing.SampleInterval, stop,
	)
	elapsed := e.now().Sub(started)
	if stop.reason != "" {
		observation.HaltReason = stop.reason
		e.emit(StageObserve, stop.reason)
	}
	return window, elapsed
}
