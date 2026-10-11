// ©AngelaMos | 2026
// engine.go

package experiment

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

type Stage string

const (
	StageBaseline Stage = "baseline"
	StageInject   Stage = "inject"
	StageConfirm  Stage = "confirm"
	StageObserve  Stage = "observe"
	StageAct      Stage = "act"
	StageIdle     Stage = "idle"
	StageResume   Stage = "resume"
	StageRevert   Stage = "revert"
	StageRecover  Stage = "recover"
	StageVerdict  Stage = "verdict"
)

const (
	detailBaseline  = "establishing steady state"
	detailObserve   = "measuring under fault"
	detailRevert    = "removing the fault"
	detailRecover   = "confirming the target came back"
	detailInjecting = "%s on %s"
	detailConfirmed = "fault confirmed by %s"
	detailUnconfirm = "the fault was not confirmed, aborting before measuring"
	detailVerdict   = "%s / %s"
	detailActFailed = "the mid-run action failed, so nothing measured after it means anything: %v"
	detailIdle      = "a credential leaked; pausing traffic for %s to see whether the cache is being re-armed"
	detailResume    = "resuming traffic with the fault still applied"

	// Jitter breaks aliasing against periodic target behaviour: cache TTLs,
	// token refresh and crons are exactly what these experiments measure, and
	// a probe locked to a fixed period can sit in phase with them.
	jitterFraction = 0.2
)

type Event struct {
	Stage  Stage
	At     time.Time
	Detail string
}

type Reporter func(Event)

// Injector is whatever can apply, confirm and undo the fault. The engine never
// talks to Docker, so the whole lifecycle is testable without a daemon.
type Injector interface {
	Inject(ctx context.Context, kind, target string) error
	Confirm(ctx context.Context) (string, error)
	Revert(ctx context.Context) error
}

var ErrNoProbePair = errors.New("an experiment needs both a valid and an invalid probe; the invalid one is the negative control that makes the verdict mean anything")

type Engine struct {
	Injector Injector
	Report   Reporter
	Now      func() time.Time
}

func (e Engine) Run(ctx context.Context, spec Experiment) (Result, error) {
	if !spec.Probes.Complete() {
		return Result{}, ErrNoProbePair
	}

	timing := spec.Timing.withDefaults()
	result := Result{
		Experiment: spec.Name,
		Hypothesis: spec.Hypothesis.String(),
		StartedAt:  e.now(),
	}

	observation := Observation{
		ForgedBaseline: spec.Probes.ForgedBaseline,
		MintedByKhaos:  spec.IdP != nil,
		FaultFor:       timing.FaultFor,
		Defect:         spec.Defect,
		HeldCaveat:     spec.HeldCaveat,
	}

	e.emit(StageBaseline, detailBaseline)

	// Measured across the BASELINE, where the target is healthy and whatever it
	// normally does it is doing. A delta of zero there means the target never
	// used the dependency this experiment is about to break.
	consultedBefore := e.consulted(spec)

	observation.Baseline = e.sample(ctx, spec.Probes, timing.BaselineFor, timing.SampleInterval)

	observation.ConsultedWhat = spec.ConsultedWhat
	observation.Consulted = e.consulted(spec) - consultedBefore

	if ctx.Err() != nil {
		return e.conclude(result, markInterrupted(observation), spec.Polarity, nil)
	}

	if _, unmet := baselineUnmet(observation.Baseline, observation.ForgedBaseline, observation.MintedByKhaos); unmet {
		return e.conclude(result, observation, spec.Polarity, nil)
	}

	e.emit(StageInject, sprintf(detailInjecting, spec.Fault.Kind, spec.Fault.Target))

	if err := e.Injector.Inject(ctx, spec.Fault.Kind, spec.Fault.Target); err != nil {
		revertErr := e.Injector.Revert(context.WithoutCancel(ctx))
		observation.RollbackFailed = revertErr != nil
		result.Observation = observation
		result.Verdict = Verdict{Epistemic: Errored, Direction: Undetermined, Reasons: []string{err.Error()}}
		result.Duration = e.now().Sub(result.StartedAt)
		// Joined, not discarded. The caller maps the rollback failure to its own
		// exit code, and keeping only a boolean here meant the CLI returned this
		// error first and never reached the boolean.
		return result, errors.Join(err, revertErr)
	}

	method, confirmErr := e.Injector.Confirm(ctx)
	observation.FaultConfirmed = confirmErr == nil && method != ""
	observation.ConfirmMethod = method

	if !observation.FaultConfirmed {
		e.emit(StageConfirm, detailUnconfirm)
		revertErr := e.Injector.Revert(context.WithoutCancel(ctx))
		observation.RollbackFailed = revertErr != nil
		return e.conclude(result, observation, spec.Polarity, errors.Join(confirmErr, revertErr))
	}

	e.emit(StageConfirm, sprintf(detailConfirmed, method))

	// The mid-run action happens AFTER the fault is confirmed and before anything
	// is measured under it, and that ordering is forced rather than convenient.
	// Revoking a credential while the authority is still reachable makes the
	// target cache a DENY, which a correct stale-serving control then serves
	// correctly; the bug only exists when the cache holds an ALLOW at the moment
	// the authority goes away. So the revocation has to be real and unreachable,
	// which means it happens here or not at all.
	if spec.Act != nil {
		e.emit(StageAct, spec.ActDetail)

		if err := spec.Act(ctx); err != nil {
			e.emit(StageAct, sprintf(detailActFailed, err))
			observation.ActFailed = true
			revertErr := e.Injector.Revert(context.WithoutCancel(ctx))
			observation.RollbackFailed = revertErr != nil
			return e.conclude(result, observation, spec.Polarity, errors.Join(err, revertErr))
		}

		observation.Acted = true
	}

	e.emit(StageObserve, detailObserve)
	observation.Fault = e.sample(ctx, spec.Probes, timing.FaultFor, timing.SampleInterval)

	observation = e.discriminate(ctx, spec, observation, timing)

	e.emit(StageRevert, detailRevert)
	revertErr := e.Injector.Revert(context.WithoutCancel(ctx))
	observation.RollbackFailed = revertErr != nil

	e.emit(StageRecover, detailRecover)
	observation.Recovery = e.sample(context.WithoutCancel(ctx), spec.Probes, timing.RecoveryFor, timing.SampleInterval)

	if ctx.Err() != nil {
		observation = markInterrupted(observation)
	}

	return e.conclude(result, observation, spec.Polarity, revertErr)
}

// discriminate is the idleness phase: stop sending traffic for longer than any
// plausible cache lifetime, with the fault still applied, then resume and measure
// again.
//
// It runs ONLY when the fault window actually leaked. The two causes it separates
// are both causes of a PERMITTED credential, so on a target that held there is
// nothing to diagnose and the pause would spend a minute of the operator's run
// learning what khaos already knows. It also runs only when the experiment asks
// for it, because the pause is meaningless without a cache lifetime to outlast
// and khaos cannot invent one.
func (e Engine) discriminate(
	ctx context.Context,
	spec Experiment,
	observation Observation,
	timing Timing,
) Observation {
	if spec.IdleFor <= 0 || ctx.Err() != nil {
		return observation
	}

	if !Leaking(observation) {
		return observation
	}

	e.emit(StageIdle, sprintf(detailIdle, spec.IdleFor))

	timer := time.NewTimer(spec.IdleFor)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return observation
	case <-timer.C:
	}

	e.emit(StageResume, detailResume)

	observation.IdleFor = spec.IdleFor
	observation.Resumed = e.sample(ctx, spec.Probes, timing.FaultFor, timing.SampleInterval)

	return observation
}

func (e Engine) conclude(result Result, observation Observation, polarity Polarity, err error) (Result, error) {
	result.Observation = observation
	result.Verdict = Judge(observation, polarity)
	result.Duration = e.now().Sub(result.StartedAt)

	e.emit(StageVerdict, sprintf(detailVerdict, result.Verdict.Epistemic, result.Verdict.Direction))

	return result, err
}

// consulted reads the experiment's endpoint counter, or zero when it declares
// none.
func (e Engine) consulted(spec Experiment) int64 {
	if spec.Consulted == nil {
		return 0
	}
	return spec.Consulted()
}

func markInterrupted(observation Observation) Observation {
	observation.Interrupted = true
	return observation
}

// sample fires both probes on a true period: the time the probes themselves
// take is subtracted from the wait, so a slow target reduces latency headroom
// rather than silently collapsing the sample count below the floor a verdict
// needs.
func (e Engine) sample(ctx context.Context, pair probe.Pair, duration, interval time.Duration) probe.Window {
	window := probe.Window{}
	deadline := e.now().Add(duration)

	for {
		started := e.now()

		for _, p := range pair.All() {
			window.Record(p.Run(ctx))
		}

		if !e.now().Before(deadline) || ctx.Err() != nil {
			return window
		}

		wait := interval - e.now().Sub(started) + jitter(interval)
		if remaining := deadline.Sub(e.now()); wait > remaining {
			wait = remaining
		}
		if wait <= 0 {
			continue
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return window
		case <-timer.C:
		}
	}
}

func jitter(interval time.Duration) time.Duration {
	span := float64(interval) * jitterFraction
	if span <= 0 {
		return 0
	}
	return time.Duration(rand.Float64() * span)
}

func (e Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}

func (e Engine) emit(stage Stage, detail string) {
	if e.Report == nil {
		return
	}
	e.Report(Event{Stage: stage, At: e.now(), Detail: detail})
}
