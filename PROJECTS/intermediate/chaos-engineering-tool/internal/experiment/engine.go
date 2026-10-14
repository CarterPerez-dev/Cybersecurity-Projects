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

var ErrNoProbePair = errors.New(
	"an experiment needs both a valid and an invalid probe; the invalid one is the negative control that makes the verdict mean anything",
)

type Engine struct {
	Injector Injector
	Report   Reporter
	Now      func() time.Time
}

// abandon reverts the fault and then concludes, which is what every failure
// AFTER a successful injection has to do. It is one function rather than one
// block per branch because there is more than one such branch, and a branch
// that returned a verdict without reverting would leave khaos's own fault
// applied while reporting a result -- the single outcome this tool must never
// produce. The cause is joined with the rollback error rather than replaced by
// it, because the caller maps a rollback failure to its own exit code.
func (e Engine) abandon(
	ctx context.Context,
	spec Experiment,
	result Result,
	observation Observation,
	cause error,
) (Result, error) {
	revertErr := e.Injector.Revert(context.WithoutCancel(ctx))
	observation.RollbackFailed = revertErr != nil

	return e.conclude(
		result,
		observation,
		spec.Polarity,
		errors.Join(cause, revertErr),
	)
}

// measureBaseline samples the healthy target and records how many times it
// consulted the dependency across that window. The delta is measured HERE, in
// the one window where the target is healthy and doing whatever it normally
// does, because a delta of zero means the target never used the dependency this
// experiment is about to break -- and an experiment against a dependency the
// target ignores can only ever report HELD for the wrong reason.
//
// Measurement only. The two decisions that follow a baseline, whether the
// operator interrupted it and whether it was ever a steady state, stay in Run
// where they are visible beside the phases they skip.
func (e Engine) measureBaseline(
	ctx context.Context,
	spec Experiment,
	timing Timing,
	observation Observation,
) Observation {
	e.emit(StageBaseline, detailBaseline)

	before, beforeErr := e.consulted(spec)

	observation.Baseline = e.sample(
		ctx,
		spec.Probes,
		timing.BaselineFor,
		timing.SampleInterval,
	)

	after, afterErr := e.consulted(spec)

	observation.ConsultedWhat = spec.ConsultedWhat
	observation.Unsupportable = spec.Unsupportable
	observation.CacheRequired = spec.CacheRequired
	observation.Consulted = after - before

	// EITHER end failing voids the count, and a negative delta is impossible
	// from a monotonic counter so it can only mean khaos misread one end. Both
	// are recorded rather than silently absorbed, because the guards downstream
	// read zero as a statement about the TARGET.
	if beforeErr != nil || afterErr != nil || observation.Consulted < 0 {
		observation.CounterUnreadable = errors.Join(beforeErr, afterErr)
		observation.Consulted = 0
	}

	return observation
}

// injectionFailed is a conclusion of its own rather than a call to conclude,
// because a fault that never landed leaves nothing to judge: there is no
// behaviour under fault to have a direction, only an error to report. The
// rollback is still attempted, since a failed Inject can still have changed
// something before it failed.
func (e Engine) injectionFailed(
	ctx context.Context,
	result Result,
	observation Observation,
	cause error,
) (Result, error) {
	revertErr := e.Injector.Revert(context.WithoutCancel(ctx))
	observation.RollbackFailed = revertErr != nil

	result.Observation = observation
	result.Verdict = Verdict{
		Epistemic: Errored,
		Direction: Undetermined,
		Reasons:   []string{cause.Error()},
	}
	result.Duration = e.now().Sub(result.StartedAt)

	// Joined, not discarded. The caller maps the rollback failure to its own
	// exit code, and keeping only a boolean here meant the CLI returned this
	// error first and never reached the boolean.
	return result, errors.Join(cause, revertErr)
}

// act performs the mid-run action, which happens AFTER the fault is confirmed
// and BEFORE anything is measured under it. That ordering is forced rather than
// convenient: revoking a credential while the authority is still reachable
// makes the target cache a DENY, which a correct stale-serving implementation
// then serves correctly. The bug only exists when the cache holds an ALLOW at
// the moment the authority goes away, so the revocation has to be real and the
// authority has to already be unreachable. It happens here or not at all.
//
// An experiment with no action returns unchanged, so the caller does not need
// to know which kind it is holding.
func (e Engine) act(
	ctx context.Context,
	spec Experiment,
	observation Observation,
) (Observation, error) {
	if spec.Act == nil {
		return observation, nil
	}

	e.emit(StageAct, spec.ActDetail)

	if err := spec.Act(ctx); err != nil {
		e.emit(StageAct, sprintf(detailActFailed, err))
		observation.ActFailed = true

		return observation, err
	}

	observation.Acted = true

	return observation, nil
}

// restore reverts the fault and then measures what the target does once it is
// gone, which together are khaos's Recovery axis: a target that never comes
// back is a different finding from one that held throughout, and only the
// second window can tell them apart.
//
// Both halves run on a context that cannot be cancelled. An operator's Ctrl-C
// must not be able to skip the rollback, and it must not be able to skip the
// evidence that the rollback worked either.
func (e Engine) restore(
	ctx context.Context,
	spec Experiment,
	timing Timing,
	observation Observation,
) (Observation, error) {
	e.emit(StageRevert, detailRevert)

	revertErr := e.Injector.Revert(context.WithoutCancel(ctx))
	observation.RollbackFailed = revertErr != nil

	e.emit(StageRecover, detailRecover)

	observation.Recovery = e.sample(
		context.WithoutCancel(ctx),
		spec.Probes,
		timing.RecoveryFor,
		timing.SampleInterval,
	)

	return observation, revertErr
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

	observation = e.measureBaseline(ctx, spec, timing, observation)

	if ctx.Err() != nil {
		return e.conclude(
			result,
			markInterrupted(observation),
			spec.Polarity,
			nil,
		)
	}

	if _, unmet := baselineUnmet(
		observation.Baseline,
		observation.ForgedBaseline,
		observation.MintedByKhaos,
	); unmet {
		return e.conclude(result, observation, spec.Polarity, nil)
	}

	e.emit(
		StageInject,
		sprintf(detailInjecting, spec.Fault.Kind, spec.Fault.Target),
	)

	if err := e.Injector.Inject(
		ctx,
		spec.Fault.Kind,
		spec.Fault.Target,
	); err != nil {
		return e.injectionFailed(ctx, result, observation, err)
	}

	method, confirmErr := e.Injector.Confirm(ctx)
	observation.FaultConfirmed = confirmErr == nil && method != ""
	observation.ConfirmMethod = method

	if !observation.FaultConfirmed {
		e.emit(StageConfirm, detailUnconfirm)
		return e.abandon(ctx, spec, result, observation, confirmErr)
	}

	e.emit(StageConfirm, sprintf(detailConfirmed, method))

	observation, actErr := e.act(ctx, spec, observation)
	if actErr != nil {
		return e.abandon(ctx, spec, result, observation, actErr)
	}

	observation = e.measureFault(ctx, spec, timing, observation)

	observation = e.discriminate(ctx, spec, observation, timing)

	observation, revertErr := e.restore(ctx, spec, timing, observation)

	if ctx.Err() != nil {
		observation = markInterrupted(observation)
	}

	return e.conclude(result, observation, spec.Polarity, revertErr)
}

// measureFault samples under the fault and records whether the target ever MET
// it, which is a different question from whether khaos armed it.
//
// The baseline's count asks whether the target uses the thing khaos faulted at
// all; this asks whether it went back to it WHILE the fault was armed. A DNS
// fault is the case that forced the distinction: it can be armed, confirmed at
// khaos's own resolver, and reach nothing, because Go's HTTP transport resolves
// a name once per kept-alive connection. Measured on the range's own gateway at
// two lookups across forty-six requests. Every other tier collapses the two
// questions safely, because a severed path or a broken certificate sits on a
// route the target cannot avoid using.
func (e Engine) measureFault(
	ctx context.Context,
	spec Experiment,
	timing Timing,
	observation Observation,
) Observation {
	e.emit(StageObserve, detailObserve)

	before, beforeErr := e.consulted(spec)

	observation.Fault = e.sample(
		ctx,
		spec.Probes,
		timing.FaultFor,
		timing.SampleInterval,
	)

	after, afterErr := e.consulted(spec)

	observation.Delivered = after - before
	observation.DeliveredWhat = spec.DeliveredWhat

	if beforeErr != nil || afterErr != nil || observation.Delivered < 0 {
		observation.CounterUnreadable = errors.Join(
			observation.CounterUnreadable,
			beforeErr,
			afterErr,
		)
		observation.Delivered = 0
	}

	return observation
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
	observation.Resumed = e.sample(
		ctx,
		spec.Probes,
		timing.FaultFor,
		timing.SampleInterval,
	)

	return observation
}

func (e Engine) conclude(
	result Result,
	observation Observation,
	polarity Polarity,
	err error,
) (Result, error) {
	result.Observation = observation
	result.Verdict = Judge(observation, polarity)
	result.Duration = e.now().Sub(result.StartedAt)

	e.emit(
		StageVerdict,
		sprintf(
			detailVerdict,
			result.Verdict.Epistemic,
			result.Verdict.Direction,
		),
	)

	return result, err
}

// consulted reads the experiment's endpoint counter, or zero when it declares
// none.
// consulted reads the experiment's counter, and a FAILURE to read is reported
// rather than folded into zero.
//
// Zero is the sentinel three separate guards branch on, so a swallowed error
// becomes "the target never did it" and khaos blames the target for khaos's own
// unreachable instrument. An experiment with no counter is a different thing
// again and returns zero with no error, because it declared no question.
func (e Engine) consulted(spec Experiment) (int64, error) {
	if spec.Consulted == nil {
		return 0, nil
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
func (e Engine) sample(
	ctx context.Context,
	pair probe.Pair,
	duration, interval time.Duration,
) probe.Window {
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
	// Spread between probes, so a periodic sampler does not beat in lockstep
	// with whatever the target does periodically. Statistical, not secret.
	//nolint:gosec // probe spread, not a secret
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
