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
	StageShift    Stage = "shift"
	StageIdle     Stage = "idle"
	StageResume   Stage = "resume"
	StageRevert   Stage = "revert"
	StageRecover  Stage = "recover"
	StageVerdict  Stage = "verdict"
)

const (
	detailBaseline    = "establishing steady state"
	detailObserve     = "measuring under fault"
	detailRevert      = "removing the fault"
	detailRecover     = "confirming the target came back"
	detailInjecting   = "%s on %s"
	detailConfirmed   = "fault confirmed by %s"
	detailUnconfirm   = "the fault was not confirmed, aborting before measuring"
	detailVerdict     = "%s / %s"
	detailActFailed   = "the mid-run action failed, so nothing measured after it means anything: %v"
	detailShift       = "%s, and measuring again"
	detailShiftFailed = "the second phase could not be established, so khaos has one window where it needs two: %v"
	detailIdle        = "a credential leaked; pausing traffic for %s to see whether the cache is being re-armed"
	detailResume      = "resuming traffic with the fault still applied"

	// Breaks aliasing against the periodic target behaviour these experiments
	// measure: cache TTLs, token refresh and crons.
	jitterFraction = 0.2
)

type Event struct {
	Stage  Stage
	At     time.Time
	Detail string
}

type Reporter func(Event)

// Injector keeps the engine away from Docker, so the lifecycle is testable
// without a daemon.
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

// abandon reverts the fault and then concludes. The cause is joined with the
// rollback error, not replaced by it: the caller maps a rollback failure to its
// own exit code.
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

// measureBaseline counts the dependency consultations while the target is still
// healthy: zero means it never used the dependency khaos is about to break.
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

	// Recorded rather than absorbed: the guards downstream read zero as a
	// statement about the TARGET.
	if beforeErr != nil || afterErr != nil || observation.Consulted < 0 {
		observation.CounterUnreadable = errors.Join(beforeErr, afterErr)
		observation.Consulted = 0
	}

	return observation
}

// injectionFailed concludes without judging, because a fault that never landed
// leaves no behaviour to have a direction.
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

	return result, errors.Join(cause, revertErr)
}

// act runs after the fault is confirmed because the ordering is forced: the bug
// only exists when the cache holds an ALLOW as the authority goes away.
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

// restore runs uncancellable: an operator's Ctrl-C must not skip the rollback,
// nor the evidence that it worked.
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
		ClosedWhen:     spec.ClosedWhen,
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

	observation = e.shift(ctx, spec, timing, observation)

	observation = e.discriminate(ctx, spec, observation, timing)

	observation, revertErr := e.restore(ctx, spec, timing, observation)

	if ctx.Err() != nil {
		observation = markInterrupted(observation)
	}

	return e.conclude(result, observation, spec.Polarity, revertErr)
}

// measureFault records whether the target ever MET the fault, not just whether
// khaos armed it: Go's HTTP transport resolves a name once per kept-alive
// connection, so a DNS fault can be armed, confirmed, and reach nothing.
func (e Engine) measureFault(
	ctx context.Context,
	spec Experiment,
	timing Timing,
	observation Observation,
) Observation {
	e.emit(StageObserve, detailObserve)

	before, beforeErr := e.consulted(spec)
	refusedBefore, refusedBeforeErr := e.refusals(spec)

	observation.Fault = e.sample(
		ctx,
		spec.Probes,
		timing.FaultFor,
		timing.SampleInterval,
	)

	after, afterErr := e.consulted(spec)
	refusedAfter, refusedAfterErr := e.refusals(spec)

	observation.Delivered = after - before
	observation.DeliveredWhat = spec.DeliveredWhat
	observation.DeliveredHint = spec.DeliveredHint
	observation.RotatedWhat = spec.RotatedWhat
	observation.Refusals = refusedAfter - refusedBefore

	// NOT folded into CounterUnreadable, which voids the run: this count feeds
	// one optional finding rather than a guard, and zero makes no claim.
	if refusedBeforeErr != nil ||
		refusedAfterErr != nil ||
		observation.Refusals < 0 {
		observation.Refusals = 0
	}

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

// shift is the SECOND fault phase. One experiment needs it and research 07
// section 6.2 is why: an authorization dependency's deny and its silence are
// different answers, a correct caller treats them differently, and a caller
// that behaves IDENTICALLY has collapsed three outcomes into two branches.
// One window cannot show that; two can.
//
// A failed shift is recorded rather than fatal. The first window is already
// measured and its finding stands on its own; what is lost is the discriminator,
// and the verdict says so instead of pretending it ran.
func (e Engine) shift(
	ctx context.Context,
	spec Experiment,
	timing Timing,
	observation Observation,
) Observation {
	if spec.Shift == nil || ctx.Err() != nil {
		return observation
	}

	observation.ShiftWhat = spec.ShiftWhat

	e.emit(StageShift, sprintf(detailShift, spec.ShiftDetail))

	if err := spec.Shift(ctx); err != nil {
		e.emit(StageShift, sprintf(detailShiftFailed, err))
		observation.ShiftFailed = true

		return observation
	}

	before, beforeErr := e.consulted(spec)

	observation.Shift = e.sample(
		ctx,
		spec.Probes,
		timing.FaultFor,
		timing.SampleInterval,
	)

	after, afterErr := e.consulted(spec)

	observation.Shifted = true
	observation.ShiftAsked = after - before

	if beforeErr != nil || afterErr != nil || observation.ShiftAsked < 0 {
		observation.CounterUnreadable = errors.Join(
			observation.CounterUnreadable,
			beforeErr,
			afterErr,
		)
		observation.ShiftAsked = 0
	}

	return observation
}

// discriminate pauses traffic past any plausible cache lifetime with the fault
// still applied, then resumes, and only when the fault window actually leaked.
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

// consulted reports a FAILURE to read rather than folding it into zero, which is
// the sentinel three separate guards read as a statement about the target.
func (e Engine) consulted(spec Experiment) (int64, error) {
	if spec.Consulted == nil {
		return 0, nil
	}
	return spec.Consulted()
}

// refusals counts the DEFINITIVE denials the faulted dependency issued, which
// is the same thing as how many times the target asked about a credential it
// had already been refused for: nothing else is answered that way.
func (e Engine) refusals(spec Experiment) (int64, error) {
	if spec.Refusals == nil {
		return 0, nil
	}
	return spec.Refusals()
}

func markInterrupted(observation Observation) Observation {
	observation.Interrupted = true
	return observation
}

// sample fires both probes on a true period: probe time comes out of the wait,
// so a slow target cannot collapse the sample count below a verdict's floor.
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
