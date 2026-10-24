// ©AngelaMos | 2026
// engine.go

package experiment

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

type Stage string

const (
	StageBaseline  Stage = "baseline"
	StageInject    Stage = "inject"
	StageConfirm   Stage = "confirm"
	StageObserve   Stage = "observe"
	StageAct       Stage = "act"
	StageShift     Stage = "shift"
	StageColdStart Stage = "cold-start"
	StageIdle      Stage = "idle"
	StageResume    Stage = "resume"
	StageRevert    Stage = "revert"
	StageRecover   Stage = "recover"
	StageVerdict   Stage = "verdict"
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
	detailColdStart   = "restarting the target so it initialises with the dependency already unreachable"

	// How long the target gets to answer again after the restart. The
	// settling samples are discarded: counting them would report khaos's own
	// restart as the target having stopped answering.
	settleFor = 30 * time.Second

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

	// Restart restarts the container the fault was applied to, for the one
	// experiment whose fault is the target initialising without a dependency.
	Restart(ctx context.Context) error
}

var ErrNeverCameBack = errors.New(
	"khaos restarted the target and it never answered again, so there is no window to measure; the fault is still applied and was reverted",
)

var ErrNoProbePair = errors.New(
	"an experiment needs both a valid and an invalid probe; the invalid one is the negative control that makes the verdict mean anything",
)

type Engine struct {
	Injector Injector
	Report   Reporter
	Now      func() time.Time

	// SettleFor bounds how long a cold-started target gets to answer again.
	// Injectable for the same reason Now is: the default is longer than a
	// test can wait for.
	SettleFor       time.Duration
	RollbackTimeout time.Duration
}

func (e Engine) rollback(ctx context.Context) error {
	timeout := e.RollbackTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	return e.Injector.Revert(cleanup)
}

func (e Engine) recoverFault(ctx context.Context) {
	if failure := recover(); failure != nil {
		err := e.rollback(ctx)
		if err != nil {
			panic(fmt.Errorf("%v; emergency rollback failed: %w", failure, err))
		}
		panic(failure)
	}
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
	revertErr := e.rollback(ctx)
	observation.RollbackFailed = revertErr != nil
	if ctx.Err() != nil {
		observation = markInterrupted(observation)
	}

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
	revertErr := e.rollback(ctx)
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

	revertErr := e.rollback(ctx)
	observation.RollbackFailed = revertErr != nil

	e.emit(StageRecover, detailRecover)

	recovery, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), timing.RecoveryFor+30*time.Second,
	)
	defer cancel()
	observation.Recovery = e.sample(
		recovery,
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
	result := e.begin(spec)

	observation := Observation{
		ForgedBaseline: spec.Probes.ForgedBaseline,
		MintedByKhaos:  spec.IdP != nil,
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
		closedWhen(observation),
	); unmet {
		return e.conclude(result, observation, spec.Polarity, nil)
	}

	e.emit(
		StageInject,
		sprintf(detailInjecting, spec.Fault.Kind, spec.Fault.Target),
	)
	defer e.recoverFault(ctx)

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

	if coldErr := e.coldStart(ctx, spec, timing); coldErr != nil {
		return e.abandon(ctx, spec, result, observation, coldErr)
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

func (e Engine) begin(spec Experiment) Result {
	return Result{
		Experiment: spec.Name, Family: spec.Family,
		Hypothesis: spec.Hypothesis.String(), Fault: spec.Fault,
		StartedAt: e.now(), Configuration: spec.Configuration,
	}
}

// coldStart restarts the target with the fault already applied, so it
// initialises without a dependency it held a moment ago. The baseline is
// already measured by this point, which is the whole ordering: a target
// booted broken refuses nothing and voids its own run.
//
// It then waits for the target to ANSWER rather than for the daemon to call
// it running, and the settling samples are discarded: counting them would
// report khaos's own restart as the target having stopped answering.
func (e Engine) coldStart(
	ctx context.Context,
	spec Experiment,
	timing Timing,
) error {
	if !spec.ColdStart {
		return nil
	}

	e.emit(StageColdStart, detailColdStart)

	if err := e.Injector.Restart(ctx); err != nil {
		return err
	}

	if e.settled(ctx, spec, timing) {
		return nil
	}

	return ErrNeverCameBack
}

// settled polls the valid stream until the target answers at all. A refusal
// counts: a correct target that cannot evaluate its policy refuses every
// request, and that is an answer.
func (e Engine) settled(
	ctx context.Context,
	spec Experiment,
	timing Timing,
) bool {
	deadline := e.now().Add(e.settleBudget())

	for e.now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}

		if spec.Probes.Valid.Run(ctx).Disposition.Answered() {
			return true
		}

		timer := time.NewTimer(timing.SampleInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}

	return false
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

	observation.Fault, observation.FaultFor = e.sampleFault(
		ctx, spec, timing, &observation,
	)

	after, afterErr := e.consulted(spec)
	refusedAfter, refusedAfterErr := e.refusals(spec)
	if spec.Delivered != nil {
		before, beforeErr = 0, nil
		after, afterErr = spec.Delivered()
	}

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

func (e Engine) shift(
	ctx context.Context,
	spec Experiment,
	timing Timing,
	observation Observation,
) Observation {
	if spec.Shift == nil || ctx.Err() != nil || observation.HaltReason != "" {
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

	observation.Shift, _ = e.sampleFault(ctx, spec, timing, &observation)

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
	if spec.IdleFor <= 0 || ctx.Err() != nil || observation.HaltReason != "" {
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
	observation.Resumed, _ = e.sampleFault(ctx, spec, timing, &observation)

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
	if observation.HaltReason != "" {
		result.Verdict.Reasons = append(
			result.Verdict.Reasons, observation.HaltReason,
		)
	}
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
	stops ...*healthStop,
) probe.Window {
	window := probe.Window{}
	deadline := e.now().Add(duration)
	stop := &healthStop{}
	if len(stops) > 0 {
		stop = stops[0]
	}

	for {
		started := e.now()
		unhealthy := false

		for _, p := range pair.All() {
			outcome := p.Run(ctx)
			window.Record(outcome)
			if (outcome.Credential == probe.Valid && outcome.Disposition != probe.Accepted) ||
				(outcome.Credential == probe.Invalid && outcome.Disposition == probe.Accepted) {
				unhealthy = true
			}
		}

		if stop.reached(unhealthy) || !e.now().Before(deadline) ||
			ctx.Err() != nil {
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

func (e Engine) settleBudget() time.Duration {
	if e.SettleFor > 0 {
		return e.SettleFor
	}
	return settleFor
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
