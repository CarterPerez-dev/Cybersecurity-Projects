// ©AngelaMos | 2026
// injector.go

package run

import (
	"context"
	"errors"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
)

var ErrNothingApplied = errors.New(
	"khaos was asked to restart the target before any fault had been applied, so there is no container it can be sure was meant",
)

type Resolver interface {
	Accept(
		ctx context.Context,
		name string,
		filter dockerx.Filter,
		guard dockerx.Guard,
	) (dockerx.Target, error)
}

// Injector adapts a Session to the experiment engine, so the engine never
// touches Docker, a journal or a lease.
type Injector struct {
	Session  *Session
	Resolver Resolver
	Filter   dockerx.Filter
	Guard    dockerx.Guard
	Progress Progress

	applied []appliedFault
}

type appliedFault struct {
	kind   string
	target dockerx.Target
}

func (i *Injector) Inject(ctx context.Context, kind, target string) error {
	guard := i.Guard

	planned, err := i.Resolver.Accept(ctx, target, i.Filter, guard)
	if err != nil {
		return err
	}

	guard.ExpectedID = planned.ID

	confirmed, err := i.Resolver.Accept(ctx, target, i.Filter, guard)
	if err != nil {
		return err
	}

	if err := i.Session.Inject(ctx, kind, confirmed); err != nil {
		return err
	}

	i.applied = append(i.applied, appliedFault{kind: kind, target: confirmed})

	return nil
}

// Confirm reads the fault back from the daemon, because an injection the API
// accepted is not the same as a fault that took effect, and a run measuring no
// fault at all reads as a pass.
func (i *Injector) Confirm(ctx context.Context) (string, error) {
	first := ""

	for _, fault := range i.applied {
		method, err := i.Session.Confirm(ctx, fault.kind, fault.target)
		if err != nil {
			return "", err
		}
		if method == "" {
			return "", nil
		}
		if first == "" {
			first = method
		}
	}

	return first, nil
}

func (i *Injector) Revert(ctx context.Context) error {
	return i.Session.RevertFaults(ctx, i.Progress)
}

// Restart restarts the container this run's fault was applied to, which is the
// container the engine resolved and consent-checked before injecting. A
// restart asked for before anything was injected is a refusal rather than a
// guess at which container was meant.
func (i *Injector) Restart(ctx context.Context) error {
	if len(i.applied) == 0 {
		return ErrNothingApplied
	}

	return i.Session.Restart(ctx, i.applied[0].target)
}
