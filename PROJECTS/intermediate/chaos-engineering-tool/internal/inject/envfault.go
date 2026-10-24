// ©AngelaMos | 2026
// envfault.go

package inject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

type EnvKind string

const (
	// EnvUnset takes the variable away. Deliverable only where the IMAGE does
	// not also define it, because the daemon merges the image's environment
	// into any key a create request omits.
	EnvUnset EnvKind = "unset"

	// EnvEmpty shadows it with `NAME=`, which is the more interesting of the
	// two: os.Getenv cannot tell it from unset and os.LookupEnv can, so a
	// required-field check written with the wrong one does not fire.
	EnvEmpty EnvKind = "empty"

	KindEnvPrefix    = "env-"
	ReplacementLabel = "khaos.replacement"

	errNoEnvPlan = "%w: %s needs to be told which variable to take away"

	errUnknownEnvKind = "%w: %q (known environment faults: %s)"

	describeEnvUnset = "replace %s with a container that does not carry %s at all, keeping the original aside so the revert is a rename rather than a rebuild"

	describeEnvEmpty = "replace %s with a container whose %s is present and EMPTY, which os.Getenv cannot tell from absent"

	confirmEnvUnset = "the replacement's own environment no longer carries %s, and the original is held as %s"

	errNoVariableThere = "%w: %s does not carry %s in its environment, so there is nothing for khaos to take away. It carries: %s"

	errImageWouldRestore = "%w: %s is defined by the IMAGE %s as well as by the container, so a replacement created without it gets the image's value back and khaos would report a fault the daemon had undone. Use the empty-value fault, which shadows it instead, or target a service that does not bake it in"

	confirmEnvEmpty = "the replacement's own environment carries %s as an empty value, read from the LAST occurrence the way the process reads it"
)

var ErrNoEnvPlan = errors.New(
	"this mutation has no environment variable to act on",
)

var ErrUnknownEnvKind = errors.New(
	"no environment fault is registered under that name",
)

func EnvKinds() []string {
	return []string{string(EnvEmpty), string(EnvUnset)}
}

func EnvFaultKind(kind EnvKind) string {
	return KindEnvPrefix + string(kind)
}

// EnvPlan is what the revert needs, and it carries no value: the original is
// held inside the replacement's own environment under a name the target does
// not read, so the journal records names only.
type EnvPlan struct {
	Kind     EnvKind `json:"kind"`
	Variable string  `json:"variable"`

	// Held is the name the ORIGINAL container was renamed to. The revert
	// removes the replacement and renames this back, which is why neither the
	// anonymous volume, the logs nor the original id are lost.
	Held string `json:"held"`

	// OriginalID is the container khaos resolved in the plan, and ReplacedID
	// is what it created. Invariant 8 re-verifies by immutable id, and this
	// fault class mints a new one, so the handover is recorded rather than
	// left for the rollback to guess.
	OriginalID string `json:"original_id"`
	ReplacedID string `json:"replaced_id,omitempty"`
	Owner      string `json:"owner,omitempty"`
}

// envMutator is the only tier that REPLACES the target. Everything else mutates
// a dependency, a file or a credential; a container's environment is fixed at
// creation and `ContainerUpdate` accepts an Env field, returns HTTP 200 with no
// warning, and changes nothing.
type envMutator struct {
	kind EnvKind
}

func init() {
	for _, name := range EnvKinds() {
		kind := EnvKind(name)
		registry[EnvFaultKind(kind)] = envMutator{kind: kind}
	}
}

func (m envMutator) Describe(env Env, target dockerx.Target) string {
	variable := ""
	if env.EnvPlan != nil {
		variable = env.EnvPlan.Variable
	}
	if variable == "" {
		variable = string(m.kind)
	}

	if m.kind == EnvEmpty {
		return fmt.Sprintf(describeEnvEmpty, target.Name, variable)
	}

	return fmt.Sprintf(describeEnvUnset, target.Name, variable)
}

// Plan refuses both ways this fault can be a no-op: a variable the target does
// not carry, and one the IMAGE defines as well, where a replacement created
// without it gets the image's value back.
func (m envMutator) Plan(
	ctx context.Context,
	env Env,
	target dockerx.Target,
) (json.RawMessage, error) {
	if env.EnvPlan == nil || env.EnvPlan.Variable == "" {
		return nil, fmt.Errorf(
			errNoEnvPlan,
			ErrNoEnvPlan,
			EnvFaultKind(m.kind),
		)
	}

	plan := env.EnvPlan

	if plan.Kind != m.kind {
		return nil, fmt.Errorf(
			errWrongTrapKind,
			ErrTrapMismatch,
			plan.Kind,
			m.kind,
		)
	}

	spec, err := env.Docker.Capture(ctx, target.ID)
	if err != nil {
		return nil, err
	}

	if _, carried := dockerx.EnvValue(
		spec.Config.Env,
		plan.Variable,
	); !carried {
		return nil, fmt.Errorf(
			errNoVariableThere,
			dockerx.ErrVariableAbsent,
			target.Name,
			plan.Variable,
			strings.Join(dockerx.Variables(spec.Config.Env), ", "),
		)
	}

	if m.kind == EnvUnset {
		imageEnv, err := env.Docker.ImageEnv(ctx, spec.Config.Image)
		if err != nil {
			return nil, err
		}

		if dockerx.ImageDefines(imageEnv, plan.Variable) {
			return nil, fmt.Errorf(
				errImageWouldRestore,
				dockerx.ErrImageDefinesVariable,
				plan.Variable,
				spec.Config.Image,
			)
		}
	}

	plan.Held = dockerx.HeldName(spec.Name)
	plan.OriginalID = target.ID
	plan.Owner = journal.NewID()

	return journal.EncodePayload(*plan)
}

// Apply renames the original aside and creates the replacement under its name,
// in that order, so nothing is destroyed: a failed create leaves the original
// present and the revert renames it back.
func (m envMutator) Apply(
	ctx context.Context,
	env Env,
	target dockerx.Target,
	raw json.RawMessage,
) error {
	var plan EnvPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return err
	}

	spec, err := env.Docker.Capture(ctx, target.ID)
	if err != nil {
		return err
	}

	environ := m.replacement(spec.Config.Env, plan.Variable)
	spec.Config.Labels = maps.Clone(spec.Config.Labels)
	if spec.Config.Labels == nil {
		spec.Config.Labels = map[string]string{}
	}
	spec.Config.Labels[ReplacementLabel] = plan.Owner

	// Stopped before the rename, because two containers cannot both hold the
	// network's static address and the service's aliases.
	if err := env.Docker.Stop(ctx, target.ID); err != nil {
		return err
	}

	if err := env.Docker.Rename(ctx, target.ID, plan.Held); err != nil {
		return err
	}

	replaced, err := env.Docker.Recreate(ctx, spec, environ)
	if err != nil {
		// The original is still there under its held name, so the revert can
		// put it back whatever happened here.
		return err
	}

	if env.EnvPlan != nil {
		env.EnvPlan.Held = plan.Held
		env.EnvPlan.OriginalID = plan.OriginalID
		env.EnvPlan.ReplacedID = replaced
	}

	return nil
}

// replacement is the one line that differs between the two faults.
func (m envMutator) replacement(environ []string, variable string) []string {
	if m.kind == EnvEmpty {
		return dockerx.ShadowedEmpty(environ, variable)
	}

	value, _ := dockerx.EnvValue(environ, variable)

	// The original value stays INSIDE the container, under a name the target
	// does not read, so khaos can restore it from a cold start without ever
	// writing it to disk.
	held := dockerx.HeldFor(variable) + "=" + value

	return append(
		dockerx.WithoutVariable(environ, variable),
		held,
	)
}

// Confirm reads the REPLACEMENT's own environment back from the daemon, which
// is the only authority on what the process was started with.
func (m envMutator) Confirm(
	ctx context.Context,
	env Env,
	target dockerx.Target,
) (string, bool, error) {
	if env.EnvPlan == nil {
		return "", false, fmt.Errorf(
			errNoEnvPlan,
			ErrNoEnvPlan,
			EnvFaultKind(m.kind),
		)
	}

	plan := env.EnvPlan

	environ, err := env.Docker.ContainerEnv(ctx, m.subject(plan, target))
	if err != nil {
		return "", false, err
	}

	value, carried := environ[plan.Variable]

	if m.kind == EnvEmpty {
		if !carried || value != "" {
			return "", false, nil
		}

		return fmt.Sprintf(confirmEnvEmpty, plan.Variable), true, nil
	}

	if carried {
		return "", false, nil
	}

	if _, held := environ[dockerx.HeldFor(plan.Variable)]; !held {
		return "", false, nil
	}

	return fmt.Sprintf(
		confirmEnvUnset,
		plan.Variable,
		dockerx.HeldFor(plan.Variable),
	), true, nil
}

// subject is the replacement when there is one, which is the identity handover
// invariant 8 needs: the id khaos resolved in the plan is not the id it is
// measuring by the time this runs.
func (m envMutator) subject(plan *EnvPlan, target dockerx.Target) string {
	if plan.ReplacedID != "" {
		return plan.ReplacedID
	}

	return target.ID
}

// Revert removes the replacement and renames the original back, so the
// anonymous volume, every prior log line and the original container id all
// survive a fault that would otherwise have destroyed all three.
func (m envMutator) Revert(
	ctx context.Context,
	env Env,
	record journal.Record,
) error {
	var plan EnvPlan

	if len(record.Payload) == 0 {
		return fmt.Errorf(
			errNoEnvPlan,
			ErrNoEnvPlan,
			EnvFaultKind(m.kind),
		)
	}

	if err := record.DecodePayload(&plan); err != nil {
		return err
	}

	if env.EnvPlan != nil && env.EnvPlan.ReplacedID != "" {
		plan.ReplacedID = env.EnvPlan.ReplacedID
	}

	if env.Docker == nil || plan.Held == "" || plan.OriginalID == "" {
		return fmt.Errorf(errNoEnvPlan, ErrNoEnvPlan, EnvFaultKind(m.kind))
	}

	original := strings.TrimSuffix(plan.Held, dockerx.HeldSuffix)

	// A cold start has only the NAME, and that name is the original's.
	replaced := plan.ReplacedID
	if replaced == "" {
		replaced = original
	}

	if err := m.removeReplacement(ctx, env, plan, replaced); err != nil {
		return err
	}

	spec, err := env.Docker.Capture(ctx, plan.OriginalID)
	if err != nil {
		return err
	}
	if spec.Name != original {
		if spec.Name != plan.Held {
			return fmt.Errorf(
				"original container %s was renamed to %q outside this mutation",
				plan.OriginalID, spec.Name,
			)
		}
		if err := env.Docker.Rename(
			ctx, plan.OriginalID, original,
		); err != nil {
			return err
		}
	}

	return env.Docker.Start(ctx, plan.OriginalID)
}

// NeedsEnv tells the run this mutation replaces the target, derived from the
// registry rather than from the kind's spelling.
func NeedsEnv(kind string) bool {
	mutator, ok := registry[kind]
	if !ok {
		return false
	}

	_, isEnv := mutator.(envMutator)

	return isEnv
}

// ValidEnvKind refuses an invented fault before anything is captured.
func ValidEnvKind(kind EnvKind) error {
	if slices.Contains(EnvKinds(), string(kind)) {
		return nil
	}

	return fmt.Errorf(
		errUnknownEnvKind,
		ErrUnknownEnvKind,
		kind,
		strings.Join(EnvKinds(), ", "),
	)
}

// Prefix declares this tier's kinds to the registry.
func (envMutator) Prefix() string { return KindEnvPrefix }

func (m envMutator) removeReplacement(
	ctx context.Context,
	env Env,
	plan EnvPlan,
	ref string,
) error {
	id, err := env.Docker.Identify(ctx, ref)

	switch {
	case errors.Is(err, dockerx.ErrContainerGone):
		return nil
	case err != nil:
		return err
	case id == plan.OriginalID:
		return nil
	}
	spec, err := env.Docker.Capture(ctx, id)
	if err != nil {
		return err
	}
	if plan.Owner == "" || spec.Config.Labels[ReplacementLabel] != plan.Owner {
		return fmt.Errorf(
			"container %s at %q is not owned by this mutation; refusing removal",
			id,
			ref,
		)
	}

	if err := env.Docker.Remove(ctx, id); err != nil &&
		!errors.Is(err, dockerx.ErrContainerGone) {
		return err
	}

	return nil
}
