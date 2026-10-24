// ©AngelaMos | 2026
// secretfault.go

package inject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/secretfile"
)

const (
	KindSecretPrefix = "secret-"

	errNoSecretPlan = "%w: %s needs to be told which secret file to break"

	errMissingOnMountPoint = "%w: %s IS the mount point rather than a file inside one, and a mount point cannot be renamed, so khaos cannot make it vanish. The in-place faults still work here; a secret delivered as a whole directory can also be made to vanish"

	describeSecret = "%s, performed in place by a short-lived container of khaos's own that mounts only %s, drops all capabilities except DAC_OVERRIDE for reading and writing the secret and FOWNER for restoring its permissions, and joins no network"

	confirmEmpty      = "the target's own copy of %s is now zero bytes, and os.ReadFile returns no error on one"
	confirmTruncated  = "the target's own copy of %s is %d bytes where it was %d"
	confirmMissing    = "%s is gone from the target's own filesystem"
	confirmUnreadable = "the target's own copy of %s is mode %04o, which is the one shape of the four that errors on the read itself"

	applyMode   = "--mode"
	applyPath   = "--path"
	applyAside  = "--aside"
	applyBytes  = "--bytes"
	applyBack   = "--restore"
	mutateVerb  = "secret-mutate"
	bytesFormat = "%d"

	// The three read bits, and the mode mask the daemon reports.
	readableBits = 0o444
	modeBits     = 0o777

	errNoSecretThere = "%w: %s is not in %s's filesystem, so there is no secret for khaos to break"
)

var ErrNoSecretPlan = errors.New(
	"this mutation has no secret file to act on",
)

var ErrSecretUnreachable = errors.New(
	"that secret cannot be broken reversibly where it lives",
)

// SecretPlan is everything the mutation and its revert need, and it carries no
// secret: the original stays beside the file inside the target's own mount.
type SecretPlan struct {
	Mutation secretfile.Mutation `json:"mutation"`
	Mount    dockerx.Mount       `json:"mount"`
	Nonce    string              `json:"nonce"`

	// Before is the size the target had, so a truncation can be confirmed as a
	// CHANGE rather than against a threshold.
	Before int64 `json:"before"`
}

func SecretKind(kind secretfile.Kind) string {
	return KindSecretPrefix + string(kind)
}

// secretMutator's authority is a short-lived container rather than a goroutine,
// for two measured reasons. The archive API unlinks and re-creates, so a target
// holding an open file descriptor never experiences the fault; and read-only is
// a property of the TARGET's mount rather than of the volume, so a helper
// mounting the same volume read-write is the only route to a `:ro` secret -
// which is how secrets are conventionally delivered.
type secretMutator struct {
	kind secretfile.Kind
}

func init() {
	for _, name := range secretfile.Kinds() {
		kind := secretfile.Kind(name)
		registry[SecretKind(kind)] = secretMutator{kind: kind}
	}
}

func (m secretMutator) Describe(env Env, _ dockerx.Target) string {
	path := string(m.kind)
	mount := ""

	if env.SecretPlan != nil {
		path = env.SecretPlan.Mutation.Path
		mount = env.SecretPlan.Mount.Destination
	}

	return fmt.Sprintf(
		describeSecret,
		secretfile.Describe(m.kind, path),
		mount,
	)
}

// Plan refuses the one shape this tier cannot undo and records the size the
// target had, so the confirmation is a difference rather than a threshold.
func (m secretMutator) Plan(
	ctx context.Context,
	env Env,
	target dockerx.Target,
) (json.RawMessage, error) {
	if env.SecretPlan == nil {
		return nil, fmt.Errorf(
			errNoSecretPlan,
			ErrNoSecretPlan,
			SecretKind(m.kind),
		)
	}

	plan := env.SecretPlan

	if plan.Mutation.Path == "" {
		return nil, fmt.Errorf(
			errNoSecretPlan,
			ErrNoSecretPlan,
			SecretKind(m.kind),
		)
	}

	if plan.Mutation.Kind != m.kind {
		return nil, fmt.Errorf(
			errWrongTrapKind,
			ErrTrapMismatch,
			plan.Mutation.Kind,
			m.kind,
		)
	}

	if err := plan.Mutation.Validate(); err != nil {
		return nil, err
	}

	if m.kind == secretfile.Missing &&
		dockerx.FileLevelMount(plan.Mount, plan.Mutation.Path) {
		return nil, fmt.Errorf(
			errMissingOnMountPoint,
			ErrSecretUnreachable,
			plan.Mutation.Path,
		)
	}

	stat, err := env.Docker.StatSecret(ctx, target.ID, plan.Mutation.Path)
	if err != nil {
		return nil, err
	}

	if !stat.Exists {
		return nil, fmt.Errorf(
			errNoSecretThere,
			ErrNoSecretPlan,
			plan.Mutation.Path,
			target.Name,
		)
	}

	// Written back through the pointer as well as journaled: the confirmation
	// is a DIFFERENCE and has to know what the target had.
	plan.Before = stat.Size
	mode := stat.Mode & modeBits
	plan.Mutation.OriginalMode = &mode
	plan.Mutation.OriginalSize = &stat.Size

	return journal.EncodePayload(*plan)
}

func (m secretMutator) Apply(
	ctx context.Context,
	env Env,
	_ dockerx.Target,
	raw json.RawMessage,
) error {
	var plan SecretPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return err
	}

	_, err := env.Docker.RunMutator(ctx, dockerx.MutatorSpec{
		Mount: plan.Mount,
		Nonce: plan.Nonce,
		Args:  mutateArgs(plan, false),
	})

	return err
}

// Confirm reads the TARGET's own filesystem rather than the helper's. The
// helper exits before this runs, so a read-back there would be a read of a
// container that no longer exists, and the question is what the container under
// test now has.
func (m secretMutator) Confirm(
	ctx context.Context,
	env Env,
	target dockerx.Target,
) (string, bool, error) {
	if env.SecretPlan == nil {
		return "", false, fmt.Errorf(
			errNoSecretPlan,
			ErrNoSecretPlan,
			SecretKind(m.kind),
		)
	}

	plan := env.SecretPlan

	stat, err := env.Docker.StatSecret(ctx, target.ID, plan.Mutation.Path)
	if err != nil {
		return "", false, err
	}

	switch m.kind {
	case secretfile.Missing:
		if stat.Exists {
			return "", false, nil
		}

		return fmt.Sprintf(confirmMissing, plan.Mutation.Path), true, nil

	case secretfile.Empty:
		if !stat.Exists || stat.Size != 0 {
			return "", false, nil
		}

		return fmt.Sprintf(confirmEmpty, plan.Mutation.Path), true, nil

	case secretfile.Truncated:
		if !stat.Exists || stat.Size == 0 || stat.Size >= plan.Before {
			return "", false, nil
		}

		return fmt.Sprintf(
			confirmTruncated,
			plan.Mutation.Path,
			stat.Size,
			plan.Before,
		), true, nil

	case secretfile.Unreadable:
		if !stat.Exists || stat.Mode&readableBits != 0 {
			return "", false, nil
		}

		return fmt.Sprintf(
			confirmUnreadable,
			plan.Mutation.Path,
			stat.Mode&modeBits,
		), true, nil

	default:
		return "", false, nil
	}
}

// Revert runs a SECOND helper, which is also what a cold start does: the
// original is beside the secret inside the target's own mount, so the journal
// needs no copy of it and khaos needs nothing it was holding in memory.
func (m secretMutator) Revert(
	ctx context.Context,
	env Env,
	record journal.Record,
) error {
	var plan SecretPlan

	if len(record.Payload) == 0 {
		return fmt.Errorf(
			errNoSecretPlan,
			ErrNoSecretPlan,
			SecretKind(m.kind),
		)
	}

	if err := record.DecodePayload(&plan); err != nil {
		return err
	}

	if env.Docker == nil {
		return fmt.Errorf(
			errNoSecretPlan,
			ErrNoSecretPlan,
			SecretKind(m.kind),
		)
	}

	_, err := env.Docker.RunMutator(ctx, dockerx.MutatorSpec{
		Mount: plan.Mount,
		Nonce: plan.Nonce,
		Args:  mutateArgs(plan, true),
	})

	return err
}

func mutateArgs(plan SecretPlan, restore bool) []string {
	args := []string{
		mutateVerb,
		applyPath, plan.Mutation.Path,
		applyAside, plan.Mutation.Aside,
		applyMode, string(plan.Mutation.Kind),
	}

	if plan.Mutation.Bytes > 0 {
		args = append(
			args,
			applyBytes,
			fmt.Sprintf(bytesFormat, plan.Mutation.Bytes),
		)
	}
	if plan.Mutation.OriginalMode != nil {
		args = append(
			args, "--original-mode", fmt.Sprint(*plan.Mutation.OriginalMode),
		)
	}
	if plan.Mutation.OriginalSize != nil {
		args = append(
			args, "--original-size", fmt.Sprint(*plan.Mutation.OriginalSize),
		)
	}

	if restore {
		args = append(args, applyBack)
	}

	return args
}

// NeedsSecret tells the run this mutation acts on a file inside the target,
// derived from the registry rather than from the kind's spelling.
func NeedsSecret(kind string) bool {
	mutator, ok := registry[kind]
	if !ok {
		return false
	}

	_, isSecret := mutator.(secretMutator)

	return isSecret
}

// Prefix declares this tier's kinds to the registry.
func (secretMutator) Prefix() string { return KindSecretPrefix }
