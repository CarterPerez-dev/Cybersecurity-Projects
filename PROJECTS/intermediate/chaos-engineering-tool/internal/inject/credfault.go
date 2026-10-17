// ©AngelaMos | 2026
// credfault.go

package inject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/dbx"
	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const (
	KindCredPrefix = "cred-"

	errNoCredTier = "%w: %s needs khaos's credential tier, and this run has none"

	errNoCredRecipe = "%w: this credential fault has nothing recorded about how to reach the engine again"

	errCredSecretGone = "%s is not in %s's environment any more, so khaos cannot re-read the credential it would need to undo this"

	describeCred = "%s, which khaos performs over the engine's own administrative protocol rather than through the daemon"
)

var ErrNoCredTier = errors.New(
	"this mutation needs khaos's credential tier, which is not open",
)

var ErrNoCredRecipe = errors.New(
	"this credential fault cannot be reverted from a cold start",
)

// CredSource is where a credential is READ FROM rather than the credential.
// The journal records this and never the secret: a flag would put it in
// /proc/<pid>/cmdline, which is world-readable on a normal host, and a journal
// entry would leave it on disk after the run.
type CredSource struct {
	ContainerID string `json:"container_id"`
	Role        string `json:"role"`
	PasswordVar string `json:"password_var"`
}

// CredPlan is everything a cold-started khaos needs to undo a credential fault.
type CredPlan struct {
	Engine   dbx.Engine  `json:"engine"`
	Address  string      `json:"address"`
	Database string      `json:"database"`
	Admin    CredSource  `json:"admin"`
	Subject  *CredSource `json:"subject,omitempty"`
}

func CredKind(kind dbx.Kind) string {
	return KindCredPrefix + string(kind)
}

// credMutator's authority is a stock database that behaves CORRECTLY. Every
// other tier exists because no correct dependency emits the defect; here the
// finding is that three correct engines never re-evaluate authentication.
type credMutator struct {
	kind dbx.Kind
}

func init() {
	for _, name := range dbx.Kinds() {
		kind := dbx.Kind(name)
		registry[CredKind(kind)] = credMutator{kind: kind}
	}
}

func (m credMutator) Describe(env Env, target dockerx.Target) string {
	trap := env.CredTrap
	if trap.Kind != m.kind {
		trap = dbx.Trap{Kind: m.kind, Role: trap.Role}
	}

	return fmt.Sprintf(
		describeCred,
		trap.Describe(target.Name, env.CredPlan.Engine),
	)
}

type credPayload struct {
	Trap dbx.Trap `json:"trap"`
	Plan CredPlan `json:"plan"`
}

func (m credMutator) Plan(
	_ context.Context,
	env Env,
	_ dockerx.Target,
) (json.RawMessage, error) {
	if env.Cred == nil {
		return nil, fmt.Errorf(errNoCredTier, ErrNoCredTier, CredKind(m.kind))
	}

	trap := env.Cred.Trap()

	if trap.Kind != m.kind {
		return nil, fmt.Errorf(
			errWrongTrapKind,
			ErrTrapMismatch,
			trap.Kind,
			m.kind,
		)
	}

	if err := trap.Validate(); err != nil {
		return nil, err
	}

	return journal.EncodePayload(credPayload{Trap: trap, Plan: env.CredPlan})
}

func (m credMutator) Apply(
	ctx context.Context,
	env Env,
	_ dockerx.Target,
	_ json.RawMessage,
) error {
	if env.Cred == nil {
		return fmt.Errorf(errNoCredTier, ErrNoCredTier, CredKind(m.kind))
	}

	return env.Cred.Arm(ctx)
}

func (m credMutator) Confirm(
	ctx context.Context,
	env Env,
	_ dockerx.Target,
) (string, bool, error) {
	if env.Cred == nil {
		return "", false, fmt.Errorf(
			errNoCredTier,
			ErrNoCredTier,
			CredKind(m.kind),
		)
	}

	return env.Cred.Observe(ctx)
}

// Revert prefers the open tier, which knows the credential it replaced. From a
// cold start it rebuilds a client out of the journal's recipe and re-reads both
// credentials from the containers that hold them.
func (m credMutator) Revert(
	ctx context.Context,
	env Env,
	record journal.Record,
) error {
	if env.Cred != nil {
		return env.Cred.Disarm(ctx)
	}

	var payload credPayload
	if len(record.Payload) == 0 {
		return fmt.Errorf(errNoCredRecipe, ErrNoCredRecipe)
	}
	if err := record.DecodePayload(&payload); err != nil {
		return err
	}

	return revertFromRecipe(ctx, env, payload)
}

func revertFromRecipe(
	ctx context.Context,
	env Env,
	payload credPayload,
) error {
	if env.Docker == nil || payload.Plan.Address == "" {
		return fmt.Errorf(errNoCredRecipe, ErrNoCredRecipe)
	}

	admin, err := readSource(ctx, env.Docker, payload.Plan.Admin)
	if err != nil {
		return err
	}

	client, err := dbx.Open(dbx.Config{
		Engine:   payload.Plan.Engine,
		Address:  payload.Plan.Address,
		Database: payload.Plan.Database,
		Admin:    admin,
	})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	var failures []error

	// A role khaos minted takes the fault with it, so the revert is removal
	// rather than restoration and there is nothing to guess.
	if payload.Trap.Minted {
		if _, err := client.Terminate(ctx, payload.Trap.Role); err != nil {
			failures = append(failures, err)
		}
		if err := client.DropRole(ctx, payload.Trap.Role); err != nil {
			failures = append(failures, err)
		}

		return errors.Join(failures...)
	}

	if payload.Plan.Subject == nil {
		return fmt.Errorf(errNoCredRecipe, ErrNoCredRecipe)
	}

	subject, err := readSource(ctx, env.Docker, *payload.Plan.Subject)
	if err != nil {
		return err
	}

	switch payload.Trap.Kind {
	case dbx.Lock:
		return client.Unlock(ctx, payload.Trap.Role)
	case dbx.Expire:
		return client.Unexpire(ctx, subject)
	default:
		return client.Rotate(ctx, subject)
	}
}

// readSource re-reads a credential from the container that owns it. The
// container is the only authority on it, and the value never travels through
// khaos's own state.
func readSource(
	ctx context.Context,
	docker *dockerx.Client,
	source CredSource,
) (dbx.Credential, error) {
	environ, err := docker.ContainerEnv(ctx, source.ContainerID)
	if err != nil {
		return dbx.Credential{}, err
	}

	password, found := environ[source.PasswordVar]
	if !found || password == "" {
		return dbx.Credential{}, fmt.Errorf(
			errCredSecretGone,
			source.PasswordVar,
			dockerx.ShortID(source.ContainerID),
		)
	}

	return dbx.Credential{Role: source.Role, Password: password}, nil
}

// IsPoolFault reports whether this mutation acts on a role belonging to the
// TARGET rather than one khaos minted, which decides which container the range
// points the experiment at.
func IsPoolFault(kind string) bool {
	mutator, ok := registry[kind]
	if !ok {
		return false
	}

	cred, isCred := mutator.(credMutator)

	return isCred && cred.kind == dbx.PoolRotate
}

// NeedsCred tells the run to open a credential tier before the baseline,
// derived from the registry rather than from the kind's spelling.
func NeedsCred(kind string) bool {
	mutator, ok := registry[kind]
	if !ok {
		return false
	}

	_, isCred := mutator.(credMutator)

	return isCred
}

// Prefix declares this tier's kinds to the registry.
func (credMutator) Prefix() string { return KindCredPrefix }
