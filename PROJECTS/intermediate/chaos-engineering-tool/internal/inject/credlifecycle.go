// ©AngelaMos | 2026
// credlifecycle.go

package inject

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/CarterPerez-dev/khaos/internal/dbx"
	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const KindCredentialTier = "credential-tier-lifetime"

type credentialTier struct{}

func init() {
	registry[KindCredentialTier] = credentialTier{}
}

func (credentialTier) Obligation() {}

func (credentialTier) Describe(_ Env, target dockerx.Target) string {
	return "open the temporary credential tier for " + target.Name
}

func (credentialTier) Plan(
	_ context.Context,
	env Env,
	_ dockerx.Target,
) (json.RawMessage, error) {
	if env.Cred == nil || env.CredPlan.Address == "" {
		return nil, ErrNoCredRecipe
	}
	trap := env.Cred.Trap()
	if err := trap.Validate(); err != nil {
		return nil, err
	}
	return journal.EncodePayload(credPayload{Trap: trap, Plan: env.CredPlan})
}

func (credentialTier) Apply(
	ctx context.Context,
	env Env,
	_ dockerx.Target,
	raw json.RawMessage,
) error {
	if env.Cred == nil || env.Docker == nil {
		return ErrNoCredTier
	}
	var payload credPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	admin, err := readSource(ctx, env.Docker, payload.Plan.Admin)
	if err != nil {
		return err
	}
	var subject dbx.Credential
	if payload.Plan.Subject != nil {
		subject, err = readSource(ctx, env.Docker, *payload.Plan.Subject)
		if err != nil {
			return err
		}
	}
	return env.Cred.Open(ctx, dbx.Config{
		Engine:   payload.Plan.Engine,
		Address:  payload.Plan.Address,
		Database: payload.Plan.Database,
		Admin:    admin,
	}, subject)
}

func (credentialTier) Confirm(
	_ context.Context,
	env Env,
	_ dockerx.Target,
) (string, bool, error) {
	if env.Cred == nil {
		return "", false, ErrNoCredTier
	}
	return "the credential tier has an open administrative connection", env.Cred.Version() != "", nil
}

func (credentialTier) Revert(
	ctx context.Context,
	env Env,
	record journal.Record,
) error {
	var payload credPayload
	if err := record.DecodePayload(&payload); err != nil {
		return err
	}
	var closeErr error
	if env.Cred != nil {
		closeErr = env.Cred.Close(ctx)
	}
	if !payload.Trap.Minted {
		return closeErr
	}
	return errors.Join(closeErr, revertFromRecipe(ctx, env, payload))
}
