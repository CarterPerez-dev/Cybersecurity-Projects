// ©AngelaMos | 2026
// credential.go

package experiment

import (
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/dbx"
	"github.com/CarterPerez-dev/khaos/internal/inject"
)

const (
	FamilyCredential = "credential"

	NameDBRotate          = "credential.db_rotate"
	NameDBRotateTerminate = "credential.db_rotate_terminate"
	NameDBAccountLock     = "credential.db_account_lock"
	NameDBExpiry          = "credential.db_credential_expiry"

	summaryDBRotate = "rotate a database password and find out whether that revoked anything, which on all three engines it does not"

	summaryDBRotateTerminate = "rotate a database password AND terminate the sessions, which is the same fault plus the one statement that makes it a revocation"

	summaryDBAccountLock = "lock a database account, which an incident runbook reaches for when a credential leaks, and see what it does to a connection that is already open"

	summaryDBExpiry = "put a database credential's validity in the past and see whether an established session notices"

	conditionDBRotate = "%s's password being rotated at the engine with no session terminated"

	conditionDBRotateTerminate = "%s's password being rotated at the engine and its sessions terminated"

	conditionDBAccountLock = "%s's account being locked at the engine"

	conditionDBExpiry = "%s's credential validity being put in the past at the engine"

	responseRevoked = "losing access on the credential that was taken away, rather than serving on it for the life of a connection that authenticated before the change"

	responseTerminated = "closing the sessions that authenticated with the credential that was replaced"

	defectDBRotate = "rotating its password at the engine and terminating nothing"

	defectDBRotateTerminate = "rotating its password at the engine and terminating its sessions"

	defectDBAccountLock = "locking its account at the engine"

	defectDBExpiry = "putting its credential validity in the past at the engine"

	caveatTerminated = "the session khaos held was closed by the engine, which is what makes termination the only one of these controls that reaches a connection that is already authenticated"

	caveatRotated = "khaos held one session across the rotation; a target with a connection pool holds as many as its pool is wide, for as long as its own configuration allows"
)

// credentialPolarity is PERMITTED for every experiment in this family, and the
// rationale is the whole teaching point: an operator rotates a credential in
// order to revoke it, and on these engines rotation is a change to the
// admission policy for FUTURE connections and nothing else.
var credentialPolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "a credential that keeps working after it was taken away at the authority is access that outlived its own revocation",
}

func buildCredential(
	trap dbx.Trap,
	condition, defect, caveat string,
) func(*Params) (Shape, error) {
	return func(params *Params) (Shape, error) {
		target := params.Get(ParamTarget)

		spec, err := credSpec(params)
		if err != nil {
			return Shape{}, err
		}

		armed := trap
		armed.Role = dbx.MintedRole()
		armed.Minted = true

		spec.Tier = dbx.NewTier(armed)

		return Shape{
			Condition:  fmt.Sprintf(condition, target),
			Target:     target,
			Probes:     credProbes(spec, spec.Engine),
			Cred:       spec,
			Defect:     defect,
			HeldCaveat: caveat,
		}, nil
	}
}

func init() {
	catalogAdd(Definition{
		Name:    NameDBRotate,
		Family:  FamilyCredential,
		Summary: summaryDBRotate,
		Hypothesis: Hypothesis{
			Condition: "a database password being rotated with no session terminated",
			Response:  responseRevoked,
		},
		Polarity:  credentialPolarity,
		FaultKind: inject.CredKind(dbx.Rotate),
		Params:    credParams,
		Build: buildCredential(
			dbx.Trap{Kind: dbx.Rotate},
			conditionDBRotate,
			defectDBRotate,
			caveatRotated,
		),
	})

	catalogAdd(Definition{
		Name:    NameDBRotateTerminate,
		Family:  FamilyCredential,
		Summary: summaryDBRotateTerminate,
		Hypothesis: Hypothesis{
			Condition: "a database password being rotated and its sessions terminated",
			Response:  responseTerminated,
		},
		Polarity:  credentialPolarity,
		FaultKind: inject.CredKind(dbx.RotateTerminate),
		Params:    credParams,
		Build: buildCredential(
			dbx.Trap{Kind: dbx.RotateTerminate},
			conditionDBRotateTerminate,
			defectDBRotateTerminate,
			caveatTerminated,
		),
	})

	catalogAdd(Definition{
		Name:    NameDBAccountLock,
		Family:  FamilyCredential,
		Summary: summaryDBAccountLock,
		Hypothesis: Hypothesis{
			Condition: "a database account being locked at the engine",
			Response:  responseRevoked,
		},
		Polarity:  credentialPolarity,
		FaultKind: inject.CredKind(dbx.Lock),
		Params:    credParams,
		Build: buildCredential(
			dbx.Trap{Kind: dbx.Lock},
			conditionDBAccountLock,
			defectDBAccountLock,
			caveatRotated,
		),
	})

	catalogAdd(Definition{
		Name:    NameDBExpiry,
		Family:  FamilyCredential,
		Summary: summaryDBExpiry,
		Hypothesis: Hypothesis{
			Condition: "a database credential's validity being put in the past",
			Response:  responseRevoked,
		},
		Polarity:  credentialPolarity,
		FaultKind: inject.CredKind(dbx.Expire),
		Params:    credParams,
		Build: buildCredential(
			dbx.Trap{Kind: dbx.Expire},
			conditionDBExpiry,
			defectDBExpiry,
			caveatRotated,
		),
	})
}
