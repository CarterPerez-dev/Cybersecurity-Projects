// ©AngelaMos | 2026
// credential.go

package experiment

import (
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/dbx"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/probe"
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

const (
	NameDBPoolStale     = "credential.db_pool_stale"
	NameDBPendingWindow = "credential.db_pending_window"

	summaryDBPoolStale = "rotate the password a service's own connection pool authenticated with, and see whether the service notices"

	summaryDBPendingWindow = "rotate the password a service's pool authenticated with, and see whether its liveness probe keeps reporting healthy while no new connection can be made"

	conditionDBPoolStale = "the password %s's own connection pool authenticated with being rotated at the engine"

	conditionDBPendingWindow = "the password behind %s's liveness probe being rotated at the engine"

	responsePool = "losing access on the credential that was taken away, rather than serving for as long as a connection that authenticated before the rotation stays in the pool"

	responsePending = "a liveness answer that reflects whether the service can actually reach its database, rather than one a connection authenticated before the rotation can keep answering"

	defectDBPool = "rotating the password its own connection pool authenticated with"

	caveatPoolHeld = "khaos rotated the credential and the service carried on; database/sql closes a connection for age only when SetConnMaxLifetime is positive, and a connection that is checked out rather than idle is not bounded by it at all"

	caveatPendingHeld = "the liveness endpoint answered throughout on a connection that authenticated before the rotation, while khaos's own read-back proves a new connection on that credential is refused; readiness has to dial to answer the question it is asking"

	probeReadyName = "readiness-that-has-to-dial"

	describeReady = "%s, which forces a connection of its own rather than answering from the pool"
)

// poolPolarity is the second place in the catalogue where HELD is the defect,
// after the TLS family. A service that carries on unchanged has kept its
// database access through a revocation, so "nothing looks wrong" is the
// finding, and DENIED - the pool redialling and failing - is the correct
// behaviour this experiment is looking for.
var poolPolarity = Polarity{
	// HELD and PERMITTED both, following the TLS family's convention. HELD is
	// this fault's own finding; PERMITTED would be the gateway's own
	// authorization failing open during the window, which is unrelated to the
	// rotation and still a defect worth reporting rather than exiting 0 on.
	Defects:   []Direction{Held, Permitted},
	Rationale: "a service that keeps serving after the credential its pool authenticated with was rotated away has kept access that outlived its own revocation, and the operator who rotated it believes it did not",
}

// buildPool wires the three streams a pooled fault needs. The readiness
// endpoint is the REVOKED stream rather than a confirmation step, which makes
// it honest in both directions: refused during the fault it scores nothing and
// the finding is the service carrying on, while accepted during the fault it
// is a real finding that the rotation never reached the pool's dials.
func buildPool(
	primary func(*Params) string,
	condition, defect, caveat string,
) func(*Params) (Shape, error) {
	return func(params *Params) (Shape, error) {
		target := params.Get(ParamTarget)

		spec, err := credSpec(params)
		if err != nil {
			return Shape{}, err
		}

		// Read HERE rather than in credSpec, because only the pooled
		// experiments declare these three and a builder reading a parameter
		// its experiment never declared is refused at build time.
		spec.EngineTarget = params.Get(ParamEngineTarget)
		spec.Subject = params.Get(ParamSubjectRole)
		spec.SubjectVar = params.Get(ParamSubjectVar)

		spec.Tier = dbx.NewTier(dbx.Trap{
			Kind:   dbx.PoolRotate,
			Role:   spec.Subject,
			Minted: false,
		})

		ready := params.Get(ParamReadyURL)

		return Shape{
			Condition: fmt.Sprintf(condition, target),
			Target:    target,
			Probes: probe.Pair{
				Valid: probe.NewHTTP(probe.HTTPOptions{
					Name:       probeValidName,
					URL:        primary(params),
					Token:      params.Get(ParamToken),
					Credential: probe.Valid,
				}),
				Invalid: probe.NewHTTP(probe.HTTPOptions{
					Name:       probeInvalidName,
					URL:        params.Get(ParamURL),
					Token:      params.Get(ParamInvalidToken),
					Credential: probe.Invalid,
					Unique:     true,
				}),
				Revoked: probe.NewHTTP(probe.HTTPOptions{
					Name:       probeReadyName,
					Describe:   fmt.Sprintf(describeReady, ready),
					URL:        ready,
					Token:      params.Get(ParamToken),
					Credential: probe.Revoked,
				}),
			},
			Cred:       spec,
			Defect:     defect,
			HeldCaveat: caveat,

			// A pool that redialled and could not authenticate makes the
			// service UNAVAILABLE rather than refusing a credential, and that
			// is this control failing closed. Without it the correct
			// behaviour - losing access - reads as the service carrying on.
			ClosedWhen: []probe.Disposition{probe.Unavailable},
		}, nil
	}
}

func init() {
	catalogAdd(Definition{
		Name:    NameDBPoolStale,
		Family:  FamilyCredential,
		Summary: summaryDBPoolStale,
		Hypothesis: Hypothesis{
			Condition: "the password a service's connection pool authenticated with being rotated",
			Response:  responsePool,
		},
		Polarity:  poolPolarity,
		FaultKind: inject.CredKind(dbx.PoolRotate),
		Params: poolParams(
			Param{Name: ParamURL, Usage: usageURL, Required: true},
		),
		Build: buildPool(
			func(params *Params) string { return params.Get(ParamURL) },
			conditionDBPoolStale,
			defectDBPool,
			caveatPoolHeld,
		),
	})

	catalogAdd(Definition{
		Name:    NameDBPendingWindow,
		Family:  FamilyCredential,
		Summary: summaryDBPendingWindow,
		Hypothesis: Hypothesis{
			Condition: "the password behind a service's liveness probe being rotated",
			Response:  responsePending,
		},
		Polarity:  poolPolarity,
		FaultKind: inject.CredKind(dbx.PoolRotate),
		Params: poolParams(
			Param{Name: ParamURL, Usage: usageURL, Required: true},
			Param{Name: ParamHealthURL, Usage: usageHealthURL, Required: true},
		),
		Build: buildPool(
			func(params *Params) string { return params.Get(ParamHealthURL) },
			conditionDBPendingWindow,
			defectDBPool,
			caveatPendingHeld,
		),
	})
}
