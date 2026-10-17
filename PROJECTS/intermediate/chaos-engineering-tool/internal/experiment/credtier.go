// ©AngelaMos | 2026
// credtier.go

package experiment

import (
	"context"
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/dbx"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	ParamEngine       = "engine"
	ParamEngineTarget = "engine-target"
	ParamSubjectRole  = "subject-role"
	ParamSubjectVar   = "subject-password-var"
	ParamHealthURL    = "health-url"
	ParamReadyURL     = "ready-url"
	ParamEnginePort   = "engine-port"
	ParamDatabase     = "database"
	ParamAdminRole    = "admin-role"
	ParamAdminVar     = "admin-password-var"

	usageEngineTarget = "the consenting container running the engine the target authenticates against; khaos reads its administrative credential and its address from it, and the role it rotates belongs to the target rather than to khaos"

	usageSubjectRole = "the database role the target's own connection pool authenticated with, which is the one khaos rotates"

	usageSubjectVar = "the environment variable on the TARGET that holds the password its pool authenticated with; khaos reads it there and puts the same value back, so a rotation it could not undo is one it will not perform"

	usageHealthURL = "the target's liveness endpoint, which is the one that answers on a pooled connection"

	usageReadyURL = "the target's readiness endpoint, which is the one that has to dial"

	usageEngine = "which database engine the target runs; the range fills this from the container's own image"

	usageEnginePort = "the port the engine listens on INSIDE its container, which khaos dials directly rather than through a published port"

	usageDatabase = "the database khaos's own administrative connection uses; PostgreSQL requires one and the MySQL family does not"

	usageAdminRole = "the role khaos performs the rotation as, which is never the role under test"

	usageAdminVar = "the environment variable on the target container that holds the administrative password; khaos reads it from the container rather than taking it on a flag, because a flag is world-readable in /proc and a journal entry would outlive the run"

	errNoEngine = "this experiment needs --%s (one of %s), because the fault is performed over the engine's own administrative protocol and the three do not share one"

	probeCurrentName = "current-credential"
	probeWrongName   = "never-valid-credential"
	probeHeldName    = "session-held-across-the-fault"

	describeCurrent = "a NEW connection to the %s presenting whatever credential should work right now"

	describeWrong = "a NEW connection to the %s presenting a password that was never correct, minted fresh per sample so nothing can answer it from a cache"

	describeHeld = "the session that authenticated BEFORE the fault, queried again and never re-authenticated"
)

// CredSpec is grouped rather than spread across Shape, which already carries
// one field per tier and would otherwise carry seven for this one.
type CredSpec struct {
	Tier *dbx.Tier

	// EngineTarget is the container running the engine, which for a pooled
	// fault is NOT the container being measured. khaos resolves both through
	// the refusal predicates, because it mutates state on one and measures the
	// other.
	EngineTarget string

	Engine   dbx.Engine
	Port     string
	Database string

	Admin    string
	AdminVar string

	// Subject is the role a pooled-service fault acts on, which belongs to the
	// target rather than to khaos. Empty for a role khaos mints.
	Subject    string
	SubjectVar string
}

// credDefaults are per-engine and pure, so Build resolves them without a
// daemon. Each is what the official image ships.
type credDefaults struct {
	port     string
	database string
	admin    string
	adminVar string
}

var credByEngine = map[dbx.Engine]credDefaults{
	dbx.Postgres: {
		port:     "5432",
		database: "postgres",
		admin:    "postgres",
		adminVar: "POSTGRES_PASSWORD",
	},
	dbx.MySQL: {
		port:     "3306",
		database: "",
		admin:    "root",
		adminVar: "MYSQL_ROOT_PASSWORD",
	},
	dbx.MariaDB: {
		port:     "3306",
		database: "",
		admin:    "root",
		adminVar: "MARIADB_ROOT_PASSWORD",
	},
}

var credParams = []Param{
	{Name: ParamTarget, Usage: usageTargetEngine, Required: true},
	{Name: ParamEngine, Usage: usageEngine},
	{Name: ParamEnginePort, Usage: usageEnginePort},
	{Name: ParamDatabase, Usage: usageDatabase},
	{Name: ParamAdminRole, Usage: usageAdminRole},
	{Name: ParamAdminVar, Usage: usageAdminVar},
}

// poolParams targets the SERVICE rather than the engine, so it needs both: the
// container khaos measures and the container khaos performs the rotation at.
func poolParams(extra ...Param) []Param {
	params := []Param{
		{Name: ParamTarget, Usage: usageTargetPooled, Required: true},
		{Name: ParamEngineTarget, Usage: usageEngineTarget, Required: true},
		{Name: ParamEngine, Usage: usageEngine},
		{Name: ParamEnginePort, Usage: usageEnginePort},
		{Name: ParamDatabase, Usage: usageDatabase},
		{Name: ParamAdminRole, Usage: usageAdminRole},
		{Name: ParamAdminVar, Usage: usageAdminVar},
		{Name: ParamSubjectRole, Usage: usageSubjectRole, Required: true},
		{Name: ParamSubjectVar, Usage: usageSubjectVar, Required: true},
		{Name: ParamReadyURL, Usage: usageReadyURL, Required: true},
		{
			Name:    ParamInvalidToken,
			Usage:   usageInvalidToken,
			Default: DefaultInvalidToken,
		},
		{Name: ParamToken, Usage: usageToken, Required: true},
	}

	return append(params, extra...)
}

const (
	usageTargetEngine = "the consenting container running the database whose credential you want to rotate"

	usageTargetPooled = "the consenting container whose own connection pool you want to rotate the credential out from under"
)

// credSpec resolves the engine and then fills every unspecified input from what
// that engine's official image ships, so a run against the range needs no flags
// and an operator's own target needs only the engine.
func credSpec(params *Params) (*CredSpec, error) {
	raw := params.Get(ParamEngine)
	if raw == "" {
		return nil, fmt.Errorf(
			errNoEngine,
			ParamEngine,
			joinNames(dbx.Engines()),
		)
	}

	engine, err := dbx.ParseEngine(raw)
	if err != nil {
		return nil, err
	}

	defaults := credByEngine[engine]

	spec := &CredSpec{
		Engine:   engine,
		Port:     orElse(params.Get(ParamEnginePort), defaults.port),
		Database: orElse(params.Get(ParamDatabase), defaults.database),
		Admin:    orElse(params.Get(ParamAdminRole), defaults.admin),
		AdminVar: orElse(params.Get(ParamAdminVar), defaults.adminVar),
	}

	return spec, nil
}

func orElse(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func joinNames(names []string) string {
	out := ""
	for i, name := range names {
		if i > 0 {
			out += nameSep
		}
		out += name
	}
	return out
}

// credProbes wires the three streams onto the tier. Every one of them is a
// fresh dial except the held session, which is the whole point: authentication
// happens once per connection on all three engines.
func credProbes(spec *CredSpec, engine dbx.Engine) probe.Pair {
	return probe.Pair{
		Valid: probe.NewCall(probe.CallOptions{
			Name:       probeCurrentName,
			Describe:   fmt.Sprintf(describeCurrent, engine),
			Credential: probe.Valid,
			Call: func(ctx context.Context) (probe.Disposition, string) {
				return dispositionOf(spec.Tier.Current(ctx))
			},
		}),
		Invalid: probe.NewCall(probe.CallOptions{
			Name:       probeWrongName,
			Describe:   fmt.Sprintf(describeWrong, engine),
			Credential: probe.Invalid,
			Call: func(ctx context.Context) (probe.Disposition, string) {
				return dispositionOf(spec.Tier.Wrong(ctx))
			},
		}),
		Revoked: probe.NewCall(probe.CallOptions{
			Name:       probeHeldName,
			Describe:   describeHeld,
			Credential: probe.Revoked,
			Call: func(ctx context.Context) (probe.Disposition, string) {
				return dispositionOf(spec.Tier.Held(ctx))
			},
		}),
	}
}

// dispositionOf maps what the engine said to what it means about the
// credential. Every refusal shape is a refusal; khaos's own problems are
// excluded from every rate rather than counted as target behaviour.
func dispositionOf(result dbx.Result) (probe.Disposition, string) {
	switch result.Answer {
	case dbx.Served:
		return probe.Accepted, result.Detail
	case dbx.Refused, dbx.Locked, dbx.Expired, dbx.MustReset, dbx.Terminated:
		return probe.Rejected, result.Detail
	case dbx.Unreachable:
		// An engine khaos could not reach ANSWERED nothing, which is not the
		// same observation as a service answering 503 - and the pooled
		// experiments declare the second as their fail-closed outcome.
		return probe.Unreachable, result.Detail
	default:
		return probe.ProbeFailed, result.Detail
	}
}
