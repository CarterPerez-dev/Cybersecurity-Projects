/*
©AngelaMos | 2026
repository.go

Repository interfaces for all persistent data access

Defines the contracts that the pgx implementation fulfills. Each
interface is scoped to a single domain: events, sessions, attackers,
credentials, IOCs, and MITRE detections. Consumers depend on
interfaces, never on concrete implementations.
*/

package store

import (
	"context"
	"time"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

type EventRepository interface {
	InsertEvent(ctx context.Context, ev *types.Event) error
	InsertBatch(
		ctx context.Context, evs []*types.Event,
	) error
	FindByIP(
		ctx context.Context, ip string, limit, offset int,
	) ([]*types.Event, error)
	FindBySession(
		ctx context.Context, sessionID string,
	) ([]*types.Event, error)
	RecentEvents(
		ctx context.Context, limit int,
	) ([]*types.Event, error)
	CountByService(
		ctx context.Context, since time.Time,
	) (map[types.ServiceType]int64, error)
	CountByCountry(
		ctx context.Context, since time.Time,
	) (map[string]int64, error)
	TotalCount(ctx context.Context) (int64, error)
}

type SessionRepository interface {
	InsertSession(
		ctx context.Context, s *types.Session,
	) error
	UpdateSession(
		ctx context.Context, s *types.Session,
	) error
	GetSession(
		ctx context.Context, id string,
	) (*types.Session, error)
	ListSessions(
		ctx context.Context,
		service string,
		limit, offset int,
	) ([]*types.Session, int64, error)
	ActiveSessions(
		ctx context.Context,
	) ([]*types.Session, error)
}

type AttackerRepository interface {
	UpsertAttacker(
		ctx context.Context, a *types.Attacker,
	) error
	GetAttacker(
		ctx context.Context, id int64,
	) (*types.Attacker, error)
	GetAttackerByIP(
		ctx context.Context, ip string,
	) (*types.Attacker, error)
	TopAttackers(
		ctx context.Context, since time.Time, limit, offset int,
	) ([]*types.Attacker, error)
	TotalCount(ctx context.Context) (int64, error)
}

type CredentialRepository interface {
	InsertCredential(
		ctx context.Context, c *types.Credential,
	) error
	TopUsernames(
		ctx context.Context, limit int,
	) ([]CredentialCount, error)
	TopPasswords(
		ctx context.Context, limit int,
	) ([]CredentialCount, error)
	TopPairs(
		ctx context.Context, limit int,
	) ([]CredentialPairCount, error)
}

type IOCRepository interface {
	UpsertIOC(ctx context.Context, ioc *types.IOC) error
	ListIOCs(
		ctx context.Context, limit, offset int,
	) ([]*types.IOC, int64, error)
}

type MITRERepository interface {
	InsertDetection(
		ctx context.Context, d *types.MITREDetection,
	) error
	TechniqueHeatmap(
		ctx context.Context, since time.Time,
	) ([]TechniqueCount, error)
	RecentDetections(
		ctx context.Context, limit int,
	) ([]*types.MITREDetection, error)
}

type CredentialCount struct {
	Value string
	Count int64
}

type CredentialPairCount struct {
	Username string
	Password string
	Count    int64
}

type TechniqueCount struct {
	TechniqueID string
	Tactic      string
	Count       int64
}

type Store interface {
	EventRepository
	SessionRepository
	AttackerRepository
	CredentialRepository
	IOCRepository
	MITRERepository
	Close()
}
