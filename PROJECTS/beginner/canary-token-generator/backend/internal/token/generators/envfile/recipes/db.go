// ©AngelaMos | 2026
// db.go

package recipes

import "fmt"

const (
	dbPostgresUser = "app_writer"
	dbPostgresHost = "db.internal"
	dbPostgresPort = 5432
	dbPostgresName = "app_prod"

	dbRedisUser = "default"
	dbRedisHost = "cache-prod.internal"
	dbRedisPort = 6379
	dbRedisDB   = 0

	dbPostgresPassLen = 24
	dbRedisPassLen    = 32

	dbPostgresURLFmt = "postgres://%s:%s@%s:%d/%s?sslmode=require"
	dbRedisURLFmt    = "redis://%s:%s@%s:%d/%d"
)

type DB struct{}

func (DB) Name() string { return keyDB }

func (DB) Generate() []EnvLine {
	pgPass := RandomAlnumMixed(dbPostgresPassLen)
	redisPass := RandomAlnumMixed(dbRedisPassLen)

	pgURL := fmt.Sprintf(
		dbPostgresURLFmt,
		dbPostgresUser,
		pgPass,
		dbPostgresHost,
		dbPostgresPort,
		dbPostgresName,
	)
	redisURL := fmt.Sprintf(
		dbRedisURLFmt,
		dbRedisUser,
		redisPass,
		dbRedisHost,
		dbRedisPort,
		dbRedisDB,
	)

	return []EnvLine{
		{Comment: "Primary datastore + cache"},
		{Key: "DATABASE_URL", Value: pgURL},
		{Key: "REDIS_URL", Value: redisURL},
	}
}
