// ©AngelaMos | 2026
// db_test.go

package recipes_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/envfile/recipes"
)

func TestDBRecipe_Name(t *testing.T) {
	require.Equal(t, "db", recipes.DB{}.Name())
}

func TestDBRecipe_GeneratesExpectedKeys(t *testing.T) {
	lines := recipes.DB{}.Generate()
	byKey := linesByKey(t, lines)

	for _, key := range []string{"DATABASE_URL", "REDIS_URL"} {
		_, ok := byKey[key]
		require.True(t, ok, "DB recipe must emit %s", key)
	}
}

func TestDBRecipe_DatabaseURLParsesAsPostgres(t *testing.T) {
	lines := recipes.DB{}.Generate()
	byKey := linesByKey(t, lines)
	parsed, err := url.Parse(byKey["DATABASE_URL"].Value)
	require.NoError(t, err)
	require.Equal(t, "postgres", parsed.Scheme)
	require.Equal(t, "db.internal:5432", parsed.Host)
	require.Equal(t, "/app_prod", parsed.Path)
	require.Equal(t, "app_writer", parsed.User.Username())

	pw, ok := parsed.User.Password()
	require.True(t, ok, "DATABASE_URL must carry a password")
	require.Regexp(t, `^[A-Za-z0-9]{24}$`, pw)
	require.Equal(t, "require", parsed.Query().Get("sslmode"))
}

func TestDBRecipe_RedisURLParsesAsRedis(t *testing.T) {
	lines := recipes.DB{}.Generate()
	byKey := linesByKey(t, lines)
	parsed, err := url.Parse(byKey["REDIS_URL"].Value)
	require.NoError(t, err)
	require.Equal(t, "redis", parsed.Scheme)
	require.Equal(t, "cache-prod.internal:6379", parsed.Host)
	require.Equal(t, "/0", parsed.Path)
	require.Equal(t, "default", parsed.User.Username())

	pw, ok := parsed.User.Password()
	require.True(t, ok, "REDIS_URL must carry a password")
	require.Regexp(t, `^[A-Za-z0-9]{32}$`, pw)
}

func TestDBRecipe_HasLeadingComment(t *testing.T) {
	lines := recipes.DB{}.Generate()
	require.NotEmpty(t, lines)
	require.NotEmpty(t, lines[0].Comment)
	require.Empty(t, lines[0].Key)
}

func TestDBRecipe_DistinctInvocationsProduceDistinctPasswords(t *testing.T) {
	seen := make(map[string]struct{})
	for range 20 {
		lines := recipes.DB{}.Generate()
		byKey := linesByKey(t, lines)
		seen[byKey["DATABASE_URL"].Value] = struct{}{}
	}
	require.Greater(t, len(seen), 18)
}
