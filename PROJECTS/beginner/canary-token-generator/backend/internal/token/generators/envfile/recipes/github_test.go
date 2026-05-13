// ©AngelaMos | 2026
// github_test.go

package recipes_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/envfile/recipes"
)

func TestGitHubRecipe_Name(t *testing.T) {
	require.Equal(t, "github", recipes.GitHub{}.Name())
}

func TestGitHubRecipe_GeneratesExpectedKeys(t *testing.T) {
	lines := recipes.GitHub{}.Generate()
	byKey := linesByKey(t, lines)

	for _, key := range []string{
		"GITHUB_TOKEN",
		"GITHUB_DEPLOY_KEY",
		"GITHUB_OWNER",
		"GITHUB_REPO",
	} {
		_, ok := byKey[key]
		require.True(t, ok, "GitHub recipe must emit %s", key)
	}
}

func TestGitHubRecipe_TokenMatchesGhpFormat(t *testing.T) {
	lines := recipes.GitHub{}.Generate()
	byKey := linesByKey(t, lines)
	require.Regexp(
		t,
		`^ghp_[A-Za-z0-9]{42}$`,
		byKey["GITHUB_TOKEN"].Value,
		"GITHUB_TOKEN must match ghp_ + 36 base62 body + 6 base62 checksum = 42 trailing chars",
	)
}

func TestGitHubRecipe_DeployKeyIsBase64Like(t *testing.T) {
	lines := recipes.GitHub{}.Generate()
	byKey := linesByKey(t, lines)
	require.Regexp(
		t,
		`^[A-Za-z0-9+/]+={0,2}$`,
		byKey["GITHUB_DEPLOY_KEY"].Value,
	)
}

func TestGitHubRecipe_OwnerAndRepoAreStable(t *testing.T) {
	lines := recipes.GitHub{}.Generate()
	byKey := linesByKey(t, lines)
	require.Equal(t, "acme-corp", byKey["GITHUB_OWNER"].Value)
	require.Equal(t, "internal-platform", byKey["GITHUB_REPO"].Value)
}

func TestGitHubRecipe_HasLeadingComment(t *testing.T) {
	lines := recipes.GitHub{}.Generate()
	require.NotEmpty(t, lines)
	require.NotEmpty(t, lines[0].Comment)
	require.Empty(t, lines[0].Key)
}
