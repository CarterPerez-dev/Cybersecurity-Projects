// ©AngelaMos | 2026
// aws_test.go

package recipes_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/envfile/recipes"
)

func linesByKey(
	t *testing.T,
	lines []recipes.EnvLine,
) map[string]recipes.EnvLine {
	t.Helper()
	out := make(map[string]recipes.EnvLine, len(lines))
	for _, l := range lines {
		if l.Key != "" {
			out[l.Key] = l
		}
	}
	return out
}

func TestAWSRecipe_Name(t *testing.T) {
	require.Equal(t, "aws", recipes.AWS{}.Name())
}

func TestAWSRecipe_GeneratesExpectedKeys(t *testing.T) {
	lines := recipes.AWS{}.Generate()
	byKey := linesByKey(t, lines)

	for _, key := range []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_REGION",
		"AWS_S3_BUCKET",
	} {
		_, ok := byKey[key]
		require.True(t, ok, "AWS recipe must emit %s", key)
	}
}

func TestAWSRecipe_AccessKeyMatchesAKIAFormat(t *testing.T) {
	lines := recipes.AWS{}.Generate()
	byKey := linesByKey(t, lines)
	require.Regexp(
		t,
		`^AKIA[A-Z0-9]{16}$`,
		byKey["AWS_ACCESS_KEY_ID"].Value,
		"AWS_ACCESS_KEY_ID must match the AKIA + 16 base32-upper-alnum format gitleaks expects",
	)
}

func TestAWSRecipe_SecretAccessKeyIsBase64Like(t *testing.T) {
	lines := recipes.AWS{}.Generate()
	byKey := linesByKey(t, lines)
	require.Regexp(
		t,
		`^[A-Za-z0-9+/]+={0,2}$`,
		byKey["AWS_SECRET_ACCESS_KEY"].Value,
	)
	require.GreaterOrEqual(
		t,
		len(byKey["AWS_SECRET_ACCESS_KEY"].Value),
		40,
		"AWS_SECRET_ACCESS_KEY must be at least 40 chars to match the real-key length floor",
	)
}

func TestAWSRecipe_RegionIsAValidAWSRegion(t *testing.T) {
	lines := recipes.AWS{}.Generate()
	byKey := linesByKey(t, lines)
	region := byKey["AWS_REGION"].Value
	require.Regexp(
		t,
		`^[a-z]{2}-[a-z]+-\d+$`,
		region,
		"AWS_REGION must match the canonical AWS region pattern (xx-name-n)",
	)
}

func TestAWSRecipe_HasLeadingComment(t *testing.T) {
	lines := recipes.AWS{}.Generate()
	require.NotEmpty(t, lines)
	require.NotEmpty(
		t,
		lines[0].Comment,
		"AWS recipe must begin with a comment for bait realism",
	)
	require.Empty(t, lines[0].Key, "comment line must not carry a Key/Value")
}

func TestAWSRecipe_DistinctInvocationsProduceDistinctSecrets(t *testing.T) {
	seen := make(map[string]struct{})
	for range 20 {
		lines := recipes.AWS{}.Generate()
		byKey := linesByKey(t, lines)
		seen[byKey["AWS_ACCESS_KEY_ID"].Value] = struct{}{}
	}
	require.Greater(
		t,
		len(seen),
		18,
		"20 invocations should produce near-20 distinct access keys",
	)
}
