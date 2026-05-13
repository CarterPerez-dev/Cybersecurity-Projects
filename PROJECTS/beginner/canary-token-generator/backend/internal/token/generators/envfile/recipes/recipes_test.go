// ©AngelaMos | 2026
// recipes_test.go

package recipes_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/envfile/recipes"
)

func TestGet_KnownKeysReturnRecipes(t *testing.T) {
	for _, name := range []string{"aws", "stripe", "github", "db"} {
		r, ok := recipes.Get(name)
		require.True(t, ok, "Get(%q) must return a recipe", name)
		require.NotNil(t, r)
		require.Equal(t, name, r.Name())
	}
}

func TestGet_UnknownKeyReturnsFalse(t *testing.T) {
	r, ok := recipes.Get("nonexistent")
	require.False(t, ok)
	require.Nil(t, r)
}

func TestAvailableKeys_ReturnsSortedSnapshot(t *testing.T) {
	keys := recipes.AvailableKeys()
	require.Equal(t, []string{"aws", "db", "github", "stripe"}, keys)
}

func TestRandomAlnumUpper_LengthAndAlphabet(t *testing.T) {
	got := recipes.RandomAlnumUpper(20)
	require.Len(t, got, 20)
	require.Regexp(t, `^[A-Z0-9]{20}$`, got)
}

func TestRandomAlnumUpper_ZeroAndNegativeReturnEmpty(t *testing.T) {
	require.Empty(t, recipes.RandomAlnumUpper(0))
	require.Empty(t, recipes.RandomAlnumUpper(-1))
}

func TestRandomAlnumMixed_LengthAndAlphabet(t *testing.T) {
	got := recipes.RandomAlnumMixed(50)
	require.Len(t, got, 50)
	require.Regexp(t, `^[A-Za-z0-9]{50}$`, got)
}

func TestRandomHexLower_LengthAndAlphabet(t *testing.T) {
	got := recipes.RandomHexLower(32)
	require.Len(t, got, 32)
	require.Regexp(t, `^[0-9a-f]{32}$`, got)
}

func TestRandomBase64_DecodesToRequestedBytes(t *testing.T) {
	got := recipes.RandomBase64(30)
	require.NotEmpty(t, got)
	require.Regexp(t, `^[A-Za-z0-9+/]+={0,2}$`, got)
}

func TestRandomBase64_ZeroReturnsEmpty(t *testing.T) {
	require.Empty(t, recipes.RandomBase64(0))
	require.Empty(t, recipes.RandomBase64(-5))
}

func TestRandomChoice_ReturnsOneOf(t *testing.T) {
	choices := []string{"a", "b", "c", "d", "e"}
	for range 50 {
		got := recipes.RandomChoice(choices)
		require.Contains(t, choices, got)
	}
}

func TestRandomChoice_EmptyReturnsEmpty(t *testing.T) {
	require.Empty(t, recipes.RandomChoice(nil))
	require.Empty(t, recipes.RandomChoice([]string{}))
}

func TestRandomChoice_SingleElementAlwaysReturnsIt(t *testing.T) {
	choices := []string{"only"}
	for range 20 {
		require.Equal(t, "only", recipes.RandomChoice(choices))
	}
}

func TestRandomness_RepeatedCallsProduceDistinctValues(t *testing.T) {
	seen := make(map[string]struct{})
	for range 100 {
		seen[recipes.RandomAlnumMixed(20)] = struct{}{}
	}
	require.Greater(
		t,
		len(seen),
		95,
		"crypto/rand should produce near-100 distinct 20-char alnum strings out of 100",
	)
}
