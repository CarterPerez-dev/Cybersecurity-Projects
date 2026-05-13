// ©AngelaMos | 2026
// stripe_test.go

package recipes_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/envfile/recipes"
)

func TestStripeRecipe_Name(t *testing.T) {
	require.Equal(t, "stripe", recipes.Stripe{}.Name())
}

func TestStripeRecipe_GeneratesExpectedKeys(t *testing.T) {
	lines := recipes.Stripe{}.Generate()
	byKey := linesByKey(t, lines)

	for _, key := range []string{
		"STRIPE_SECRET_KEY",
		"STRIPE_PUBLISHABLE_KEY",
		"STRIPE_WEBHOOK_SECRET",
	} {
		_, ok := byKey[key]
		require.True(t, ok, "Stripe recipe must emit %s", key)
	}
}

func TestStripeRecipe_SecretKeyMatchesLiveFormat(t *testing.T) {
	lines := recipes.Stripe{}.Generate()
	byKey := linesByKey(t, lines)
	require.Regexp(
		t,
		`^sk_live_[A-Za-z0-9]{24}$`,
		byKey["STRIPE_SECRET_KEY"].Value,
	)
}

func TestStripeRecipe_PublishableKeyMatchesLiveFormat(t *testing.T) {
	lines := recipes.Stripe{}.Generate()
	byKey := linesByKey(t, lines)
	require.Regexp(
		t,
		`^pk_live_[A-Za-z0-9]{24}$`,
		byKey["STRIPE_PUBLISHABLE_KEY"].Value,
	)
}

func TestStripeRecipe_WebhookSecretMatchesFormat(t *testing.T) {
	lines := recipes.Stripe{}.Generate()
	byKey := linesByKey(t, lines)
	require.Regexp(
		t,
		`^whsec_[A-Za-z0-9]{32}$`,
		byKey["STRIPE_WEBHOOK_SECRET"].Value,
	)
}

func TestStripeRecipe_HasLeadingComment(t *testing.T) {
	lines := recipes.Stripe{}.Generate()
	require.NotEmpty(t, lines)
	require.NotEmpty(t, lines[0].Comment)
	require.Empty(t, lines[0].Key)
}

func TestStripeRecipe_KeysAreDistinct(t *testing.T) {
	lines := recipes.Stripe{}.Generate()
	byKey := linesByKey(t, lines)
	require.NotEqual(
		t,
		byKey["STRIPE_SECRET_KEY"].Value,
		byKey["STRIPE_PUBLISHABLE_KEY"].Value,
		"secret and publishable keys must have different random bodies",
	)
}
