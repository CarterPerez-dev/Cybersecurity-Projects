// ©AngelaMos | 2026
// stripe.go

package recipes

const (
	stripeSecretPrefix      = "sk_live_"
	stripePublishablePrefix = "pk_live_"
	stripeWebhookPrefix     = "whsec_"

	stripeKeyBodyLen     = 24
	stripeWebhookBodyLen = 32
)

type Stripe struct{}

func (Stripe) Name() string { return keyStripe }

func (Stripe) Generate() []EnvLine {
	return []EnvLine{
		{Comment: "Stripe production keys"},
		{
			Key:   "STRIPE_SECRET_KEY",
			Value: stripeSecretPrefix + RandomAlnumMixed(stripeKeyBodyLen),
		},
		{
			Key:   "STRIPE_PUBLISHABLE_KEY",
			Value: stripePublishablePrefix + RandomAlnumMixed(stripeKeyBodyLen),
		},
		{
			Key:   "STRIPE_WEBHOOK_SECRET",
			Value: stripeWebhookPrefix + RandomAlnumMixed(stripeWebhookBodyLen),
		},
	}
}
