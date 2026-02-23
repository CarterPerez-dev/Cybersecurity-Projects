// ©AngelaMos | 2026
// builtin.go

package rules

import (
	"regexp"

	"github.com/CarterPerez-dev/portia/pkg/types"
)

func ptr(f float64) *float64 { return &f }

func RegisterBuiltins(reg *Registry) {
	for _, r := range builtinRules {
		reg.Register(r)
	}
}

var builtinRules = []*types.Rule{
	{
		ID:          "aws-access-key-id",
		Description: "AWS Access Key ID",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"AKIA"},
		Pattern: regexp.MustCompile(
			`\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "aws-secret-access-key",
		Description: "AWS Secret Access Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"aws_secret", "aws_access", "secret_access"},
		Pattern: regexp.MustCompile(
			`(?i)(?:aws_secret_access_key|aws_secret|secret_access)` +
				`[\s=:'"]+([A-Za-z0-9/+=]{40})\b`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "aws-session-token",
		Description: "AWS Session Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"aws_session_token"},
		Pattern: regexp.MustCompile(
			`(?i)aws_session_token[\s=:'"]+` +
				`([A-Za-z0-9/+=]{100,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "github-pat-fine",
		Description: "GitHub Fine-Grained Personal Access Token",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"github_pat_"},
		Pattern: regexp.MustCompile(
			`\b(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "github-pat-classic",
		Description: "GitHub Personal Access Token (Classic)",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"ghp_"},
		Pattern: regexp.MustCompile(
			`\b(ghp_[a-zA-Z0-9]{36})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "github-oauth-token",
		Description: "GitHub OAuth Access Token",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"gho_"},
		Pattern: regexp.MustCompile(
			`\b(gho_[a-zA-Z0-9]{36})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "github-app-token",
		Description: "GitHub App Installation Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"ghs_"},
		Pattern: regexp.MustCompile(
			`\b(ghs_[a-zA-Z0-9]{36})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "github-refresh-token",
		Description: "GitHub Refresh Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"ghr_"},
		Pattern: regexp.MustCompile(
			`\b(ghr_[a-zA-Z0-9]{36})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "gitlab-pat",
		Description: "GitLab Personal Access Token",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"glpat-"},
		Pattern: regexp.MustCompile(
			`\b(glpat-[a-zA-Z0-9\-_]{20,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "gitlab-pipeline-trigger",
		Description: "GitLab Pipeline Trigger Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"glptt-"},
		Pattern: regexp.MustCompile(
			`\b(glptt-[a-zA-Z0-9]{40})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "gitlab-runner-token",
		Description: "GitLab Runner Registration Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"glrt-"},
		Pattern: regexp.MustCompile(
			`\b(glrt-[a-zA-Z0-9\-_]{20,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "gcp-api-key",
		Description: "Google Cloud Platform API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"AIza"},
		Pattern: regexp.MustCompile(
			`\b(AIza[0-9A-Za-z\-_]{35})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "gcp-service-account",
		Description: "GCP Service Account Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"service_account", "private_key_id"},
		Pattern: regexp.MustCompile(
			`"type"\s*:\s*"service_account"`,
		),
		SecretType: types.SecretTypePrivateKey,
	},
	{
		ID:          "gcp-oauth-client-secret",
		Description: "Google OAuth Client Secret",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"GOCSPX-"},
		Pattern: regexp.MustCompile(
			`\b(GOCSPX-[a-zA-Z0-9\-_]{28})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "azure-client-secret",
		Description: "Azure Active Directory Client Secret",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"azure", "client_secret"},
		Pattern: regexp.MustCompile(
			`(?i)(?:client_secret|azure[_.]?secret)` +
				`[\s=:'"]+([a-zA-Z0-9~._\-]{34,})\b`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "azure-storage-key",
		Description: "Azure Storage Account Access Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"AccountKey="},
		Pattern: regexp.MustCompile(
			`AccountKey=([a-zA-Z0-9+/=]{88})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "azure-connection-string",
		Description: "Azure SQL Connection String",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"Server=tcp:", ".database.windows.net"},
		Pattern: regexp.MustCompile(
			`Server=tcp:[^;]+\.database\.windows\.net[^;]*;` +
				`[^"'\s]*Password=[^;'"]+`,
		),
		SecretType: types.SecretTypeConnectionString,
	},
	{
		ID:          "slack-bot-token",
		Description: "Slack Bot Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"xoxb-"},
		Pattern: regexp.MustCompile(
			`\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-` +
				`[a-zA-Z0-9]{24,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "slack-user-token",
		Description: "Slack User Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"xoxp-"},
		Pattern: regexp.MustCompile(
			`\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-` +
				`[0-9]{10,13}-[a-f0-9]{32})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "slack-webhook",
		Description: "Slack Webhook URL",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"hooks.slack.com"},
		Pattern: regexp.MustCompile(
			`(https://hooks\.slack\.com/services/` +
				`T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24})`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "slack-app-token",
		Description: "Slack App-Level Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"xapp-"},
		Pattern: regexp.MustCompile(
			`\b(xapp-[0-9]-[A-Z0-9]{10,}-` +
				`[0-9]{10,}-[a-zA-Z0-9]{64})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "stripe-live-secret",
		Description: "Stripe Live Secret Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"sk_live_"},
		Pattern: regexp.MustCompile(
			`\b(sk_live_[a-zA-Z0-9]{24,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "stripe-live-restricted",
		Description: "Stripe Live Restricted Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"rk_live_"},
		Pattern: regexp.MustCompile(
			`\b(rk_live_[a-zA-Z0-9]{24,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "stripe-test-secret",
		Description: "Stripe Test Secret Key",
		Severity:    types.SeverityLow,
		Keywords:    []string{"sk_test_"},
		Pattern: regexp.MustCompile(
			`\b(sk_test_[a-zA-Z0-9]{24,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "stripe-webhook-secret",
		Description: "Stripe Webhook Signing Secret",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"whsec_"},
		Pattern: regexp.MustCompile(
			`\b(whsec_[a-zA-Z0-9]{32,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "twilio-api-key",
		Description: "Twilio API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"SK", "twilio"},
		Pattern: regexp.MustCompile(
			`\b(SK[0-9a-fA-F]{32})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "twilio-account-sid",
		Description: "Twilio Account SID",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"twilio", "AC"},
		Pattern: regexp.MustCompile(
			`\b(AC[0-9a-fA-F]{32})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "sendgrid-api-key",
		Description: "SendGrid API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"SG."},
		Pattern: regexp.MustCompile(
			`\b(SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "mailchimp-api-key",
		Description: "Mailchimp API Key",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"mailchimp", "-us"},
		Pattern: regexp.MustCompile(
			`\b([0-9a-f]{32}-us[0-9]{1,2})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "shopify-access-token",
		Description: "Shopify Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"shpat_"},
		Pattern: regexp.MustCompile(
			`\b(shpat_[a-fA-F0-9]{32})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "shopify-custom-app",
		Description: "Shopify Custom App Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"shpca_"},
		Pattern: regexp.MustCompile(
			`\b(shpca_[a-fA-F0-9]{32})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "shopify-private-app",
		Description: "Shopify Private App Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"shppa_"},
		Pattern: regexp.MustCompile(
			`\b(shppa_[a-fA-F0-9]{32})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "shopify-shared-secret",
		Description: "Shopify Shared Secret",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"shpss_"},
		Pattern: regexp.MustCompile(
			`\b(shpss_[a-fA-F0-9]{32})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "npm-access-token",
		Description: "NPM Access Token",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"npm_"},
		Pattern: regexp.MustCompile(
			`\b(npm_[a-zA-Z0-9]{36})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "pypi-api-token",
		Description: "PyPI API Token",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"pypi-"},
		Pattern: regexp.MustCompile(
			`\b(pypi-[a-zA-Z0-9\-_]{100,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "rubygems-api-key",
		Description: "RubyGems API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"rubygems_"},
		Pattern: regexp.MustCompile(
			`\b(rubygems_[a-f0-9]{48})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "docker-hub-pat",
		Description: "Docker Hub Personal Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"dckr_pat_"},
		Pattern: regexp.MustCompile(
			`\b(dckr_pat_[a-zA-Z0-9\-_]{27,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "jwt-token",
		Description: "JSON Web Token",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"eyJ"},
		Pattern: regexp.MustCompile(
			`\b(eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+` +
				`\.[a-zA-Z0-9\-_]+)\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "ssh-private-key-rsa",
		Description: "RSA Private Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"BEGIN RSA PRIVATE KEY"},
		Pattern: regexp.MustCompile(
			`-----BEGIN RSA PRIVATE KEY-----`,
		),
		SecretType: types.SecretTypePrivateKey,
	},
	{
		ID:          "ssh-private-key-openssh",
		Description: "OpenSSH Private Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"BEGIN OPENSSH PRIVATE KEY"},
		Pattern: regexp.MustCompile(
			`-----BEGIN OPENSSH PRIVATE KEY-----`,
		),
		SecretType: types.SecretTypePrivateKey,
	},
	{
		ID:          "ssh-private-key-ec",
		Description: "EC Private Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"BEGIN EC PRIVATE KEY"},
		Pattern: regexp.MustCompile(
			`-----BEGIN EC PRIVATE KEY-----`,
		),
		SecretType: types.SecretTypePrivateKey,
	},
	{
		ID:          "ssh-private-key-dsa",
		Description: "DSA Private Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"BEGIN DSA PRIVATE KEY"},
		Pattern: regexp.MustCompile(
			`-----BEGIN DSA PRIVATE KEY-----`,
		),
		SecretType: types.SecretTypePrivateKey,
	},
	{
		ID:          "pgp-private-key",
		Description: "PGP Private Key Block",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"BEGIN PGP PRIVATE KEY"},
		Pattern: regexp.MustCompile(
			`-----BEGIN PGP PRIVATE KEY BLOCK-----`,
		),
		SecretType: types.SecretTypePrivateKey,
	},
	{
		ID:          "private-key-pkcs8",
		Description: "PKCS8 Private Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"BEGIN PRIVATE KEY"},
		Pattern: regexp.MustCompile(
			`-----BEGIN PRIVATE KEY-----`,
		),
		SecretType: types.SecretTypePrivateKey,
	},
	{
		ID:          "generic-password",
		Description: "Password in Assignment",
		Severity:    types.SeverityHigh,
		Keywords: []string{
			"password", "passwd", "pwd",
		},
		Pattern: regexp.MustCompile(
			`(?i)(?:password|passwd|pwd)\s*` +
				`[:=]\s*['"]([^'"]{8,})['"]`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.0),
		SecretType:  types.SecretTypePassword,
	},
	{
		ID:          "generic-secret",
		Description: "Secret in Assignment",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"secret"},
		Pattern: regexp.MustCompile(
			`(?i)(?:secret|secret_key|secretkey)\s*` +
				`[:=]\s*['"]([^'"]{8,})['"]`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.0),
		SecretType:  types.SecretTypePassword,
	},
	{
		ID:          "generic-api-key",
		Description: "API Key in Assignment",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"api_key", "apikey"},
		Pattern: regexp.MustCompile(
			`(?i)(?:api_?key|api_?secret)\s*` +
				`[:=]\s*['"]([^'"]{16,})['"]`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "generic-token",
		Description: "Token in Assignment",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"token", "auth_token", "access_token"},
		Pattern: regexp.MustCompile(
			`(?i)(?:token|auth_token|access_token|bearer)\s*` +
				`[:=]\s*['"]([^'"]{16,})['"]`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "postgres-connection",
		Description: "PostgreSQL Connection String",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"postgres://", "postgresql://"},
		Pattern: regexp.MustCompile(
			`(postgres(?:ql)?://[^\s'"}{]+:` +
				`[^\s'"}{@]+@[^\s'"}{]+)`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeConnectionString,
	},
	{
		ID:          "mysql-connection",
		Description: "MySQL Connection String",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"mysql://"},
		Pattern: regexp.MustCompile(
			`(mysql://[^\s'"}{]+:[^\s'"}{@]+@[^\s'"}{]+)`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeConnectionString,
	},
	{
		ID:          "mongodb-connection",
		Description: "MongoDB Connection String",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"mongodb+srv://", "mongodb://"},
		Pattern: regexp.MustCompile(
			`(mongodb(?:\+srv)?://[^\s'"}{]+:` +
				`[^\s'"}{@]+@[^\s'"}{]+)`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeConnectionString,
	},
	{
		ID:          "redis-connection",
		Description: "Redis Connection String",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"redis://"},
		Pattern: regexp.MustCompile(
			`(redis://[^\s'"}{]+:[^\s'"}{@]+@[^\s'"}{]+)`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeConnectionString,
	},
	{
		ID:          "firebase-url",
		Description: "Firebase Database URL with Auth",
		Severity:    types.SeverityHigh,
		Keywords:    []string{".firebaseio.com"},
		Pattern: regexp.MustCompile(
			`(https://[a-z0-9\-]+\.firebaseio\.com[^\s'"]*` +
				`auth=[^\s'"&]+)`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "hashicorp-vault-token",
		Description: "HashiCorp Vault Token",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"hvs.", "hvb.", "hvr."},
		Pattern: regexp.MustCompile(
			`\b(hv[sbr]\.[a-zA-Z0-9\-_]{24,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "hashicorp-terraform-token",
		Description: "HashiCorp Terraform Cloud Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"atlasv1"},
		Pattern: regexp.MustCompile(
			`\b([a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_]{60,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "datadog-api-key",
		Description: "Datadog API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"datadog", "dd_api_key"},
		Pattern: regexp.MustCompile(
			`(?i)(?:datadog|dd)[\s_-]*api[\s_-]*key\s*[:=]\s*` +
				`['"]?([a-f0-9]{32})['"]?\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "newrelic-license-key",
		Description: "New Relic License Key",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"newrelic", "new_relic", "license_key"},
		Pattern: regexp.MustCompile(
			`(?i)(?:new[\s_-]*relic|nr)[\s_-]*(?:license|insert)` +
				`[\s_-]*key\s*[:=]\s*['"]?([a-f0-9]{40})['"]?\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "telegram-bot-token",
		Description: "Telegram Bot Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"telegram", "bot"},
		Pattern: regexp.MustCompile(
			`\b([0-9]{8,10}:[A-Za-z0-9_\-]{35})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "discord-bot-token",
		Description: "Discord Bot Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"discord"},
		Pattern: regexp.MustCompile(
			`\b([MN][A-Za-z0-9]{23,}\.` +
				`[A-Za-z0-9\-_]{6}\.` +
				`[A-Za-z0-9\-_]{27,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "discord-webhook",
		Description: "Discord Webhook URL",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"discord.com/api/webhooks"},
		Pattern: regexp.MustCompile(
			`(https://discord(?:app)?\.com/api/webhooks/` +
				`[0-9]+/[a-zA-Z0-9\-_]+)`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "heroku-api-key",
		Description: "Heroku API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"heroku", "HEROKU_API_KEY"},
		Pattern: regexp.MustCompile(
			`(?i)heroku[\s_-]*api[\s_-]*key\s*[:=]\s*` +
				`['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-` +
				`[0-9a-f]{4}-[0-9a-f]{12})['"]?`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "supabase-service-key",
		Description: "Supabase Service Role Key",
		Severity:    types.SeverityCritical,
		Keywords: []string{
			"supabase_service_role",
			"service_role_key",
			"SUPABASE_SERVICE",
		},
		Pattern: regexp.MustCompile(
			`(?i)supabase[\s_-]*service[\s_-]*role[\s_-]*key?\s*[:=]\s*` +
				`['"]?(eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)['"]?`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "digitalocean-pat",
		Description: "DigitalOcean Personal Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"dop_v1_"},
		Pattern: regexp.MustCompile(
			`\b(dop_v1_[a-f0-9]{64})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "digitalocean-oauth",
		Description: "DigitalOcean OAuth Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"doo_v1_"},
		Pattern: regexp.MustCompile(
			`\b(doo_v1_[a-f0-9]{64})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "digitalocean-refresh-token",
		Description: "DigitalOcean Refresh Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"dor_v1_"},
		Pattern: regexp.MustCompile(
			`\b(dor_v1_[a-f0-9]{64})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "linear-api-key",
		Description: "Linear API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"lin_api_"},
		Pattern: regexp.MustCompile(
			`\b(lin_api_[a-zA-Z0-9]{40})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "openai-api-key",
		Description: "OpenAI API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"sk-"},
		Pattern: regexp.MustCompile(
			`\b(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "openai-api-key-project",
		Description: "OpenAI Project API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"sk-proj-"},
		Pattern: regexp.MustCompile(
			`\b(sk-proj-[a-zA-Z0-9\-_]{80,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "anthropic-api-key",
		Description: "Anthropic API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"sk-ant-"},
		Pattern: regexp.MustCompile(
			`\b(sk-ant-[a-zA-Z0-9\-_]{80,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "age-secret-key",
		Description: "Age Encryption Secret Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"AGE-SECRET-KEY-"},
		Pattern: regexp.MustCompile(
			`\b(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypePrivateKey,
	},
	{
		ID:          "vault-batch-token",
		Description: "Vault Batch Token",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"hvb."},
		Pattern: regexp.MustCompile(
			`\b(hvb\.[a-zA-Z0-9\-_]{100,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "doppler-token",
		Description: "Doppler Service Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"dp.st."},
		Pattern: regexp.MustCompile(
			`\b(dp\.st\.[a-zA-Z0-9\-_]{40,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "infracost-api-key",
		Description: "Infracost API Token",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"ico-"},
		Pattern: regexp.MustCompile(
			`\b(ico-[a-zA-Z0-9]{32})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "prefect-api-token",
		Description: "Prefect API Token",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"pnu_"},
		Pattern: regexp.MustCompile(
			`\b(pnu_[a-zA-Z0-9]{36})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "pulumi-access-token",
		Description: "Pulumi Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"pul-"},
		Pattern: regexp.MustCompile(
			`\b(pul-[a-f0-9]{40})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "databricks-token",
		Description: "Databricks Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"dapi"},
		Pattern: regexp.MustCompile(
			`\b(dapi[a-f0-9]{32})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "confluent-api-key",
		Description: "Confluent Access Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"confluent"},
		Pattern: regexp.MustCompile(
			`(?i)confluent[\s_-]*(?:api[\s_-]*)?(?:key|secret)\s*` +
				`[:=]\s*['"]?([a-zA-Z0-9]{16})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "grafana-api-key",
		Description: "Grafana API Key or Service Account Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"glsa_", "eyJr"},
		Pattern: regexp.MustCompile(
			`\b(glsa_[a-zA-Z0-9]{32}_[a-f0-9]{8})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "grafana-cloud-token",
		Description: "Grafana Cloud API Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"glc_"},
		Pattern: regexp.MustCompile(
			`\b(glc_[a-zA-Z0-9\-_+=]{32,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "cloudflare-api-key",
		Description: "Cloudflare API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"cloudflare"},
		Pattern: regexp.MustCompile(
			`(?i)cloudflare[\s_-]*(?:api[\s_-]*)?key\s*[:=]\s*` +
				`['"]?([a-f0-9]{37})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "cloudflare-api-token",
		Description: "Cloudflare API Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"cloudflare"},
		Pattern: regexp.MustCompile(
			`(?i)cloudflare[\s_-]*(?:api[\s_-]*)?token\s*[:=]\s*` +
				`['"]?([a-zA-Z0-9_\-]{40})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "huggingface-token",
		Description: "Hugging Face Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"hf_"},
		Pattern: regexp.MustCompile(
			`\b(hf_[a-zA-Z0-9]{34,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "vercel-token",
		Description: "Vercel Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"vercel"},
		Pattern: regexp.MustCompile(
			`(?i)vercel[\s_-]*(?:api[\s_-]*)?token\s*[:=]\s*` +
				`['"]?([a-zA-Z0-9]{24})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "netlify-token",
		Description: "Netlify Personal Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"nfp_"},
		Pattern: regexp.MustCompile(
			`\b(nfp_[a-zA-Z0-9]{40,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "postman-api-key",
		Description: "Postman API Key",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"PMAK-"},
		Pattern: regexp.MustCompile(
			`\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "figma-pat",
		Description: "Figma Personal Access Token",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"figd_"},
		Pattern: regexp.MustCompile(
			`\b(figd_[a-zA-Z0-9\-_]{40,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "flyio-token",
		Description: "Fly.io Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"fo1_"},
		Pattern: regexp.MustCompile(
			`\b(fo1_[a-zA-Z0-9_\-]{40,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "planetscale-token",
		Description: "PlanetScale Service Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"pscale_tkn_"},
		Pattern: regexp.MustCompile(
			`\b(pscale_tkn_[a-zA-Z0-9\-_]{40,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "planetscale-password",
		Description: "PlanetScale Database Password",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"pscale_pw_"},
		Pattern: regexp.MustCompile(
			`\b(pscale_pw_[a-zA-Z0-9\-_]{40,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypePassword,
	},
	{
		ID:          "replicate-api-token",
		Description: "Replicate API Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"r8_"},
		Pattern: regexp.MustCompile(
			`\b(r8_[a-zA-Z0-9]{38,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "sentry-auth-token",
		Description: "Sentry Auth Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"sntrys_"},
		Pattern: regexp.MustCompile(
			`\b(sntrys_[a-zA-Z0-9\-_]{60,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "atlassian-api-token",
		Description: "Atlassian/Jira API Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"ATATT"},
		Pattern: regexp.MustCompile(
			`\b(ATATT[a-zA-Z0-9\-_]{50,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "mapbox-public-token",
		Description: "Mapbox Public Token",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"pk.eyJ"},
		Pattern: regexp.MustCompile(
			`\b(pk\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "mapbox-secret-token",
		Description: "Mapbox Secret Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"sk.eyJ"},
		Pattern: regexp.MustCompile(
			`\b(sk\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "render-api-key",
		Description: "Render API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"rnd_"},
		Pattern: regexp.MustCompile(
			`\b(rnd_[a-zA-Z0-9]{32,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "facebook-app-secret",
		Description: "Facebook/Meta App Secret",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"facebook", "fb_secret", "app_secret"},
		Pattern: regexp.MustCompile(
			`(?i)(?:facebook|fb)[\s_-]*(?:app[\s_-]*)?secret\s*[:=]\s*` +
				`['"]?([a-f0-9]{32})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "twitter-api-key",
		Description: "Twitter/X API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"twitter", "x_api_key"},
		Pattern: regexp.MustCompile(
			`(?i)(?:twitter|x)[\s_-]*(?:api[\s_-]*)?(?:key|secret)\s*[:=]\s*` +
				`['"]?([a-zA-Z0-9]{25,50})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "discord-client-secret",
		Description: "Discord Client Secret",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"discord", "client_secret"},
		Pattern: regexp.MustCompile(
			`(?i)discord[\s_-]*client[\s_-]*secret\s*[:=]\s*` +
				`['"]?([a-zA-Z0-9\-_]{32})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "okta-api-token",
		Description: "Okta API Token",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"okta", "ssws"},
		Pattern: regexp.MustCompile(
			`(?i)(?:okta[\s_-]*(?:api[\s_-]*)?token|SSWS)\s*[:=]\s*` +
				`['"]?([a-zA-Z0-9\-_]{30,})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "launchdarkly-sdk-key",
		Description: "LaunchDarkly SDK Key",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"launchdarkly", "launch_darkly"},
		Pattern: regexp.MustCompile(
			`\b(sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "launchdarkly-api-key",
		Description: "LaunchDarkly API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"launchdarkly", "launch_darkly"},
		Pattern: regexp.MustCompile(
			`\b(api-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "algolia-api-key",
		Description: "Algolia API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"algolia"},
		Pattern: regexp.MustCompile(
			`(?i)algolia[\s_-]*(?:api[\s_-]*)?(?:key|secret)\s*[:=]\s*` +
				`['"]?([a-f0-9]{32})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "alibaba-cloud-access-key",
		Description: "Alibaba Cloud Access Key ID",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"LTAI"},
		Pattern: regexp.MustCompile(
			`\b(LTAI[a-zA-Z0-9]{20})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "square-access-token",
		Description: "Square Production Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"sq0atp-"},
		Pattern: regexp.MustCompile(
			`\b(sq0atp-[a-zA-Z0-9\-_]{22})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "square-app-secret",
		Description: "Square Application Secret",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"sq0csp-"},
		Pattern: regexp.MustCompile(
			`\b(sq0csp-[a-zA-Z0-9\-_]{43})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "razorpay-key-id",
		Description: "Razorpay API Key ID",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"rzp_live_", "rzp_test_"},
		Pattern: regexp.MustCompile(
			`\b(rzp_(?:live|test)_[a-zA-Z0-9]{14})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "mailgun-api-key",
		Description: "Mailgun Private API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"mailgun"},
		Pattern: regexp.MustCompile(
			`(?i)mailgun[\s_-]*(?:api[\s_-]*)?key\s*[:=]\s*['"]?(key-[a-f0-9]{32})['"]?`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "resend-api-key",
		Description: "Resend API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"re_"},
		Pattern: regexp.MustCompile(
			`\b(re_[a-zA-Z0-9_]{36,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "groq-api-key",
		Description: "Groq API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"gsk_"},
		Pattern: regexp.MustCompile(
			`\b(gsk_[a-zA-Z0-9]{40,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "perplexity-api-key",
		Description: "Perplexity AI API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"pplx-"},
		Pattern: regexp.MustCompile(
			`\b(pplx-[a-f0-9]{48})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "1password-service-account-token",
		Description: "1Password Service Account Token",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"ops_"},
		Pattern: regexp.MustCompile(
			`\b(ops_[a-zA-Z0-9+/=\-_]{43,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "github-actions-token",
		Description: "GitHub Actions Runtime Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"gha_"},
		Pattern: regexp.MustCompile(
			`\b(gha_[a-zA-Z0-9]{36})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "circleci-api-token",
		Description: "CircleCI Personal API Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"CCIPAT_"},
		Pattern: regexp.MustCompile(
			`\b(CCIPAT_[a-zA-Z0-9_]{40,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "sonarqube-token",
		Description: "SonarQube / SonarCloud Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"squ_"},
		Pattern: regexp.MustCompile(
			`\b(squ_[a-f0-9]{40})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "posthog-project-api-key",
		Description: "PostHog Project API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"phc_"},
		Pattern: regexp.MustCompile(
			`\b(phc_[a-zA-Z0-9]{43,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "axiom-api-token",
		Description: "Axiom API Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"xaat-"},
		Pattern: regexp.MustCompile(
			`\b(xaat-[a-zA-Z0-9\-]{36,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "dynatrace-api-token",
		Description: "Dynatrace API Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"dynatrace"},
		Pattern: regexp.MustCompile(
			`\b(dt0[a-zA-Z]{2}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{64})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "cloudinary-url",
		Description: "Cloudinary API URL with Credentials",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"cloudinary://"},
		Pattern: regexp.MustCompile(
			`(cloudinary://[0-9]+:[a-zA-Z0-9_\-]+@[a-z][a-z0-9_\-]+)`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeConnectionString,
	},
	{
		ID:          "firebase-fcm-server-key",
		Description: "Firebase Cloud Messaging Server Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"AAAA"},
		Pattern: regexp.MustCompile(
			`\b(AAAA[a-zA-Z0-9_\-]{7}:APA91[a-zA-Z0-9_\-]{100,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "microsoft-teams-webhook",
		Description: "Microsoft Teams Incoming Webhook URL",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"webhook.office.com"},
		Pattern: regexp.MustCompile(
			`(https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9\-@/]{60,})`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "hubspot-private-app-token",
		Description: "HubSpot Private App Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"hubspot"},
		Pattern: regexp.MustCompile(
			`\b(pat-[a-z]{2,3}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-` +
				`[a-f0-9]{4}-[a-f0-9]{12})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "planetscale-deploy-token",
		Description: "PlanetScale Deploy Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"pscale_deploy_"},
		Pattern: regexp.MustCompile(
			`\b(pscale_deploy_[a-zA-Z0-9\-_]{40,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "doppler-cli-token",
		Description: "Doppler CLI Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"dp.ct."},
		Pattern: regexp.MustCompile(
			`\b(dp\.ct\.[a-zA-Z0-9\-_]{40,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "brevo-api-key",
		Description: "Brevo (Sendinblue) API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"xkeysib-"},
		Pattern: regexp.MustCompile(
			`\b(xkeysib-[a-f0-9]{32,}-[a-zA-Z0-9_]{8,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "neon-database-url",
		Description: "Neon Database Connection String",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"neon.tech"},
		Pattern: regexp.MustCompile(
			`(postgres(?:ql)?://[^\s'"}{]+:[^\s'"}{@]+@[^\s'"}{]*neon\.tech/[^\s'"}{]+)`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeConnectionString,
	},
	{
		ID:          "braintree-access-token",
		Description: "Braintree Production Access Token",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"braintree"},
		Pattern: regexp.MustCompile(
			`\b(access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "bitbucket-access-token",
		Description: "Bitbucket HTTP Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"ATBB"},
		Pattern: regexp.MustCompile(
			`\b(ATBB[a-zA-Z0-9]{32,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "turso-auth-token",
		Description: "Turso Database Auth Token",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"turso"},
		Pattern: regexp.MustCompile(
			`(?i)turso[\s_-]*(?:auth[\s_-]*)?token\s*[:=]\s*` +
				`['"]?(eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)['"]?`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "twilio-auth-token",
		Description: "Twilio Auth Token",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"twilio", "auth_token"},
		Pattern: regexp.MustCompile(
			`(?i)twilio[\s_-]*auth[\s_-]*token\s*[:=]\s*['"]?([a-f0-9]{32})['"]?`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "pagerduty-api-key",
		Description: "PagerDuty API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"pagerduty"},
		Pattern: regexp.MustCompile(
			`(?i)pager[\s_-]*duty[\s_-]*(?:api[\s_-]*)?(?:key|token)\s*[:=]\s*` +
				`['"]?([a-zA-Z0-9_\-+]{20,})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "snyk-api-token",
		Description: "Snyk API Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"snyk"},
		Pattern: regexp.MustCompile(
			`(?i)snyk[\s_-]*(?:api[\s_-]*)?token\s*[:=]\s*` +
				`['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "honeycomb-api-key",
		Description: "Honeycomb API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"honeycomb"},
		Pattern: regexp.MustCompile(
			`(?i)honeycomb[\s_-]*(?:api[\s_-]*)?(?:key|token)\s*[:=]\s*['"]?([a-zA-Z0-9]{22,64})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "segment-write-key",
		Description: "Segment Write Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"segment", "write_key"},
		Pattern: regexp.MustCompile(
			`(?i)segment[\s_-]*write[\s_-]*key\s*[:=]\s*['"]?([a-zA-Z0-9]{32,})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "rollbar-access-token",
		Description: "Rollbar Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"rollbar"},
		Pattern: regexp.MustCompile(
			`(?i)rollbar[\s_-]*(?:access[\s_-]*)?token\s*[:=]\s*['"]?([a-f0-9]{32})['"]?`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "zendesk-api-token",
		Description: "Zendesk API Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"zendesk"},
		Pattern: regexp.MustCompile(
			`(?i)zendesk[\s_-]*(?:api[\s_-]*)?token\s*[:=]\s*['"]?([a-zA-Z0-9]{40,})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "hetzner-api-token",
		Description: "Hetzner Cloud API Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"hetzner"},
		Pattern: regexp.MustCompile(
			`(?i)hetzner[\s_-]*(?:api[\s_-]*)?(?:key|token)\s*[:=]\s*['"]?([a-zA-Z0-9]{64})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "linode-api-token",
		Description: "Linode API Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"linode"},
		Pattern: regexp.MustCompile(
			`(?i)linode[\s_-]*(?:api[\s_-]*)?(?:key|token)\s*[:=]\s*['"]?([a-zA-Z0-9]{64})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "vultr-api-key",
		Description: "Vultr API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"vultr"},
		Pattern: regexp.MustCompile(
			`(?i)vultr[\s_-]*(?:api[\s_-]*)?(?:key|token)\s*[:=]\s*` +
				`['"]?([A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12})['"]?`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "buildkite-api-token",
		Description: "Buildkite API Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"buildkite"},
		Pattern: regexp.MustCompile(
			`(?i)buildkite[\s_-]*(?:api[\s_-]*)?(?:key|token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{20,})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "mixpanel-secret",
		Description: "Mixpanel Project Secret",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"mixpanel"},
		Pattern: regexp.MustCompile(
			`(?i)mixpanel[\s_-]*(?:api[\s_-]*)?secret\s*[:=]\s*['"]?([a-f0-9]{32})['"]?`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "freshdesk-api-key",
		Description: "Freshdesk API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"freshdesk"},
		Pattern: regexp.MustCompile(
			`(?i)freshdesk[\s_-]*(?:api[\s_-]*)?key\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "elastic-api-key",
		Description: "Elasticsearch API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"elastic", "elasticsearch"},
		Pattern: regexp.MustCompile(
			`(?i)elastic(?:search)?[\s_-]*(?:api[\s_-]*)?(?:key|token)\s*[:=]\s*` +
				`['"]?([a-zA-Z0-9+/=]{32,})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "coinbase-api-key",
		Description: "Coinbase API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"coinbase"},
		Pattern: regexp.MustCompile(
			`(?i)coinbase[\s_-]*(?:api[\s_-]*)?(?:key|secret|token)\s*[:=]\s*` +
				`['"]?([a-zA-Z0-9_\-]{32,})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "supabase-anon-key",
		Description: "Supabase Anonymous Key",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"supabase_anon_key", "SUPABASE_ANON"},
		Pattern: regexp.MustCompile(
			`(?i)supabase[\s_-]*anon[\s_-]*key\s*[:=]\s*` +
				`['"]?(eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)['"]?`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "ibm-cloud-api-key",
		Description: "IBM Cloud API Key",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"ibm", "ibmcloud"},
		Pattern: regexp.MustCompile(
			`(?i)ibm(?:cloud)?[\s_-]*(?:api[\s_-]*)?key\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{44})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeAPIKey,
	},
	{
		ID:          "upstash-rest-token",
		Description: "Upstash REST API Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"upstash"},
		Pattern: regexp.MustCompile(
			`(?i)upstash[\s_-]*(?:rest[\s_-]*)?(?:token|url)\s*[:=]\s*['"]?([a-zA-Z0-9+/=_\-]{80,})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "postmark-server-token",
		Description: "Postmark Server Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"postmark"},
		Pattern: regexp.MustCompile(
			`(?i)postmark[\s_-]*(?:server[\s_-]*)?(?:api[\s_-]*)?token\s*[:=]\s*` +
				`['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "contentful-delivery-token",
		Description: "Contentful Content Delivery API Token",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"contentful"},
		Pattern: regexp.MustCompile(
			`(?i)contentful[\s_-]*(?:delivery[\s_-]*)?(?:api[\s_-]*)?(?:key|token)\s*[:=]\s*` +
				`['"]?([a-zA-Z0-9_\-]{43,})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "intercom-access-token",
		Description: "Intercom Access Token",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"intercom"},
		Pattern: regexp.MustCompile(
			`(?i)intercom[\s_-]*(?:access[\s_-]*)?(?:api[\s_-]*)?(?:key|token)\s*[:=]\s*` +
				`['"]?([a-zA-Z0-9_\-]{60,})['"]?`,
		),
		SecretGroup: 1,
		Entropy:     ptr(3.5),
		SecretType:  types.SecretTypeToken,
	},
	{
		ID:          "amplitude-api-key",
		Description: "Amplitude API Key",
		Severity:    types.SeverityMedium,
		Keywords:    []string{"amplitude"},
		Pattern: regexp.MustCompile(
			`(?i)amplitude[\s_-]*(?:api[\s_-]*)?(?:key|secret)\s*[:=]\s*['"]?([a-f0-9]{32})['"]?`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	},
}
