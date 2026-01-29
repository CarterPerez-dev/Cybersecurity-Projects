/*
AngelaMos | 2026
secrets.go
*/

package rules

import (
	"math"
	"regexp"
	"strings"
)

type SecretType string

const (
	SecretTypeGeneric          SecretType = "generic"
	SecretTypeAWSKey           SecretType = "aws_key"
	SecretTypeAWSSecret        SecretType = "aws_secret"
	SecretTypeGCPKey           SecretType = "gcp_key"
	SecretTypeAzureKey         SecretType = "azure_key"
	SecretTypeGitHub           SecretType = "github_token"
	SecretTypeGitLab           SecretType = "gitlab_token"
	SecretTypeSlack            SecretType = "slack_token"
	SecretTypeStripe           SecretType = "stripe_key"
	SecretTypeTwilio           SecretType = "twilio_key"
	SecretTypeSendGrid         SecretType = "sendgrid_key"
	SecretTypeMailgun          SecretType = "mailgun_key"
	SecretTypeNPM              SecretType = "npm_token"
	SecretTypePyPI             SecretType = "pypi_token"
	SecretTypeDockerHub        SecretType = "dockerhub_token"
	SecretTypeSSHKey           SecretType = "ssh_key"
	SecretTypePrivateKey       SecretType = "private_key"
	SecretTypeJWT              SecretType = "jwt"
	SecretTypeBasicAuth        SecretType = "basic_auth"
	SecretTypeBearer           SecretType = "bearer_token"
	SecretTypeAPIKey           SecretType = "api_key"
	SecretTypePassword         SecretType = "password"
	SecretTypeDatabase         SecretType = "database_url"
	SecretTypeConnectionString SecretType = "connection_string"
)

type SecretPattern struct {
	Type        SecretType
	Pattern     *regexp.Regexp
	Description string
}

var SecretPatterns = []SecretPattern{
	// ==================== AWS ====================
	{
		Type: SecretTypeAWSKey,
		Pattern: regexp.MustCompile(
			`(?i)(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`,
		),
		Description: "AWS Access Key ID",
	},
	{
		Type: SecretTypeAWSSecret,
		Pattern: regexp.MustCompile(
			`(?i)aws_?secret_?access_?key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`,
		),
		Description: "AWS Secret Access Key",
	},
	{
		Type: SecretTypeAWSKey,
		Pattern: regexp.MustCompile(
			`(?i)aws_?session_?token\s*[=:]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?`,
		),
		Description: "AWS Session Token",
	},

	// ==================== GCP ====================
	{
		Type: SecretTypeGCPKey,
		Pattern: regexp.MustCompile(
			`(?i)("type"\s*:\s*"service_account")`,
		),
		Description: "GCP Service Account JSON",
	},
	{
		Type:        SecretTypeGCPKey,
		Pattern:     regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),
		Description: "Google API Key",
	},
	{
		Type: SecretTypeGCPKey,
		Pattern: regexp.MustCompile(
			`(?i)[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
		),
		Description: "Google OAuth Client ID",
	},

	// ==================== Azure ====================
	{
		Type: SecretTypeAzureKey,
		Pattern: regexp.MustCompile(
			`(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}`,
		),
		Description: "Azure Storage Account Key",
	},
	{
		Type: SecretTypeAzureKey,
		Pattern: regexp.MustCompile(
			`(?i)azure[_-]?(storage[_-]?)?key\s*[=:]\s*['"]?([A-Za-z0-9+/=]{88})['"]?`,
		),
		Description: "Azure Key in variable",
	},
	{
		Type: SecretTypeAzureKey,
		Pattern: regexp.MustCompile(
			`(?i)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.[a-zA-Z0-9~_-]{34,}`,
		),
		Description: "Azure Application Secret",
	},

	// ==================== GitHub ====================
	{
		Type: SecretTypeGitHub,
		Pattern: regexp.MustCompile(
			`(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}`,
		),
		Description: "GitHub Personal Access Token",
	},
	{
		Type: SecretTypeGitHub,
		Pattern: regexp.MustCompile(
			`(?i)github[_-]?token\s*[=:]\s*['"]?([A-Za-z0-9_]{36,255})['"]?`,
		),
		Description: "GitHub Token in variable",
	},
	{
		Type: SecretTypeGitHub,
		Pattern: regexp.MustCompile(
			`(?i)github_app_[0-9]+_installation_[0-9]+_access_token`,
		),
		Description: "GitHub App Installation Token",
	},

	// ==================== GitLab ====================
	{
		Type:        SecretTypeGitLab,
		Pattern:     regexp.MustCompile(`(?i)glpat-[A-Za-z0-9\-_]{20,}`),
		Description: "GitLab Personal Access Token",
	},
	{
		Type:        SecretTypeGitLab,
		Pattern:     regexp.MustCompile(`(?i)glsa-[A-Za-z0-9\-_]{20,}`),
		Description: "GitLab Service Account Token",
	},
	{
		Type:        SecretTypeGitLab,
		Pattern:     regexp.MustCompile(`(?i)glrt-[A-Za-z0-9\-_]{20,}`),
		Description: "GitLab Runner Token",
	},

	// ==================== Slack ====================
	{
		Type: SecretTypeSlack,
		Pattern: regexp.MustCompile(
			`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`,
		),
		Description: "Slack Token",
	},
	{
		Type: SecretTypeSlack,
		Pattern: regexp.MustCompile(
			`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`,
		),
		Description: "Slack Webhook URL",
	},
	{
		Type:        SecretTypeSlack,
		Pattern:     regexp.MustCompile(`xoxe\.[a-zA-Z0-9\-]+`),
		Description: "Slack Enterprise Grid Token",
	},

	// ==================== Stripe ====================
	{
		Type: SecretTypeStripe,
		Pattern: regexp.MustCompile(
			`(?i)(sk|pk|rk)_(test|live)_[0-9a-zA-Z]{24,}`,
		),
		Description: "Stripe API Key",
	},
	{
		Type:        SecretTypeStripe,
		Pattern:     regexp.MustCompile(`(?i)whsec_[A-Za-z0-9]{32,}`),
		Description: "Stripe Webhook Secret",
	},

	// ==================== Twilio ====================
	{
		Type: SecretTypeTwilio,
		Pattern: regexp.MustCompile(
			`(?i)twilio[_-]?(auth[_-]?token|api[_-]?key)\s*[=:]\s*['"]?([A-Za-z0-9]{32})['"]?`,
		),
		Description: "Twilio Auth Token or API Key",
	},
	{
		Type:        SecretTypeTwilio,
		Pattern:     regexp.MustCompile(`SK[a-f0-9]{32}`),
		Description: "Twilio API Key",
	},

	// ==================== SendGrid ====================
	{
		Type: SecretTypeSendGrid,
		Pattern: regexp.MustCompile(
			`SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`,
		),
		Description: "SendGrid API Key",
	},

	// ==================== Mailgun ====================
	{
		Type:        SecretTypeMailgun,
		Pattern:     regexp.MustCompile(`(?i)key-[0-9a-zA-Z]{32}`),
		Description: "Mailgun API Key",
	},

	// ==================== NPM ====================
	{
		Type:        SecretTypeNPM,
		Pattern:     regexp.MustCompile(`(?i)npm_[A-Za-z0-9]{36}`),
		Description: "NPM Access Token",
	},
	{
		Type: SecretTypeNPM,
		Pattern: regexp.MustCompile(
			`//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-_]+`,
		),
		Description: "NPM Auth Token in .npmrc",
	},

	// ==================== PyPI ====================
	{
		Type: SecretTypePyPI,
		Pattern: regexp.MustCompile(
			`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`,
		),
		Description: "PyPI API Token",
	},

	// ==================== Docker Hub ====================
	{
		Type:        SecretTypeDockerHub,
		Pattern:     regexp.MustCompile(`(?i)dckr_pat_[A-Za-z0-9\-_]{27,}`),
		Description: "Docker Hub Personal Access Token",
	},

	// ==================== SSH & Private Keys ====================
	{
		Type: SecretTypeSSHKey,
		Pattern: regexp.MustCompile(
			`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`,
		),
		Description: "SSH Private Key",
	},
	{
		Type:        SecretTypePrivateKey,
		Pattern:     regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
		Description: "Generic Private Key",
	},
	{
		Type: SecretTypePrivateKey,
		Pattern: regexp.MustCompile(
			`-----BEGIN PGP PRIVATE KEY BLOCK-----`,
		),
		Description: "PGP Private Key",
	},
	{
		Type: SecretTypePrivateKey,
		Pattern: regexp.MustCompile(
			`-----BEGIN ENCRYPTED PRIVATE KEY-----`,
		),
		Description: "Encrypted Private Key",
	},

	// ==================== JWT ====================
	{
		Type: SecretTypeJWT,
		Pattern: regexp.MustCompile(
			`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/]*`,
		),
		Description: "JSON Web Token",
	},

	// ==================== Authentication ====================
	{
		Type:        SecretTypeBasicAuth,
		Pattern:     regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9+/=]{20,}`),
		Description: "HTTP Basic Authentication",
	},
	{
		Type:        SecretTypeBearer,
		Pattern:     regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-_.]+`),
		Description: "Bearer Token",
	},

	// ==================== Database Connection Strings ====================
	{
		Type: SecretTypeDatabase,
		Pattern: regexp.MustCompile(
			`(?i)(postgres|postgresql|mysql|mongodb|redis|amqp|mssql):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+`,
		),
		Description: "Database Connection URL with credentials",
	},
	{
		Type: SecretTypeConnectionString,
		Pattern: regexp.MustCompile(
			`(?i)(Server|Data Source)=[^;]+;.*(Password|Pwd)=[^;]+`,
		),
		Description: "Connection String with password",
	},
	{
		Type: SecretTypeDatabase,
		Pattern: regexp.MustCompile(
			`mongodb\+srv:\/\/[^:]+:[^@]+@[^\s"']+`,
		),
		Description: "MongoDB Atlas Connection String",
	},

	// ==================== Datadog ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)DD_API_KEY\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`,
		),
		Description: "Datadog API Key",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)DD_APP_KEY\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`,
		),
		Description: "Datadog Application Key",
	},

	// ==================== PagerDuty ====================
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`(?i)pd_[a-z0-9]{20}_[a-z0-9]{7}`),
		Description: "PagerDuty API Token",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)pagerduty[_-]?api[_-]?key\s*[=:]\s*['"]?([A-Za-z0-9\-_+]{20,})['"]?`,
		),
		Description: "PagerDuty API Key",
	},

	// ==================== Heroku ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)heroku[_-]?api[_-]?key\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`,
		),
		Description: "Heroku API Key",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)HEROKU_API_KEY\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`,
		),
		Description: "Heroku API Key Variable",
	},

	// ==================== DigitalOcean ====================
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
		Description: "DigitalOcean Personal Access Token",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)digitalocean[_-]?token\s*[=:]\s*['"]?([a-f0-9]{64})['"]?`,
		),
		Description: "DigitalOcean Token Variable",
	},

	// ==================== Linode ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)linode[_-]?token\s*[=:]\s*['"]?([a-f0-9]{64})['"]?`,
		),
		Description: "Linode API Token",
	},

	// ==================== Vultr ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)vultr[_-]?api[_-]?key\s*[=:]\s*['"]?([A-Z0-9]{36})['"]?`,
		),
		Description: "Vultr API Key",
	},

	// ==================== Oracle Cloud ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)oci[_-]?api[_-]?key\s*[=:]\s*['"]?([A-Za-z0-9+/=]{200,})['"]?`,
		),
		Description: "Oracle Cloud Infrastructure API Key",
	},

	// ==================== IBM Cloud ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)ibm[_-]?cloud[_-]?api[_-]?key\s*[=:]\s*['"]?([A-Za-z0-9\-_]{44})['"]?`,
		),
		Description: "IBM Cloud API Key",
	},

	// ==================== Alibaba Cloud ====================
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`(?i)LTAI[A-Za-z0-9]{12,20}`),
		Description: "Alibaba Cloud Access Key ID",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)alibaba[_-]?access[_-]?key[_-]?secret\s*[=:]\s*['"]?([A-Za-z0-9]{30})['"]?`,
		),
		Description: "Alibaba Cloud Access Key Secret",
	},

	// ==================== CircleCI ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)circle[_-]?token\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`,
		),
		Description: "CircleCI Personal API Token",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)CIRCLE_TOKEN\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`,
		),
		Description: "CircleCI Token Variable",
	},

	// ==================== Travis CI ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)travis[_-]?token\s*[=:]\s*['"]?([A-Za-z0-9\-_]{22})['"]?`,
		),
		Description: "Travis CI API Token",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)TRAVIS_TOKEN\s*[=:]\s*['"]?([A-Za-z0-9\-_]{22})['"]?`,
		),
		Description: "Travis CI Token Variable",
	},

	// ==================== Buildkite ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)buildkite[_-]?token\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`,
		),
		Description: "Buildkite API Token",
	},

	// ==================== Drone ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)drone[_-]?token\s*[=:]\s*['"]?([A-Za-z0-9]{32})['"]?`,
		),
		Description: "Drone CI Token",
	},

	// ==================== TeamCity ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)teamcity[_-]?token\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`,
		),
		Description: "TeamCity Access Token",
	},

	// ==================== Bamboo ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)bamboo[_-]?api[_-]?token\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`,
		),
		Description: "Bamboo API Token",
	},

	// ==================== Discord ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`https://discord\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9\-_]{68}`,
		),
		Description: "Discord Webhook URL",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`https://discordapp\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9\-_]{68}`,
		),
		Description: "Discord App Webhook URL",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)[MN][A-Za-z\d]{23}\.[A-Za-z\d]{6}\.[A-Za-z\d_\-]{27}`,
		),
		Description: "Discord Bot Token",
	},

	// ==================== Telegram ====================
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9_-]{35}`),
		Description: "Telegram Bot Token",
	},

	// ==================== Microsoft Teams ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9\-]+@[a-f0-9\-]+/IncomingWebhook/[a-f0-9]+/[a-f0-9\-]+`,
		),
		Description: "Microsoft Teams Webhook URL",
	},

	// ==================== PayPal ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)paypal[_-]?client[_-]?secret\s*[=:]\s*['"]?([A-Za-z0-9\-_]{64})['"]?`,
		),
		Description: "PayPal Client Secret",
	},
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`(?i)A[A-Z0-9]{79}`),
		Description: "PayPal Access Token",
	},

	// ==================== Square ====================
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`sq0[a-z]{3}-[A-Za-z0-9\-_]{22,43}`),
		Description: "Square Access Token",
	},
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`EAAA[a-zA-Z0-9]{60}`),
		Description: "Square OAuth Secret",
	},

	// ==================== Braintree ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)braintree[_-]?(access[_-]?token|private[_-]?key)\s*[=:]\s*['"]?([a-z0-9]{32})['"]?`,
		),
		Description: "Braintree Access Token",
	},

	// ==================== Authorize.net ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)authorize[_-]?net[_-]?transaction[_-]?key\s*[=:]\s*['"]?([A-Za-z0-9]{16})['"]?`,
		),
		Description: "Authorize.net Transaction Key",
	},

	// ==================== Postmark ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,
		),
		Description: "Postmark Server Token (Generic UUID format)",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)postmark[_-]?api[_-]?token\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`,
		),
		Description: "Postmark API Token",
	},

	// ==================== SparkPost ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)sparkpost[_-]?api[_-]?key\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`,
		),
		Description: "SparkPost API Key",
	},

	// ==================== Amazon SES ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)ses[_-]?smtp[_-]?password\s*[=:]\s*['"]?([A-Za-z0-9+/=]{44})['"]?`,
		),
		Description: "Amazon SES SMTP Password",
	},

	// ==================== New Relic ====================
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`NRAK-[A-Z0-9]{27}`),
		Description: "New Relic User API Key",
	},
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`NRJS-[a-f0-9]{19}`),
		Description: "New Relic Browser API Key",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)new[_-]?relic[_-]?license[_-]?key\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`,
		),
		Description: "New Relic License Key",
	},

	// ==================== Splunk ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)splunk[_-]?token\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`,
		),
		Description: "Splunk Authentication Token",
	},
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`Splunk\s+[A-Za-z0-9\-]{73}`),
		Description: "Splunk HEC Token",
	},

	// ==================== Sumo Logic ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)sumo[_-]?logic[_-]?access[_-]?(id|key)\s*[=:]\s*['"]?([A-Za-z0-9]{14,20})['"]?`,
		),
		Description: "Sumo Logic Access ID/Key",
	},

	// ==================== Elastic ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)elastic[_-]?api[_-]?key\s*[=:]\s*['"]?([A-Za-z0-9\-_=]{100,})['"]?`,
		),
		Description: "Elastic API Key",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)elasticsearch[_-]?password\s*[=:]\s*['"]?([A-Za-z0-9\-_]{20,})['"]?`,
		),
		Description: "Elasticsearch Password",
	},

	// ==================== Grafana Cloud ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)grafana[_-]?api[_-]?key\s*[=:]\s*['"]?([A-Za-z0-9\-_=]{100,})['"]?`,
		),
		Description: "Grafana Cloud API Key",
	},
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`glc_[A-Za-z0-9+/]{32,}={0,2}`),
		Description: "Grafana Cloud API Token",
	},

	// ==================== CockroachDB ====================
	{
		Type: SecretTypeDatabase,
		Pattern: regexp.MustCompile(
			`postgresql:\/\/[^:]+:[^@]+@[a-z0-9\-]+\.cockroachlabs\.cloud:\d+\/[^\s'"]+`,
		),
		Description: "CockroachDB Connection String",
	},

	// ==================== PlanetScale ====================
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`pscale_tkn_[A-Za-z0-9\-_\.=]{43}`),
		Description: "PlanetScale Token",
	},
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`pscale_pw_[A-Za-z0-9\-_\.=]{43}`),
		Description: "PlanetScale Password",
	},

	// ==================== Supabase ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3MiOiJzdXBhYmFzZS[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`,
		),
		Description: "Supabase Service Role Key",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)supabase[_-]?anon[_-]?key\s*[=:]\s*['"]?(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)['"]?`,
		),
		Description: "Supabase Anon Key",
	},

	// ==================== Auth0 ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)auth0[_-]?client[_-]?secret\s*[=:]\s*['"]?([A-Za-z0-9\-_]{64})['"]?`,
		),
		Description: "Auth0 Client Secret",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)auth0[_-]?api[_-]?token\s*[=:]\s*['"]?([A-Za-z0-9\-_\.=]{28,})['"]?`,
		),
		Description: "Auth0 Management API Token",
	},

	// ==================== Okta ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)okta[_-]?api[_-]?token\s*[=:]\s*['"]?([A-Za-z0-9\-_]{42})['"]?`,
		),
		Description: "Okta API Token",
	},
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`(?i)ssws\s+[A-Za-z0-9\-_]{42}`),
		Description: "Okta API Token (SSWS format)",
	},

	// ==================== Firebase ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)firebase[_-]?api[_-]?key\s*[=:]\s*['"]?(AIza[0-9A-Za-z\-_]{35})['"]?`,
		),
		Description: "Firebase API Key",
	},

	// ==================== Clerk ====================
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`sk_test_[A-Za-z0-9]{48}`),
		Description: "Clerk Secret Key (Test)",
	},
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`sk_live_[A-Za-z0-9]{48}`),
		Description: "Clerk Secret Key (Live)",
	},

	// ==================== OpenAI ====================
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`sk-[A-Za-z0-9]{48}`),
		Description: "OpenAI API Key (Legacy)",
	},
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`sk-proj-[A-Za-z0-9\-_]{48,}`),
		Description: "OpenAI Project API Key",
	},
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`sk-org-[A-Za-z0-9]{48,}`),
		Description: "OpenAI Organization API Key",
	},

	// ==================== Anthropic ====================
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`sk-ant-api03-[A-Za-z0-9\-_]{95,}`),
		Description: "Anthropic API Key",
	},

	// ==================== HuggingFace ====================
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`hf_[A-Za-z0-9]{38}`),
		Description: "HuggingFace Access Token",
	},

	// ==================== Replicate ====================
	{
		Type:        SecretTypeAPIKey,
		Pattern:     regexp.MustCompile(`r8_[A-Za-z0-9]{40}`),
		Description: "Replicate API Token",
	},

	// ==================== Pinecone ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)pinecone[_-]?api[_-]?key\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`,
		),
		Description: "Pinecone API Key",
	},

	// ==================== Algolia ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)algolia[_-]?admin[_-]?api[_-]?key\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`,
		),
		Description: "Algolia Admin API Key",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)x-algolia-api-key:\s*[A-Za-z0-9]{32}`,
		),
		Description: "Algolia API Key Header",
	},

	// ==================== Cloudinary ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[a-z0-9\-]+`,
		),
		Description: "Cloudinary URL with API Secret",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)cloudinary[_-]?api[_-]?secret\s*[=:]\s*['"]?([A-Za-z0-9\-_]{27})['"]?`,
		),
		Description: "Cloudinary API Secret",
	},

	// ==================== Mapbox ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`pk\.eyJ1Ijoi[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_\.]+`,
		),
		Description: "Mapbox Public Token",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`sk\.eyJ1Ijoi[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_\.]+`,
		),
		Description: "Mapbox Secret Token",
	},

	// ==================== Plaid ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)plaid[_-]?(secret|client_id)\s*[=:]\s*['"]?([a-f0-9]{30})['"]?`,
		),
		Description: "Plaid API Secret",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`access-(?:sandbox|development|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,
		),
		Description: "Plaid Access Token",
	},

	// ==================== Bitbucket ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)bitbucket[_-]?app[_-]?password\s*[=:]\s*['"]?([A-Za-z0-9]{20})['"]?`,
		),
		Description: "Bitbucket App Password",
	},

	// ==================== Atlassian ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)atlassian[_-]?token\s*[=:]\s*['"]?([A-Za-z0-9]{24})['"]?`,
		),
		Description: "Atlassian API Token",
	},

	// ==================== Confluent ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)confluent[_-]?cloud[_-]?api[_-]?key\s*[=:]\s*['"]?([A-Z0-9]{16})['"]?`,
		),
		Description: "Confluent Cloud API Key",
	},

	// ==================== Redis ====================
	{
		Type:        SecretTypeDatabase,
		Pattern:     regexp.MustCompile(`redis:\/\/:[^@]+@[^\s"']+`),
		Description: "Redis Connection String with Password",
	},
	{
		Type:        SecretTypeDatabase,
		Pattern:     regexp.MustCompile(`rediss:\/\/[^:]+:[^@]+@[^\s"']+`),
		Description: "Redis SSL Connection String",
	},

	// ==================== Cloudflare ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)cloudflare[_-]?api[_-]?key\s*[=:]\s*['"]?([a-f0-9]{37})['"]?`,
		),
		Description: "Cloudflare Global API Key",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)cloudflare[_-]?api[_-]?token\s*[=:]\s*['"]?([A-Za-z0-9\-_]{40})['"]?`,
		),
		Description: "Cloudflare API Token",
	},

	// ==================== Sentry ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`https://[a-f0-9]{32}@[a-z0-9\-]+\.ingest\.sentry\.io/[0-9]+`,
		),
		Description: "Sentry DSN",
	},
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)sentry[_-]?auth[_-]?token\s*[=:]\s*['"]?([a-f0-9]{64})['"]?`,
		),
		Description: "Sentry Auth Token",
	},

	// ==================== Generic High-Entropy Secrets ====================
	{
		Type: SecretTypeAPIKey,
		Pattern: regexp.MustCompile(
			`(?i)(api[_-]?key|apikey|api[_-]?secret|apisecret)['":\s=]+[A-Za-z0-9\-_]{32,}`,
		),
		Description: "Generic API Key Pattern",
	},
	{
		Type: SecretTypePassword,
		Pattern: regexp.MustCompile(
			`(?i)(password|passwd|pwd)['":\s=]+[^\s'"]{8,}`,
		),
		Description: "Generic Password Pattern",
	},
}

var SensitiveEnvNames = map[string]struct{}{
	// ==================== Generic Auth ====================
	"PASSWORD":        {},
	"PASSWD":          {},
	"PASS":            {},
	"PWD":             {},
	"SECRET":          {},
	"SECRET_KEY":      {},
	"SECRETKEY":       {},
	"API_KEY":         {},
	"APIKEY":          {},
	"API_SECRET":      {},
	"APISECRET":       {},
	"ACCESS_KEY":      {},
	"ACCESSKEY":       {},
	"ACCESS_TOKEN":    {},
	"ACCESSTOKEN":     {},
	"AUTH_TOKEN":      {},
	"AUTHTOKEN":       {},
	"AUTH_KEY":        {},
	"AUTHKEY":         {},
	"PRIVATE_KEY":     {},
	"PRIVATEKEY":      {},
	"ENCRYPTION_KEY":  {},
	"ENCRYPTIONKEY":   {},
	"SIGNING_KEY":     {},
	"SIGNINGKEY":      {},
	"JWT_SECRET":      {},
	"JWTSECRET":       {},
	"SESSION_SECRET":  {},
	"SESSIONSECRET":   {},
	"COOKIE_SECRET":   {},
	"COOKIESECRET":    {},
	"TOKEN":           {},
	"BEARER_TOKEN":    {},
	"OAUTH_TOKEN":     {},
	"REFRESH_TOKEN":   {},
	"CLIENT_SECRET":   {},
	"CONSUMER_SECRET": {},
	"WEBHOOK_SECRET":  {},
	"MASTER_KEY":      {},
	"ADMIN_PASSWORD":  {},
	"USER_PASSWORD":   {},
	"ROOT_PASSWORD":   {},

	// ==================== Database ====================
	"DB_PASSWORD":          {},
	"DBPASSWORD":           {},
	"DATABASE_PASSWORD":    {},
	"DATABASEPASSWORD":     {},
	"DATABASE_URL":         {},
	"DB_URL":               {},
	"CONNECTION_STRING":    {},
	"MYSQL_PASSWORD":       {},
	"MYSQLPASSWORD":        {},
	"MYSQL_ROOT_PASSWORD":  {},
	"POSTGRES_PASSWORD":    {},
	"POSTGRESPASSWORD":     {},
	"POSTGRESQL_PASSWORD":  {},
	"REDIS_PASSWORD":       {},
	"REDISPASSWORD":        {},
	"REDIS_URL":            {},
	"MONGO_PASSWORD":       {},
	"MONGOPASSWORD":        {},
	"MONGODB_PASSWORD":     {},
	"MONGODB_URI":          {},
	"MONGODB_URL":          {},
	"MSSQL_PASSWORD":       {},
	"ORACLE_PASSWORD":      {},
	"CASSANDRA_PASSWORD":   {},
	"COCKROACHDB_URL":      {},
	"PLANETSCALE_TOKEN":    {},
	"SUPABASE_KEY":         {},
	"SUPABASE_ANON_KEY":    {},
	"SUPABASE_SERVICE_KEY": {},

	// ==================== AWS ====================
	"AWS_SECRET_ACCESS_KEY": {},
	"AWS_ACCESS_KEY_ID":     {},
	"AWS_SESSION_TOKEN":     {},
	"AWS_API_KEY":           {},

	// ==================== GCP ====================
	"GCP_PRIVATE_KEY":                {},
	"GOOGLE_API_KEY":                 {},
	"GOOGLE_APPLICATION_CREDENTIALS": {},
	"GCLOUD_SERVICE_KEY":             {},

	// ==================== Azure ====================
	"AZURE_CLIENT_SECRET":   {},
	"AZURE_STORAGE_KEY":     {},
	"AZURE_TENANT_ID":       {},
	"AZURE_SUBSCRIPTION_ID": {},

	// ==================== GitHub ====================
	"GITHUB_TOKEN":                 {},
	"GH_TOKEN":                     {},
	"GITHUB_PAT":                   {},
	"GITHUB_PERSONAL_ACCESS_TOKEN": {},
	"GITHUB_APP_PRIVATE_KEY":       {},

	// ==================== GitLab ====================
	"GITLAB_TOKEN":       {},
	"CI_JOB_TOKEN":       {},
	"CI_DEPLOY_PASSWORD": {},

	// ==================== Bitbucket ====================
	"BITBUCKET_PASSWORD":     {},
	"BITBUCKET_APP_PASSWORD": {},

	// ==================== Docker ====================
	"DOCKER_PASSWORD":    {},
	"DOCKER_AUTH":        {},
	"DOCKERHUB_TOKEN":    {},
	"DOCKERHUB_PASSWORD": {},
	"REGISTRY_PASSWORD":  {},

	// ==================== NPM / Yarn ====================
	"NPM_TOKEN":       {},
	"NPM_AUTH_TOKEN":  {},
	"YARN_AUTH_TOKEN": {},

	// ==================== Slack ====================
	"SLACK_TOKEN":       {},
	"SLACK_WEBHOOK":     {},
	"SLACK_WEBHOOK_URL": {},
	"SLACK_BOT_TOKEN":   {},
	"SLACK_API_TOKEN":   {},

	// ==================== Stripe ====================
	"STRIPE_SECRET_KEY":     {},
	"STRIPE_API_KEY":        {},
	"STRIPE_PRIVATE_KEY":    {},
	"STRIPE_WEBHOOK_SECRET": {},

	// ==================== Twilio ====================
	"TWILIO_AUTH_TOKEN": {},
	"TWILIO_API_KEY":    {},
	"TWILIO_API_SECRET": {},

	// ==================== SendGrid ====================
	"SENDGRID_API_KEY": {},

	// ==================== Mailgun ====================
	"MAILGUN_API_KEY":     {},
	"MAILGUN_PRIVATE_KEY": {},

	// ==================== Postmark ====================
	"POSTMARK_API_TOKEN":    {},
	"POSTMARK_SERVER_TOKEN": {},

	// ==================== SparkPost ====================
	"SPARKPOST_API_KEY": {},

	// ==================== SES ====================
	"SES_SMTP_PASSWORD": {},
	"SES_ACCESS_KEY":    {},

	// ==================== Firebase ====================
	"FIREBASE_API_KEY":      {},
	"FIREBASE_PRIVATE_KEY":  {},
	"FIREBASE_CLIENT_EMAIL": {},

	// ==================== Heroku ====================
	"HEROKU_API_KEY": {},

	// ==================== DigitalOcean ====================
	"DIGITALOCEAN_TOKEN":        {},
	"DIGITALOCEAN_ACCESS_TOKEN": {},

	// ==================== Linode ====================
	"LINODE_TOKEN":     {},
	"LINODE_API_TOKEN": {},

	// ==================== Vultr ====================
	"VULTR_API_KEY": {},

	// ==================== Oracle Cloud ====================
	"OCI_CLI_KEY_FILE": {},
	"OCI_CLI_USER":     {},

	// ==================== IBM Cloud ====================
	"IBM_CLOUD_API_KEY": {},
	"IBMCLOUD_API_KEY":  {},

	// ==================== Alibaba Cloud ====================
	"ALIBABA_CLOUD_ACCESS_KEY_ID":     {},
	"ALIBABA_CLOUD_ACCESS_KEY_SECRET": {},

	// ==================== Cloudflare ====================
	"CLOUDFLARE_API_KEY":   {},
	"CLOUDFLARE_API_TOKEN": {},
	"CF_API_KEY":           {},

	// ==================== Datadog ====================
	"DATADOG_API_KEY": {},
	"DD_API_KEY":      {},
	"DD_APP_KEY":      {},

	// ==================== New Relic ====================
	"NEW_RELIC_LICENSE_KEY": {},
	"NEW_RELIC_API_KEY":     {},
	"NEWRELIC_LICENSE_KEY":  {},

	// ==================== Sentry ====================
	"SENTRY_DSN":        {},
	"SENTRY_AUTH_TOKEN": {},

	// ==================== PagerDuty ====================
	"PAGERDUTY_API_KEY": {},
	"PD_API_KEY":        {},

	// ==================== CircleCI ====================
	"CIRCLE_TOKEN":   {},
	"CIRCLECI_TOKEN": {},

	// ==================== Travis CI ====================
	"TRAVIS_TOKEN": {},

	// ==================== Buildkite ====================
	"BUILDKITE_TOKEN":     {},
	"BUILDKITE_API_TOKEN": {},

	// ==================== Drone ====================
	"DRONE_TOKEN": {},

	// ==================== TeamCity ====================
	"TEAMCITY_TOKEN": {},

	// ==================== Bamboo ====================
	"BAMBOO_TOKEN": {},

	// ==================== Discord ====================
	"DISCORD_WEBHOOK":   {},
	"DISCORD_BOT_TOKEN": {},
	"DISCORD_TOKEN":     {},

	// ==================== Telegram ====================
	"TELEGRAM_BOT_TOKEN": {},
	"TELEGRAM_TOKEN":     {},

	// ==================== Teams ====================
	"TEAMS_WEBHOOK":     {},
	"TEAMS_WEBHOOK_URL": {},

	// ==================== PayPal ====================
	"PAYPAL_CLIENT_SECRET": {},
	"PAYPAL_SECRET":        {},

	// ==================== Square ====================
	"SQUARE_ACCESS_TOKEN": {},
	"SQUARE_SECRET":       {},

	// ==================== Braintree ====================
	"BRAINTREE_PRIVATE_KEY":  {},
	"BRAINTREE_ACCESS_TOKEN": {},

	// ==================== Authorize.net ====================
	"AUTHORIZENET_TRANSACTION_KEY": {},

	// ==================== Splunk ====================
	"SPLUNK_TOKEN":     {},
	"SPLUNK_HEC_TOKEN": {},

	// ==================== Sumo Logic ====================
	"SUMOLOGIC_ACCESS_ID":  {},
	"SUMOLOGIC_ACCESS_KEY": {},

	// ==================== Elastic ====================
	"ELASTIC_API_KEY":        {},
	"ELASTICSEARCH_PASSWORD": {},

	// ==================== Grafana ====================
	"GRAFANA_API_KEY":       {},
	"GRAFANA_CLOUD_API_KEY": {},

	// ==================== Auth0 ====================
	"AUTH0_CLIENT_SECRET": {},
	"AUTH0_API_TOKEN":     {},

	// ==================== Okta ====================
	"OKTA_API_TOKEN":    {},
	"OKTA_CLIENT_TOKEN": {},

	// ==================== Clerk ====================
	"CLERK_SECRET_KEY": {},
	"CLERK_API_KEY":    {},

	// ==================== OpenAI ====================
	"OPENAI_API_KEY":    {},
	"OPENAI_SECRET_KEY": {},

	// ==================== Anthropic ====================
	"ANTHROPIC_API_KEY": {},
	"CLAUDE_API_KEY":    {},

	// ==================== HuggingFace ====================
	"HUGGINGFACE_TOKEN": {},
	"HF_TOKEN":          {},

	// ==================== Replicate ====================
	"REPLICATE_API_TOKEN": {},

	// ==================== Pinecone ====================
	"PINECONE_API_KEY": {},

	// ==================== Algolia ====================
	"ALGOLIA_API_KEY":       {},
	"ALGOLIA_ADMIN_API_KEY": {},

	// ==================== Cloudinary ====================
	"CLOUDINARY_API_SECRET": {},
	"CLOUDINARY_URL":        {},

	// ==================== Mapbox ====================
	"MAPBOX_ACCESS_TOKEN": {},
	"MAPBOX_SECRET_TOKEN": {},

	// ==================== Plaid ====================
	"PLAID_SECRET":    {},
	"PLAID_CLIENT_ID": {},

	// ==================== Atlassian ====================
	"ATLASSIAN_TOKEN":      {},
	"JIRA_API_TOKEN":       {},
	"CONFLUENCE_API_TOKEN": {},

	// ==================== Confluent ====================
	"CONFLUENT_API_KEY":    {},
	"CONFLUENT_API_SECRET": {},

	// ==================== SSH / TLS ====================
	"SSH_PRIVATE_KEY": {},
	"SSH_KEY":         {},
	"SSL_KEY":         {},
	"TLS_KEY":         {},
	"CERTIFICATE_KEY": {},
	"CERT_KEY":        {},

	// ==================== Encryption ====================
	"ENCRYPTION_PASSWORD": {},
	"CRYPTO_KEY":          {},
	"AES_KEY":             {},
}

func IsSensitiveEnvName(name string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(name))
	if _, exists := SensitiveEnvNames[normalized]; exists {
		return true
	}
	sensitiveSubstrings := []string{
		"PASSWORD", "PASSWD", "SECRET", "TOKEN", "KEY", "CREDENTIAL",
		"AUTH", "PRIVATE", "APIKEY", "API_KEY", "ACCESS",
	}
	for _, substr := range sensitiveSubstrings {
		if strings.Contains(normalized, substr) {
			return true
		}
	}
	return false
}

func DetectSecrets(content string) []SecretPattern {
	var matches []SecretPattern
	for _, pattern := range SecretPatterns {
		if pattern.Pattern.MatchString(content) {
			matches = append(matches, pattern)
		}
	}
	return matches
}

func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len(s))
	var entropy float64
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func IsHighEntropyString(s string, minLength int, minEntropy float64) bool {
	if len(s) < minLength {
		return false
	}
	return CalculateEntropy(s) >= minEntropy
}
