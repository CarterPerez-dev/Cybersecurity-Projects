# Core Security Concepts

This document explains the security concepts you'll encounter while building Portia. These aren't just definitions. We'll dig into why they matter and how they actually work in production systems.

## Secret Sprawl

### What It Is

Secret sprawl is the uncontrolled spread of credentials, API keys, tokens, and other sensitive values across source code, configuration files, CI/CD pipelines, chat logs, and documentation. Once a secret enters a git repository, it exists in every clone forever, even if the file is later deleted.

### Why It Matters

GitHub reported in 2023 that they detected over 12.8 million new secrets leaked in public repositories that year. That number only covers the secrets they actively scan for. The real number is significantly higher.

**Uber, November 2016**
Two engineers committed AWS access keys to a private GitHub repository. Six months later, attackers who had access to that repo used the keys to access an S3 bucket containing 57 million rider and driver records (names, email addresses, phone numbers, driver license numbers). Uber paid the attackers $100,000 to delete the data and keep quiet, then paid $148 million in a settlement with all 50 US state attorneys general. The keys matched the exact `AKIA` prefix pattern that Portia's `aws-access-key-id` rule detects (`internal/rules/builtin.go`).

**Samsung, March 2022**
The Lapsus$ group exfiltrated 190GB of Samsung source code from internal Git servers. Inside the code: hardcoded credentials for Samsung's SmartThings platform, private signing keys, and source code for bootloaders and TrustZone. The attack surface existed because secrets were embedded directly in application code rather than injected at runtime.

**Twitter, January 2023**
A researcher discovered that Twitter's mobile apps contained embedded API keys that could be extracted through reverse engineering. Twitter acknowledged the issue and rotated the keys, but the incident highlighted a fundamental problem: mobile apps ship compiled code to millions of devices, and any secrets in that code are extractable.

### How It Works

Secrets end up in code through three main paths:

**Development shortcuts**: A developer needs an API key to test a feature. They paste it into a config file, commit it, and plan to move it to environment variables later. They never do. The key sits in git history forever. Even deleting the file and committing the deletion doesn't help because `git log --all --full-history` still shows it.

**Copy-paste from documentation**: Cloud providers often show example commands with placeholder keys like `AKIAIOSFODNN7EXAMPLE`. Developers replace the placeholder with their real key, forget to revert, and commit the file.

**CI/CD configuration**: Secrets are set as environment variables in CI pipelines (GitHub Actions, CircleCI, Jenkins). When a developer copies a workflow file or exports a pipeline config, those values end up in version-controlled files. The CircleCI breach in January 2023 happened partly because customer secrets were stored as plaintext environment variables accessible to CI jobs.

### Defense Strategies

Portia implements pre-commit scanning, which catches secrets before they enter git history. But scanning is just one layer:

1. **Pre-commit hooks** - Run Portia on staged files before every commit
2. **CI pipeline scanning** - Run Portia on every pull request as a required check
3. **Vault integration** - Use HashiCorp Vault, AWS Secrets Manager, or similar tools to inject secrets at runtime
4. **Environment variables** - Keep secrets out of code entirely. Reference `${API_KEY}` instead of pasting the key.
5. **Rotation** - Assume secrets will leak. Rotate them regularly so leaked keys expire quickly.

## Shannon Entropy

### What It Is

Shannon entropy (named after Claude Shannon, the father of information theory) measures the randomness of a string. It answers the question: "How surprised would I be by each character?" English text has low entropy (you can predict the next letter). An API key like `xK9mP2vL5nQ8jR3t` has high entropy (each character is unpredictable).

The formula: `H = -Σ p(x) * log₂(p(x))`

Where `p(x)` is the frequency of each character divided by the string length.

### Why It Matters

Regex alone isn't enough to detect all secrets. Some rules match structural patterns (`AKIA` prefix for AWS keys, `ghp_` prefix for GitHub tokens). But many secrets have no structural prefix. A password like `xK9mP2vL5nQ8jR3t` looks like random characters, and that randomness itself is the signal.

Human-readable text (variable names, comments, URLs) has entropy around 2.5-3.5 bits per character. Randomly generated secrets typically have entropy above 4.0. By computing entropy and comparing to a threshold, Portia can flag high-randomness strings that don't match any specific regex pattern.

### How It Works

The implementation at `internal/rules/entropy.go` works in three steps:

**Step 1: Charset detection** - Determine whether the string looks like hex (`0-9a-f`), base64 (`A-Za-z0-9+/=`), or general alphanumeric. This matters because the entropy threshold differs: a hex string needs lower entropy to be suspicious (since hex only has 16 possible characters), while alphanumeric strings need higher entropy.

**Step 2: Character frequency counting** - Count how many times each character appears. For `aabbcc`, the frequencies are: `a=2, b=2, c=2`. Each character has probability 2/6 = 0.333.

**Step 3: Entropy calculation** - For each unique character, compute `-p * log₂(p)` and sum them. For `aabbcc`: `-0.333 * log₂(0.333) * 3 unique chars = 1.585 bits`. For a random 20-character string with all unique characters: `-0.05 * log₂(0.05) * 20 = 4.322 bits`.

**Thresholds used in Portia:**
- Hex strings (charset `0-9a-f`): 3.0 bits minimum
- Base64 strings (charset `A-Za-z0-9+/=`): 4.0 bits minimum
- Alphanumeric strings: 3.5 bits minimum

These thresholds are configured per-rule in `internal/rules/builtin.go`. Rules like `generic-password` and `generic-secret` use entropy thresholds to filter out low-randomness false positives like `password = "admin"`.

### Common Pitfalls

**Low entropy doesn't mean safe.** The string `aaaaaaaaAAAAAAAA` has low entropy but could still be a valid API key for a poorly designed system. Entropy is one signal, not the only signal.

**Charset matters.** A hex string `deadbeef` has low absolute entropy but might be suspicious in a hex context. Portia's `DetectCharset` function (`internal/rules/entropy.go`) adjusts thresholds based on the character set.

## Regular Expression-Based Detection

### What It Is

Most cloud providers and services use structured formats for their credentials. AWS access keys always start with `AKIA`, `ABIA`, `ACCA`, or `ASIA` followed by 16 uppercase alphanumeric characters. GitHub PATs start with `ghp_` followed by 36 alphanumeric characters. Stripe live keys start with `sk_live_`. These patterns are specific enough to match with regular expressions while having very low false positive rates.

### Why It Matters

Prefix-based detection works because cloud providers intentionally design their key formats to be identifiable. AWS uses the `AKIA` prefix specifically so that tools can detect leaked keys. GitHub changed their token format from random hex strings to prefixed tokens (`ghp_`, `gho_`, `ghs_`, `ghr_`) in 2021 to enable exactly this kind of scanning.

### How It Works

Each rule in `internal/rules/builtin.go` has four components that work together:

**Keywords** - Fast string matching to eliminate ~95% of chunks before regex. If a chunk doesn't contain the keyword `AKIA`, there's no point running the AWS key regex against it. This is a performance optimization. See `internal/rules/registry.go` MatchKeywords function.

**Pattern** - The actual regex. For AWS keys: `\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`. The `\b` word boundaries prevent matching substrings of longer tokens. The capture group `(...)` extracts just the secret portion.

**SecretGroup** - Which regex capture group contains the secret value. Group 0 is the entire match; group 1 is the first parenthesized group. Most rules use group 1 to extract the key without surrounding context.

**Allowlist** - Per-rule patterns that suppress known false positives. AWS keys have an allowlist for `AKIAIOSFODNN7EXAMPLE` (the AWS documentation example key).

### 150 Rules Organized by Provider

Portia's builtin rules cover:
- **Cloud providers**: AWS (3), GCP (3), Azure (3), Alibaba Cloud (1), IBM Cloud (1), Cloudflare (2)
- **Source control**: GitHub (6), GitLab (3), Bitbucket (1)
- **Payment**: Stripe (4), Square (2), Razorpay (1), Braintree (1), Coinbase (1)
- **Communication**: Slack (4), Twilio (3), SendGrid (1), Discord (3), Telegram (1), Microsoft Teams (1), Intercom (1)
- **Email**: Mailchimp (1), Mailgun (1), Resend (1), Brevo (1), Postmark (1)
- **Infrastructure**: Heroku (1), DigitalOcean (3), Supabase (2), Confluent (1), Fly.io (1), Render (1), Vercel (1), Netlify (1), PlanetScale (3), Neon (1), Upstash (1), Turso (1)
- **Hosting/VPS**: Hetzner (1), Linode (1), Vultr (1)
- **AI/ML**: OpenAI (2), Anthropic (1), HuggingFace (1), Replicate (1), Groq (1), Perplexity (1)
- **CI/CD**: CircleCI (1), Buildkite (1), GitHub Actions (1)
- **Secrets management**: Vault (1), Doppler (2), 1Password (1)
- **Cryptographic**: SSH/PGP/PKCS8 keys (6), JWT (1), Age (1)
- **Package registries**: NPM (1), PyPI (1), RubyGems (1), Docker Hub (1)
- **Generic**: password (1), secret (1), api-key (1), token (1)
- **Connection strings**: PostgreSQL (1), MySQL (1), MongoDB (1), Redis (1), Firebase URL (1), Cloudinary (1)
- **Monitoring/Observability**: Datadog (1), New Relic (1), Grafana (2), Sentry (1), PostHog (1), Axiom (1), Dynatrace (1), Honeycomb (1), Elastic (1), Segment (1), Rollbar (1), Mixpanel (1), Amplitude (1)
- **Developer tools**: Figma (1), Linear (1), Postman (1), Algolia (1), Contentful (1), Snyk (1), SonarQube (1), Freshdesk (1), Zendesk (1)
- **Other**: Terraform (1), Shopify (4), Okta (1), LaunchDarkly (2), Infracost (1), Prefect (1), Pulumi (1), Databricks (1), HubSpot (1), PagerDuty (1), Atlassian (1), Facebook (1), Twitter (1), Firebase FCM (1), Mapbox (2), Doppler CLI (1)

## False Positive Reduction

### What It Is

A naive regex scanner produces hundreds or thousands of false positives: placeholder values, template variables, test fixtures, example keys from documentation. If the output is noisy, developers ignore it. False positive reduction is the set of techniques that make scanner output trustworthy enough to act on.

### Why It Matters

GitGuardian's 2023 State of Secrets Sprawl report found that teams using secrets scanners with high false positive rates had a 40% lower remediation rate than teams with low false positive scanners. Noise kills action. If every other finding is a false positive, developers stop reading findings.

### How It Works

Portia uses a 5-layer filter chain at `internal/engine/filter.go` and `internal/engine/detector.go`:

**Layer 1: Keyword pre-filtering** (`internal/rules/registry.go` MatchKeywords)
Before running any regex, check if the chunk even contains keywords relevant to any rule. A file full of HTML with no instance of `password`, `secret`, `key`, `token`, or any provider-specific prefix won't match any rules. This eliminates ~95% of chunks immediately and is a pure performance optimization.

**Layer 2: Structural validation** (`internal/engine/detector.go` extractSecret)
After regex matches, extract the secret using the capture group. If the capture group is empty or the match is just whitespace, discard it. This handles edge cases where a regex matches surrounding syntax but captures nothing meaningful.

**Layer 3: Placeholder detection** (`internal/engine/filter.go` IsPlaceholder)
Check the secret value against known placeholder patterns: `example`, `test`, `dummy`, `fake`, `placeholder`, `YOUR_API_KEY`, `xxxx...`, `****...`, `${VARIABLE}`, `{{TEMPLATE}}`, `TODO`, `CHANGEME`, `REPLACE_ME`. These are defined in `internal/rules/registry.go` GlobalValueAllowlist.

**Layer 4: Template detection** (`internal/engine/filter.go` IsTemplated)
Check if the secret is a template variable: `${ENV_VAR}`, `{{handlebars}}`, `os.getenv(...)`, `process.env.X`, `System.getenv(...)`, `ENV[...]`. These aren't real secrets; they're references to secrets stored elsewhere.

**Layer 5: Stopword filtering** (`internal/engine/filter.go` IsStopword)
Check if the secret, when split on delimiters (`_`, `-`, `.`, `/`), contains common programming words like `function`, `controller`, `database`, `config`, etc. The stopword list at `internal/engine/filter.go` has 700+ words. This catches false positives like `module_controller_factory` that regex might match as a generic token.

**Layer 6: Path allowlisting** (`internal/rules/registry.go` GlobalPathAllowlist)
Skip files that are known to contain non-sensitive data: `go.mod`, `go.sum`, `package-lock.json`, `yarn.lock`, `.min.js` files, `node_modules/`, `vendor/`, binary formats.

### Common Pitfall

The biggest mistake with false positive reduction: being too aggressive. If you filter out too many results, you'll miss real secrets. Portia's approach is conservative by default. Each filter layer targets a specific class of false positives with high precision. The stopword list only matches on delimiter-split parts (not substrings) to avoid filtering out real secrets that happen to contain common words as substrings.

## HIBP k-Anonymity

### What It Is

Have I Been Pwned (HIBP) is Troy Hunt's database of billions of passwords and credentials from known data breaches. Portia can check whether a detected secret appears in any known breach. But sending the secret to an external API would defeat the purpose. k-Anonymity solves this: you send only 5 characters of the secret's SHA-1 hash, and the server returns all hashes that share that prefix. You check locally whether your full hash appears in the results.

### Why It Matters

If Portia finds `password = "P@ssw0rd123"` in your code, knowing it appears in 47,000 known breaches adds urgency. A unique, randomly-generated password that hasn't been breached is less urgent than a commonly-used password that's in every credential stuffing wordlist.

The 2019 Collection #1 breach dump contained 773 million unique email addresses and 21 million unique passwords. The 2021 RockYou2021 leak contained 8.4 billion passwords. If your detected secret appears in these datasets, attackers already have it.

### How It Works

Implementation at `internal/hibp/client.go`:

1. **SHA-1 hash**: Compute `SHA-1(secret)`. For "P@ssw0rd123": `a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`
2. **Prefix extraction**: Take the first 5 hex characters: `a94a8`
3. **API query**: `GET https://api.pwnedpasswords.com/range/a94a8`
4. **Response**: The API returns ~500-800 hash suffixes with occurrence counts
5. **Local matching**: Check if the remaining 35 characters of your hash appear in the response

The API never sees the full hash, so it can't determine which password you're checking. This is the k-anonymity guarantee.

**LRU cache** (`internal/hibp/client.go`): Results are cached in a 10,000-entry LRU cache. If the same prefix has been queried before, the cached result is returned. This avoids redundant API calls when scanning large codebases with similar secrets.

**Circuit breaker** (`internal/hibp/client.go`): Using Sony's gobreaker library, the client tracks API failures. After 5 consecutive errors, the circuit opens and requests are rejected immediately for 60 seconds. This prevents cascading failures if the HIBP API is down or rate-limited.

### Common Pitfall

HIBP is designed for passwords, not API keys. A leaked AWS access key won't appear in password breach databases. HIBP checking is most useful for password-type findings (the `generic-password` and `generic-secret` rules) and less useful for provider-specific tokens. Portia only sends password and generic-secret findings to HIBP, skipping provider-specific tokens entirely.

## SARIF Output Format

### What It Is

SARIF (Static Analysis Results Interchange Format) is an OASIS standard (version 2.1.0) for expressing the output of static analysis tools. It's a JSON-based format that GitHub, Azure DevOps, GitLab, and other CI platforms can consume to display findings inline on pull requests.

### Why It Matters

Without SARIF, integrating a scanner into CI requires custom parsing logic for each tool's output format. With SARIF, you produce one JSON file and every major CI platform knows how to display it. GitHub Code Scanning, for example, accepts SARIF uploads and shows findings as annotations on the PR diff.

### How It Works

Portia's SARIF reporter at `internal/reporter/sarif.go` produces a v2.1.0 compliant document:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "portia",
        "rules": [...]
      }
    },
    "results": [...]
  }]
}
```

Each finding maps to a SARIF `result` with:
- `ruleId` - The Portia rule ID (e.g., `aws-access-key-id`)
- `level` - Mapped from Portia severity (CRITICAL/HIGH = `error`, MEDIUM = `warning`, LOW = `note`)
- `message` - The finding description
- `locations` - File path and line number
- `properties` - Portia-specific metadata (entropy, HIBP status, masked secret)

To upload to GitHub Code Scanning:
```bash
portia scan --format sarif . > results.sarif
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -f sarif=@results.sarif \
  -f commit_sha=$(git rev-parse HEAD)
```
