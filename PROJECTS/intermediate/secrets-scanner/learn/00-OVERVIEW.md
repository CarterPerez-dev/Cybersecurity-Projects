# Portia - Secrets Scanner for Codebases

## What This Is

Portia is a Go CLI tool that scans source code directories and git history for leaked secrets: API keys, passwords, tokens, private keys, connection strings. It uses 150 detection rules, Shannon entropy analysis, a 5-layer false positive filter, and optional Have I Been Pwned breach verification. Files are split into 50-line chunks and processed through a bounded concurrent worker pool, with results reported in terminal, JSON, or SARIF format.

The name comes from Shakespeare's *The Merchant of Venice*, where Portia is the one who exposes what's hidden in the contract. This tool does the same for your codebase.

## Why This Matters

Hardcoded secrets in source code are one of the most common and most damaging security mistakes in software development. This isn't theoretical. Here are three incidents that show exactly why this matters:

**Uber, 2016 - Hardcoded AWS Keys on GitHub**
Two Uber engineers committed AWS access keys to a private GitHub repository. Attackers who gained access to that repo used the keys to reach an S3 bucket containing the personal information of 57 million riders and drivers. Uber paid $148 million in settlements. The keys were sitting in the repo for months before the breach. A tool like Portia, scanning on every commit, would have flagged `AKIA...` patterns immediately using the `aws-access-key-id` rule defined at `internal/rules/builtin.go:22-31`. The regex `\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b` catches exactly this format.

**CircleCI, January 2023 - Secrets in CI Configuration**
An attacker compromised a CircleCI engineer's laptop and used the session cookie to access internal systems. They then extracted customer secrets that were stored as environment variables in CI/CD pipelines. The advisory (CCI-2023-001) urged all customers to rotate every secret stored in CircleCI. The root issue: secrets were configured as plaintext values in CI configs rather than fetched from vaults at runtime. If those config files had been scanned before deployment, the problem would have been caught. Portia's generic rules for `password`, `secret`, `token`, and `api_key` assignments target exactly this pattern.

**Codecov, April 2021 - Supply Chain Attack via Exfiltrated Tokens**
Attackers modified Codecov's bash uploader script to exfiltrate environment variables from CI environments. Every company using Codecov's bash uploader leaked whatever tokens and keys were present in their CI environment, including credentials for GitHub, AWS, and internal services. The modified script ran for two months before detection. Among the affected companies: Twitch, HashiCorp, Confluent. Portia detects tokens for GitHub (`ghp_`, `gho_`, `ghs_`), HashiCorp Vault (`hvs.`, `hvb.`, `hvr.`), and many other providers, all defined in `internal/rules/builtin.go`.

The common thread: secrets sitting in code or configs where automated tools could have caught them. That's what this project builds.

## What You'll Learn

Building this project teaches you both security concepts and real Go engineering patterns.

**Security Concepts:**
- **Secret sprawl and why it happens** - Why developers keep hardcoding credentials despite knowing better, and the systemic solutions (environment variables, vault integrations, pre-commit hooks)
- **Shannon entropy for anomaly detection** - Using information theory to distinguish random API keys from normal English text. The math is at `internal/rules/entropy.go`.
- **k-Anonymity** - Troy Hunt's protocol for checking if a secret appears in breach databases without revealing the secret itself. Implementation at `internal/hibp/client.go`.
- **False positive reduction** - Why naive regex scanning produces thousands of garbage results, and the 5-layer filtering approach that makes output actually useful. See `internal/engine/filter.go`.
- **SARIF for CI integration** - The industry-standard format that GitHub, Azure DevOps, and other CI platforms consume to show security findings inline on pull requests.

**Technical Skills (Go-specific):**
- **errgroup concurrent pipelines** - Bounded worker pools using `golang.org/x/sync/errgroup` with channel-based communication. The full pipeline is at `internal/engine/pipeline.go`.
- **Cobra CLI framework** - Building a multi-command CLI with persistent flags, config file support, and subcommands. Root command at `internal/cli/root.go`.
- **go-git library** - Programmatic git history traversal, commit walking, blob reading, and staged file scanning without shelling out to `git`. See `internal/source/git.go`.
- **Circuit breaker pattern** - Using `gobreaker` to prevent cascading failures when external APIs (HIBP) are down. Configured at `internal/hibp/client.go`.
- **LRU caching** - Bounded in-memory caching with `hashicorp/golang-lru` to avoid redundant API calls. See `internal/hibp/client.go`.
- **TOML configuration** - Layered config resolution with CLI flags > config file > defaults. Supports both `.portia.toml` and `pyproject.toml` (`[tool.portia]` table). See `internal/config/config.go` and `internal/cli/root.go`.

**Tools and Techniques:**
- **Regex crafting for security** - Writing patterns that match real credential formats (AWS key prefixes, GitHub token formats, Stripe key patterns) while avoiding false positives
- **just task runner** - Using `Justfile` as an alternative to Makefiles for build, test, lint workflows
- **golangci-lint** - Static analysis configuration at `.golangci.yml` for enforcing code quality

## Prerequisites

**Required knowledge:**
- **Go basics** - You need to understand goroutines, channels, interfaces, and structs. The pipeline uses all of these heavily. If `go func()` or `chan types.Chunk` looks unfamiliar, work through the Go Tour first.
- **Regular expressions** - The detection engine is built on regex. You should know capture groups, quantifiers, character classes, and non-capturing groups. The rules at `internal/rules/builtin.go` use all of these.
- **Git fundamentals** - You should understand commits, branches, staging, and blobs. The git scanner walks these structures programmatically.

**Tools you'll need:**
- **Go 1.22+** - Uses `range` over integers (e.g., `for range p.workers` at `internal/engine/pipeline.go:53`), which requires Go 1.22
- **just** - Task runner. Install with `cargo install just` or your package manager
- **git** - For the git history scanning features

**Helpful but not required:**
- **Information theory** - Understanding entropy helps, but the concepts doc explains it from scratch
- **SARIF specification** - The OASIS standard for static analysis results. You can read the output without knowing the spec.

## Installation

Three ways to install Portia:

**Option 1: Install script** (no Go required)
```bash
curl -fsSL https://raw.githubusercontent.com/CarterPerez-dev/portia/main/install.sh | bash
```

This downloads a pre-built binary for your platform (Linux/macOS, amd64/arm64). If no binary is available, it falls back to building from source with Go.

**Option 2: Go install**
```bash
go install github.com/CarterPerez-dev/portia/cmd/portia@latest
```

Requires Go 1.24+. The binary is placed in your `$GOPATH/bin` (or `$GOBIN`).

**Option 3: Build from source**
```bash
cd PROJECTS/intermediate/secrets-scanner
go build -o portia ./cmd/portia
```

This is the path you'll use when working through this project and making changes to the code.

## Quick Start

Get the project running:
```bash
cd PROJECTS/intermediate/secrets-scanner

./portia scan ./testdata/fixtures

./portia scan --format json ./testdata/fixtures

./portia scan --hibp ./testdata/fixtures

./portia git --depth 10 .

./portia git --staged .
```

Expected output on the test fixtures: colored terminal output showing detected secrets with severity levels, rule IDs, file paths, line numbers, entropy scores, and masked secret values.

To initialize a config file:
```bash
./portia init
```

This creates `.portia.toml` with default settings. Edit it to disable rules, set excludes, or enable HIBP checking by default.

For Python projects, you can use `pyproject.toml` instead:
```bash
./portia pyproject
```

This creates a `pyproject.toml` with a `[tool.portia]` section. Portia automatically reads from `pyproject.toml` when no `.portia.toml` is found.

## Project Structure

```
secrets-scanner/
├── cmd/portia/main.go           # Entry point, calls cli.Execute()
├── internal/
│   ├── cli/                     # Cobra commands
│   │   ├── root.go              # Root command, flag definitions, config init
│   │   ├── scan.go              # `portia scan` - directory scanning
│   │   ├── git.go               # `portia git` - git history scanning
│   │   ├── init.go              # `portia init` + `portia pyproject` - create config files
│   │   └── config.go            # `portia config` - show current config
│   ├── config/
│   │   └── config.go            # TOML config loader, defaults, search paths
│   ├── engine/
│   │   ├── detector.go          # Applies rules to chunks, entropy validation
│   │   ├── filter.go            # Stopwords, placeholders, templates, allowlists
│   │   └── pipeline.go          # errgroup worker pool, deduplication
│   ├── hibp/
│   │   └── client.go            # k-anonymity API client, LRU cache, circuit breaker
│   ├── reporter/
│   │   ├── reporter.go          # Reporter interface and factory
│   │   ├── terminal.go          # Colored terminal output with masking
│   │   ├── json.go              # JSON output format
│   │   └── sarif.go             # SARIF v2.1.0 output for CI integration
│   ├── rules/
│   │   ├── builtin.go           # 150 detection rules covering AWS, GitHub, etc.
│   │   ├── entropy.go           # Shannon entropy calculator and charset detection
│   │   └── registry.go          # Rule storage, keyword matching, global allowlists
│   ├── source/
│   │   ├── source.go            # Source interface definition
│   │   ├── directory.go         # Filesystem walker with 50-line chunking
│   │   └── git.go               # Git history scanner using go-git
│   └── ui/                      # Colors, spinner, banner, symbols
├── pkg/types/types.go           # Core types: Finding, Chunk, Rule, Severity
├── testdata/fixtures/            # Test secrets for integration testing
├── Justfile                      # Task runner
└── .golangci.yml                 # Linter configuration
```

## Development Commands

This project uses [`just`](https://github.com/casey/just) as a command runner. Run `just` with no arguments to see all available commands.

| Command | Description |
|---------|-------------|
| `just lint` | Run golangci-lint |
| `just lint-fix` | Run golangci-lint with auto-fix |
| `just format` | Format code via golangci-lint |
| `just vet` | Run `go vet` |
| `just tidy` | Run `go mod tidy` |
| `just test` | Run all tests with race detector |
| `just test-v` | Run tests with verbose output |
| `just cover` | Run tests with coverage summary |
| `just cover-html` | Generate HTML coverage report |
| `just ci` | Run lint + test (full CI check) |
| `just check` | Run lint + vet |
| `just run <args>` | Run portia with arguments (e.g., `just run scan .`) |
| `just dev-scan` | Scan testdata directory |
| `just dev-git` | Scan current repo git history |
| `just dev-json` | Scan testdata with JSON output |
| `just dev-sarif` | Scan testdata with SARIF output |
| `just dev-rules` | List all detection rules |
| `just build` | Production build to `bin/portia` |
| `just install` | `go install` to `$GOPATH/bin` |
| `just info` | Show project/Go/OS info |
| `just clean` | Remove build artifacts |

## Next Steps

Work through the documents in order:

1. **01-CONCEPTS.md** - Security concepts: secret sprawl, Shannon entropy, regex-based detection, false positive filtering, k-anonymity, SARIF
2. **02-ARCHITECTURE.md** - System design: pipeline architecture, concurrency model, data flow, component interactions
3. **03-IMPLEMENTATION.md** - Code walkthrough: every key file explained with line references
4. **04-CHALLENGES.md** - Extensions: pre-commit hooks, custom rules, incremental scanning, GitHub Actions

## Common Issues

**"No secrets detected" on real code:**
Your code might be clean. Try scanning `testdata/fixtures/` first to confirm the tool works. If scanning real code, check that you're not excluding too many paths. Use `--verbose` to see which files are being scanned.

**Git scan is slow:**
Use `--depth` to limit how many commits to scan. `--depth 100` scans the last 100 commits instead of the entire history. For a quick check, use `--staged` to scan only staged changes.

**Too many false positives:**
Edit `.portia.toml` to add paths or values to the allowlist. You can also disable specific rules with `rules.disable = ["generic-password"]`. The filter system (stopwords, placeholders, templates) handles most cases, but project-specific patterns may need custom allowlisting.

**HIBP checking fails:**
The HIBP API has rate limits. The circuit breaker at `internal/hibp/client.go` will open after 5 consecutive failures, preventing further requests for 60 seconds. This is by design. If the API is consistently unavailable, the scan still completes without breach data.

**Build errors with Go version:**
This project uses `for range p.workers` syntax which requires Go 1.22+. Check your version with `go version`.

## Related Projects

Other projects in this repository that complement secrets scanning:

- **api-security-scanner** (`PROJECTS/intermediate/api-security-scanner/`) - Scans APIs for security misconfigurations. Where Portia finds secrets in code, this project tests whether APIs are properly secured at runtime.
- **docker-security-audit** (`PROJECTS/intermediate/docker-security-audit/`) - Audits Docker images and configs for security issues. Complements Portia by checking container environments where secrets are often exposed via environment variables.
- **api-rate-limiter** (`PROJECTS/advanced/api-rate-limiter/`) - Implements rate limiting algorithms. Relevant because Portia's HIBP client uses the same circuit breaker pattern to handle external API rate limits gracefully.
