# Bomber - SBOM Generator & Vulnerability Matcher

## What This Is

Bomber is a Go CLI tool that scans project directories for dependencies across Go, Node.js, and Python ecosystems, constructs a dependency graph with cycle detection and depth tracking, generates SBOM documents in SPDX 2.3 and CycloneDX 1.5 JSON formats, and cross-references every package against the OSV and NVD vulnerability databases. It includes a policy engine that gates CI/CD pipelines by enforcing severity thresholds, dependency depth limits, and vulnerability age constraints.

## Why This Matters

Software supply chain attacks have become one of the most effective and fastest-growing categories of breaches. Attackers target the code you didn't write: the libraries, frameworks, and transitive dependencies your project pulls in. Without visibility into what's actually in your dependency tree, you can't defend against it. That's what SBOMs solve, and that's why governments and enterprises are now mandating them.

**Real world scenarios where this applies:**

- **SolarWinds Orion, 2020** - Attackers compromised the build pipeline of SolarWinds' Orion platform and injected a backdoor (SUNBURST) into a routine software update. 18,000 organizations installed the update, including the US Treasury, DHS, and FireEye. The core problem: no organization consuming Orion had visibility into what code was actually inside it. An SBOM wouldn't have prevented the injection, but it would have given defenders a machine-readable manifest to immediately answer "do we use this component?" when the advisory dropped, instead of the weeks of manual triage that actually happened.

- **Log4Shell (CVE-2021-44228), December 2021** - A critical RCE vulnerability in Apache Log4j affected virtually every Java application. CVSS 10.0. Organizations spent weeks determining whether they were exposed because Log4j was buried as a transitive dependency three or four levels deep. Companies with SBOMs could query their records and know within minutes. Everyone else was reading JAR manifests by hand. This is the exact problem Bomber's dependency graph with depth tracking solves: `pkg.DepthLevel` tells you exactly how far removed a vulnerable library is from your direct dependencies.

- **event-stream incident (npm), 2018** - A malicious maintainer gained commit access to the popular `event-stream` npm package and added a dependency on `flatmap-stream`, which contained code targeting the Copay Bitcoin wallet. The attack targeted a transitive dependency that most consumers never knew existed. Bomber's graph construction traces these chains, and the policy engine's `max_depth` rule lets you set a ceiling on how deep your transitive dependency tree is allowed to go.

## What You'll Learn

Building this project teaches you how SBOM generation and vulnerability matching work at the protocol level, not just as abstract concepts.

**Security Concepts:**
- **Software Bill of Materials (SBOM)** - What an SBOM actually contains, why Executive Order 14028 mandated them for US federal suppliers, and the difference between the two dominant formats (SPDX and CycloneDX)
- **Package URL (PURL) specification** - The universal addressing scheme for software packages across ecosystems. PURL is how bomber identifies `pkg:golang/golang.org/x/net@v0.1.0` vs `pkg:npm/express@4.18.2` vs `pkg:pypi/requests@2.31.0` using a single format
- **CVSS v3.1 scoring** - The math behind vulnerability severity scores. Bomber implements the full CVSS v3.1 base score calculator at `internal/vuln/cvss.go`, including the ISS formula, scope-dependent impact adjustments, and the round-up function from the CVSS specification
- **Vulnerability database protocols** - How the OSV batch query API and NVD REST API v2.0 work, including PURL-based lookups, CPE matching, rate limiting, and the differences between the two

**Technical Skills:**
- **Multi-ecosystem dependency parsing** - Parsing `go.mod`/`go.sum`, `package.json`/`pnpm-lock.yaml`, and `pyproject.toml`/`uv.lock` to extract package names, versions, and dependency relationships
- **Directed graph construction** - Building dependency graphs with BFS-based depth computation and DFS-based cycle detection at `internal/graph/graph.go`
- **Interface-driven architecture** - Using Go interfaces (`DependencyParser`, `vuln.Client`) to make the system extensible without modifying core logic
- **SQLite caching** - TTL-based response caching with `modernc.org/sqlite` (a pure-Go SQLite implementation) to avoid redundant API calls

**Tools and Techniques:**
- **Cobra CLI framework** - Building a multi-command CLI (`scan`, `generate`, `vuln`, `check`) with persistent flags, custom help functions, and signal handling for graceful cancellation
- **SPDX 2.3 and CycloneDX 1.5 JSON output** - Generating spec-compliant SBOM documents with proper namespacing, external references, and relationship tracking
- **Policy-as-code for CI/CD** - YAML-based policy files evaluated at `internal/policy/engine.go` that exit with code 1 on violation, designed to drop into any CI pipeline

## Prerequisites

**Required knowledge:**
- **Go basics** - You need to understand interfaces, structs, goroutines, and the standard library's `encoding/json`, `net/http`, and `os` packages. The code uses all of these heavily.
- **Dependency management concepts** - You should know what a lockfile is, what "direct" vs "transitive" dependencies means, and roughly how `go.mod`, `package.json`, and `pyproject.toml` work.
- **HTTP APIs** - The vulnerability matchers make HTTP requests to external services. You should understand request/response cycles, status codes, and JSON serialization.

**Tools you'll need:**
- **Go 1.25+** - The `go.mod` declares `go 1.25.0`
- **just** - Task runner for build, test, and lint commands. Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`
- **golangci-lint** - For linting. The project configures 14 linters at `.golangci.yml`

**Helpful but not required:**
- **SPDX specification** - Reading the SPDX 2.3 JSON schema helps understand the output format, but the implementation guide covers the key fields
- **CycloneDX specification** - Same for CycloneDX 1.5
- **SQL basics** - The cache uses SQLite, but the queries are simple

## Installation

Three ways to install Bomber:

**Option 1: Go install**
```bash
go install github.com/CarterPerez-dev/bomber/cmd/bomber@latest
```

Requires Go 1.25+. The binary is placed in your `$GOPATH/bin` (or `$GOBIN`).

**Option 2: Install script** (no Go required)
```bash
curl -fsSL https://raw.githubusercontent.com/CarterPerez-dev/Cybersecurity-Projects/main/PROJECTS/intermediate/sbom-generator-vulnerability-matcher/install.sh | bash
```

This downloads a pre-built binary for your platform (Linux/macOS, amd64/arm64). Falls back to building from source with Go if no binary is available.

**Option 3: Build from source**
```bash
cd PROJECTS/intermediate/sbom-generator-vulnerability-matcher
go build -ldflags="-s -w" -o bin/bomber ./cmd/bomber
```

This is the path you'll use when working through this project and making changes.

## Quick Start

```bash
cd PROJECTS/intermediate/sbom-generator-vulnerability-matcher

bomber scan .                                # scan this project's own dependencies
bomber generate . --sbom-format spdx         # generate SPDX 2.3 SBOM
bomber generate . --sbom-format cyclonedx    # generate CycloneDX 1.5 SBOM
bomber vuln .                                # check for known vulnerabilities
bomber check . --policy policy.yaml          # evaluate against a policy
```

Expected output from `bomber scan .`: a summary showing the number of packages (direct and transitive), detected ecosystems, and any circular dependencies.

For vulnerability scanning with NVD enrichment, set an API key:
```bash
export BOMBER_NVD_API_KEY="your-key-here"
bomber vuln .
```

## Project Structure

```
sbom-generator-vulnerability-matcher/
├── cmd/bomber/main.go              # Entry point, calls cli.Execute()
├── internal/
│   ├── cli/                        # Cobra commands
│   │   ├── root.go                 # Root command, global flags, signal handling
│   │   ├── scan.go                 # `bomber scan` - dependency discovery
│   │   ├── generate.go             # `bomber generate` - SBOM output
│   │   ├── vuln.go                 # `bomber vuln` - vulnerability matching
│   │   └── check.go                # `bomber check` - policy evaluation
│   ├── config/
│   │   └── config.go               # Tool metadata and API constants
│   ├── graph/
│   │   └── graph.go                # Graph traversal, cycle detection, merging
│   ├── parser/
│   │   ├── parser.go               # DependencyParser interface
│   │   ├── registry.go             # Parser registry and auto-detection
│   │   ├── gomod.go                # Go ecosystem: go.mod, go.sum, go mod graph
│   │   ├── node.go                 # Node ecosystem: package.json, pnpm-lock.yaml
│   │   └── python.go               # Python ecosystem: pyproject.toml, uv.lock
│   ├── policy/
│   │   ├── rules.go                # Policy YAML loading
│   │   └── engine.go               # Policy evaluation: severity, depth, age
│   ├── report/
│   │   ├── terminal.go             # Colored terminal output
│   │   └── json.go                 # JSON report output
│   ├── sbom/
│   │   ├── spdx.go                 # SPDX 2.3 JSON generator
│   │   └── cyclonedx.go            # CycloneDX 1.5 JSON generator
│   ├── ui/                         # Colors, spinner, banner, symbols
│   └── vuln/
│       ├── client.go               # Vulnerability client interface
│       ├── osv.go                   # OSV batch query API client
│       ├── nvd.go                   # NVD REST API v2.0 client with rate limiting
│       ├── cvss.go                  # CVSS v3.1 base score calculator
│       └── cache.go                # SQLite-backed response cache with TTL
├── pkg/types/types.go              # Core types: Package, Vulnerability, ScanResult
├── testdata/                       # Test fixtures for all ecosystems
├── Justfile                        # Task runner
└── .golangci.yml                   # Linter configuration (14 linters)
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
| `just run <args>` | Run bomber with arguments (e.g., `just run scan .`) |
| `just dev-scan` | Scan current directory |
| `just dev-generate` | Generate CycloneDX SBOM for current directory |
| `just dev-vuln` | Run vulnerability scan on current directory |
| `just build` | Production build to `bin/bomber` |
| `just install` | `go install` to `$GOPATH/bin` |
| `just info` | Show project/Go/OS info |
| `just clean` | Remove build artifacts |

## Next Steps

Work through the documents in order:

1. **01-CONCEPTS.md** - Security concepts: SBOMs, supply chain attacks, SPDX vs CycloneDX, PURL, CVSS scoring, vulnerability databases
2. **02-ARCHITECTURE.md** - System design: pipeline architecture, data flow, component interactions, design patterns
3. **03-IMPLEMENTATION.md** - Code walkthrough: every key file explained with code snippets
4. **04-CHALLENGES.md** - Extensions: new ecosystems, SARIF output, license compliance, GitHub Actions integration

## Common Issues

**"No ecosystems detected":**
Bomber looks for `go.mod`, `package.json`, or `pyproject.toml` in the target directory and its subdirectories. Make sure the path you're scanning contains at least one of these files. Use `--verbose` to see what directories are being traversed.

**Vulnerability scan returns empty results:**
The OSV API is the primary source and requires no authentication. If it's returning empty, the packages may genuinely have no known vulnerabilities. Try scanning a project with a known vulnerable dependency like `golang.org/x/net@v0.1.0` to verify the tool works.

**NVD queries are slow:**
Without an API key, NVD rate-limits to one request every 1.7 seconds. With a key (`export BOMBER_NVD_API_KEY=...`), the rate increases to one request every 200ms. NVD queries are per-package (not batched like OSV), so large dependency trees take time.

**Cache is stale:**
The SQLite cache defaults to a 24-hour TTL. Use `--no-cache` to bypass it, or delete `~/.bomber/cache.db` to clear it entirely.

**Build errors with Go version:**
This project requires Go 1.25+. Check your version with `go version`.

## Related Projects

Other projects in this repository that complement SBOM generation:

- **secrets-scanner** (`PROJECTS/intermediate/secrets-scanner/`) - Scans source code for hardcoded secrets. Where Bomber audits your dependency supply chain, Portia audits what you're accidentally shipping inside your own code.
- **docker-security-audit** (`PROJECTS/intermediate/docker-security-audit/`) - Audits Docker images for security issues. Container images have their own dependency trees (OS packages, installed binaries) that also benefit from SBOM analysis.
- **api-security-scanner** (`PROJECTS/intermediate/api-security-scanner/`) - Scans APIs for misconfigurations. Complements Bomber by testing runtime security posture rather than build-time dependency risk.
