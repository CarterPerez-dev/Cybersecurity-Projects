# Extension Challenges

You've built the base project. Now make it yours by extending it with new features.

These challenges are ordered by difficulty. Start with the easier ones to build confidence, then tackle the harder ones when you want to dive deeper.

## Easy Challenges

### Challenge 1: Add a Blocked Packages Policy Rule

**What to build:** A new policy rule that fails when specific packages are present in the dependency tree, regardless of whether they have vulnerabilities.

**Why it's useful:** Some packages are known-risky even without CVEs. Packages with single maintainers, packages that have been abandoned, or packages your organization has decided to ban. The `event-stream` attack wouldn't have triggered a vulnerability scan, but a "blocked packages" list would have caught `flatmap-stream` immediately.

**What you'll learn:**
- Extending the policy YAML schema
- Adding a new evaluation path in the policy engine
- Working with the dependency graph to check package names

**Hints:**
- Add `blocked_packages: ["lodash", "moment"]` to the `Policy` struct in `internal/policy/rules.go`
- In `internal/policy/engine.go`, iterate over all packages in all graphs and check against the blocked list
- The check should match on package name, not PURL, so you can block `lodash` without specifying a version

**Test it works:**
Create a policy file with `blocked_packages: ["lodash"]` and run `bomber check testdata/node-project --policy your-policy.yaml`. It should fail because the node test fixture depends on lodash.

### Challenge 2: Add Markdown Report Output

**What to build:** A `--format markdown` option that outputs the vulnerability report as a GitHub-flavored Markdown table.

**Why it's useful:** CI/CD pipelines often post results as PR comments. A Markdown table renders cleanly in GitHub, GitLab, and Bitbucket PR discussions.

**What you'll learn:**
- Adding a new output format to the report layer
- Working with `io.Writer` for composable output
- Extending CLI flag handling

**Hints:**
- Create `internal/report/markdown.go` with functions matching the terminal report signatures
- The vulnerability table should have columns: Package, Vulnerability ID, Severity, CVSS Score, Fix Version
- Register the format in `internal/cli/scan.go`, `vuln.go`, and `check.go` alongside `terminal` and `json`

**Test it works:**
Run `bomber vuln testdata/go-project --format markdown` and verify the output renders correctly when pasted into a GitHub issue.

### Challenge 3: Add `--direct-only` Flag

**What to build:** A flag that filters scan and vulnerability results to only show direct dependencies, ignoring transitives.

**Why it's useful:** When triaging vulnerabilities, direct dependencies are actionable (you can bump the version in your manifest). Transitive vulnerabilities require waiting for your direct dependency to update, which is a different workflow.

**What you'll learn:**
- Adding persistent flags to Cobra commands
- Filtering `ScanResult` and `VulnReport` based on `Package.Direct`

**Hints:**
- Add the flag in `internal/cli/root.go` with `rootCmd.PersistentFlags().BoolVar`
- Filter in `queryVulns` before sending to the API: only include packages where `pkg.Direct == true`
- Also filter `ScanResult` for the scan summary counts

**Test it works:**
Compare output of `bomber vuln testdata/go-project` with and without `--direct-only`. The direct-only version should show fewer packages.

## Intermediate Challenges

### Challenge 4: Add Rust Ecosystem Support

**What to build:** A parser for Rust projects that reads `Cargo.toml` and `Cargo.lock`.

**Real world application:** Rust is growing fast in systems programming and security tooling. Cargo.lock has a well-defined format with explicit dependency sections.

**What you'll learn:**
- Implementing the `DependencyParser` interface for a new ecosystem
- TOML parsing for Cargo's format (different from Python's pyproject.toml)
- PURL construction for the `cargo` type

**Implementation approach:**

1. **Add `EcosystemRust`** to the `Ecosystem` enum in `pkg/types/types.go` with a `String()` case returning `"rust"`

2. **Create `internal/parser/cargo.go`:**
   - `Detect()`: check for `Cargo.toml`
   - `Parse()`: read `Cargo.toml` for project name/version and direct dependencies, read `Cargo.lock` for resolved versions and the full dependency tree
   - PURLs follow the format `pkg:cargo/serde@1.0.200`

3. **Register** in `internal/parser/registry.go`

4. **Create test fixtures** in `testdata/rust-project/` with a `Cargo.toml` and `Cargo.lock`

**Hints:**
- Cargo.lock has `[[package]]` TOML arrays with `name`, `version`, `source`, and `checksum` fields
- Dependencies in Cargo.lock are listed as `dependencies = ["dep1", "dep2 0.3.0 (registry+...)"]`
- The tricky part is parsing the dependency format, which can include version and source constraints

**Test it works:**
Create a test Rust project fixture and run `bomber scan testdata/rust-project`. Verify the package count and ecosystem detection.

### Challenge 5: Add SARIF Output for CI Integration

**What to build:** A `--format sarif` option that outputs vulnerability findings in SARIF v2.1.0 format for integration with GitHub Code Scanning, Azure DevOps, and other CI platforms.

**Real world application:** GitHub Actions can ingest SARIF files and display findings inline on pull requests. This is how tools like CodeQL, Snyk, and Trivy surface results in the GitHub UI.

**What you'll learn:**
- SARIF specification structure (runs, results, rules, locations)
- Building complex JSON documents with nested structs
- CI/CD integration patterns

**Implementation approach:**

1. **Create `internal/report/sarif.go`** with SARIF v2.1.0 types:
   - `sarifLog` with `$schema`, `version`, `runs`
   - Each vulnerability becomes a `result` with a `ruleId`, `message`, and `level`
   - Map CVSS severity to SARIF levels: CRITICAL/HIGH = "error", MEDIUM = "warning", LOW = "note"

2. **Map Bomber data to SARIF fields:**
   - Rule ID = vulnerability ID (e.g., `CVE-2023-44487`)
   - Rule shortDescription = vulnerability summary
   - Result message = package PURL + fix version if available
   - Level = severity mapping

3. **Add format handling** in the CLI commands

**Hints:**
- The SARIF schema URL is `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json`
- GitHub Actions uses `github/codeql-action/upload-sarif@v3` to ingest SARIF files
- Look at the secrets-scanner project's `internal/reporter/sarif.go` for a working SARIF implementation in the same codebase

**Test it works:**
Run `bomber vuln testdata/go-project --format sarif | jq .` and verify it's valid SARIF. Upload it to GitHub Code Scanning in a test repo.

### Challenge 6: Add License Detection

**What to build:** Extract license information from dependencies and add it to the SBOM output.

**Real world application:** SBOMs aren't just for vulnerability tracking. License compliance is the other major use case. Organizations need to know if they're using GPL-licensed code in proprietary software.

**What you'll learn:**
- SPDX license expression syntax
- Extending the `Package` type with new fields
- Extracting license data from ecosystem-specific sources

**Implementation approach:**

1. **Add `License string` field** to `types.Package`

2. **Go parser:** Extract license from `go.sum` or by running `go list -m -json` which includes a `Dir` field you can scan for LICENSE files

3. **Node parser:** Read the `license` field from `package.json` entries in `pnpm-lock.yaml`

4. **Python parser:** Read the `license` field from package metadata (this may require querying PyPI or reading `dist-info`)

5. **Update SBOM generators:**
   - SPDX: set `licenseConcluded` and `licenseDeclared` fields
   - CycloneDX: add `licenses` array to components

**Hints:**
- Start with just the Node parser, which has license info readily available in `package.json`
- SPDX license identifiers are standardized: "MIT", "Apache-2.0", "GPL-3.0-only"
- For packages where license can't be determined, use "NOASSERTION" (SPDX) or omit the field (CycloneDX)

## Advanced Challenges

### Challenge 7: Add Reachability Analysis

**What to build:** Determine whether a vulnerable function is actually called by the project, not just imported as a dependency.

**Why this is hard:** A project can depend on `golang.org/x/net` without ever calling the vulnerable HTTP/2 functions. Knowing the dependency is present is useful; knowing whether the vulnerable code path is reachable is much more actionable.

**What you'll learn:**
- Static analysis with Go's `go/ast` and `go/types` packages
- Call graph construction
- False positive reduction in vulnerability scanning

**Architecture changes needed:**

```
┌───────────────────┐     ┌───────────────────┐
│ Vulnerability     │     │ Call Graph         │
│ Match (existing)  │────▶│ Analysis (new)     │
│ pkg + vuln ID     │     │ symbols reachable? │
└───────────────────┘     └───────────┬────────┘
                                      │
                                      ▼
                          ┌───────────────────┐
                          │ Enriched Match    │
                          │ + reachable: bool │
                          └───────────────────┘
```

**Implementation steps:**

1. **Research phase:** Study Go's `golang.org/x/tools/go/callgraph` package and the `vulncheck` approach used by `govulncheck`

2. **Design phase:** Decide whether to do import-level analysis (which packages are imported) or symbol-level analysis (which functions are called). Import-level is simpler but less precise.

3. **Implementation phase:**
   - Parse Go source files with `go/ast`
   - Build an import graph
   - Cross-reference with vulnerability affected symbols
   - Add `Reachable bool` to `VulnMatch`

4. **Testing phase:** Create test fixtures with both reachable and unreachable vulnerable imports

**Gotchas:**
- Only feasible for Go projects (Go's tooling supports this analysis). For Node and Python, import-level analysis is the practical ceiling.
- Reflection and dynamic dispatch defeat static analysis. You'll need to flag these cases as "unknown reachability" rather than "not reachable."

### Challenge 8: Build a Dependency Diff Tool

**What to build:** A `bomber diff` command that compares two SBOMs and shows what changed: added packages, removed packages, version changes, new vulnerabilities, resolved vulnerabilities.

**Why this is hard:** Diffing SBOMs requires normalizing identifiers across formats, handling renames and version bumps, and presenting changes in a way that's actionable.

**What you'll learn:**
- SBOM parsing (the reverse of generation)
- Set operations on dependency data
- Changelog presentation for security context

**Implementation steps:**

1. **Create `internal/diff/diff.go`** with types:
   ```
   Added []Package
   Removed []Package
   Changed []PackageChange  (old version → new version)
   NewVulns []VulnMatch
   ResolvedVulns []VulnMatch
   ```

2. **Add `bomber diff old.json new.json`** command

3. **Handle both SPDX and CycloneDX** input formats by detecting the format from the JSON structure

4. **Run vulnerability scans** on both the old and new package sets to compute the vulnerability delta

**Gotchas:**
- PURLs without versions (possible in fallback parsing) make diffing ambiguous
- A package can be "changed" in one ecosystem and "removed + added" in another if it moved between lockfiles

### Challenge 9: Add GitHub Actions Integration

**What to build:** A complete GitHub Actions workflow that runs Bomber on every PR, caches results between runs, posts a comment with the vulnerability summary, and blocks merging if the policy fails.

**Why this is hard:** CI integration involves environment detection, artifact caching, GitHub API interaction, and idempotent comment posting (update existing comment rather than creating duplicates).

**What you'll learn:**
- GitHub Actions workflow syntax and caching
- GitHub REST API for PR comments
- CI/CD security scanning patterns used in production

**Implementation steps:**

1. **Create `.github/workflows/sbom-check.yml`:**
   - Trigger on `pull_request`
   - Install Bomber (use the install script or `go install`)
   - Run `bomber check . --policy policy.yaml --format json`
   - Cache `~/.bomber/cache.db` between runs

2. **Create a comment script** that reads Bomber's JSON output and formats it as a Markdown PR comment using `gh api`

3. **Handle idempotent comments:** search for existing Bomber comments on the PR and update them instead of creating new ones

4. **Add status check integration:** use `bomber check` exit code to pass/fail the check

**Gotchas:**
- The cache path needs to be relative or configurable for CI caching
- PR comment permissions require `pull-requests: write` in the workflow
- Rate limits on the GitHub API need handling for monorepos with many PRs

## Expert Challenges

### Challenge 10: Build a Vulnerability Database Mirror

**What to build:** A local mirror of the OSV database that Bomber queries instead of the live API. This eliminates network dependency and enables air-gapped environments.

**Prerequisites:** You should have completed the cache challenge and understand SQLite schema design.

**What you'll learn:**
- Database synchronization patterns
- Bulk data ingestion and indexing
- Offline security scanning (required in air-gapped government/defense environments)

**Planning this feature:**

Before you code, think through:
- How do you handle initial sync vs incremental updates?
- What's the storage footprint? (OSV has ~200,000+ vulnerability records)
- How do you query the local database with the same PURL-based interface?

**Implementation phases:**

**Phase 1: Database schema**
- Design SQLite tables for vulnerabilities, affected packages, and version ranges
- Index by PURL prefix (ecosystem type) for fast lookups

**Phase 2: Sync engine**
- Use OSV's bulk export (Google Cloud Storage buckets) or the list endpoint
- Implement incremental sync based on last-modified timestamps

**Phase 3: Local query client**
- Implement `vuln.Client` interface backed by the local database
- Replace HTTP queries with SQL queries
- Handle version range matching locally

**Phase 4: CLI integration**
- Add `bomber mirror sync` command to trigger sync
- Add `--offline` flag to use only the local mirror
- Fall back to API if mirror is stale

**Success criteria:**
- [ ] Initial sync completes in under 10 minutes
- [ ] Incremental sync completes in under 30 seconds
- [ ] Query results match live API results for the test fixtures
- [ ] Works without network access after initial sync
- [ ] Storage is under 500MB for the full OSV database

## Performance Challenges

### Challenge: Handle 10,000-Dependency Monorepos

**The goal:** Make Bomber handle a monorepo with 10,000+ total dependencies without running out of memory or taking more than 60 seconds (excluding API calls).

**Current bottleneck:** The dependency graph stores all packages in memory. SBOM generation serializes the entire graph to JSON. For very large projects, both the graph and the JSON output can be large.

**Optimization approaches:**

**Approach 1: Streaming SBOM generation**
- Instead of building the full JSON document in memory, stream SPDX/CycloneDX output using `json.Encoder`
- Gain: Constant memory for SBOM generation regardless of graph size
- Tradeoff: Can't pretty-print with `json.MarshalIndent` (need custom formatting)

**Approach 2: Parallel parsing**
- Run ecosystem parsers concurrently with `errgroup`
- Gain: A monorepo with Go, Node, and Python projects scans 3x faster
- Tradeoff: Need to synchronize graph accumulation

**Benchmark it:**
```bash
time bomber scan ./large-monorepo
time bomber generate ./large-monorepo --sbom-format cyclonedx > /dev/null
```

Target metrics:
- Scan phase: < 5 seconds for 10,000 packages
- SBOM generation: < 10 seconds, < 200MB RSS

### Challenge: Reduce Binary Size

**The goal:** Get the Bomber binary under 5MB (current is larger due to the SQLite dependency).

**Optimization approaches:**

- Use `go build -ldflags="-s -w"` (already in the Justfile, strips debug info and symbol table)
- Consider `upx` compression for distribution
- Profile the binary with `go tool nm` to identify large dependencies
- Evaluate whether `modernc.org/sqlite` can be replaced with a lighter cache (e.g., bbolt) if SQLite features aren't needed

## Security Challenges

### Challenge: Add SBOM Signing

**What to implement:** Cryptographic signing of generated SBOMs so consumers can verify they haven't been tampered with.

**Threat model:** An attacker who can modify SBOMs in transit or at rest could hide vulnerabilities or add fake clean reports. Signing prevents this.

**Implementation:**
- Use `cosign` (Sigstore) or `notation` (Notary v2) for keyless signing
- Add `--sign` flag to the generate command
- Attach the signature as a separate `.sig` file or embed it in the SBOM metadata
- Add `bomber verify <sbom-file>` command to validate signatures

**Testing the security:**
- Modify a signed SBOM and verify that `bomber verify` detects the tampering
- Verify that signing works with both SPDX and CycloneDX output

### Challenge: Add VEX (Vulnerability Exploitability eXchange) Support

**What to implement:** VEX document generation that states whether vulnerabilities in an SBOM are actually exploitable in your specific context.

**Real world application:** A vulnerability in a dependency you import but never call its affected function is "not affected." VEX lets you formally state this, reducing noise for downstream consumers of your SBOM.

**Implementation:**
- Add `bomber vex ./project` command
- For each vulnerability found, prompt or accept a status: "not_affected", "affected", "fixed", "under_investigation"
- Output VEX in CycloneDX VEX or OpenVEX format
- Store VEX statements in a local file (`.bomber/vex.json`) so they persist across scans

## Real World Integration Challenges

### Integrate with GitHub Dependency Graph

**The goal:** Upload Bomber's dependency data to GitHub's Dependency Graph API so it appears in the repository's "Insights > Dependency graph" tab.

**What you'll need:**
- GitHub API token with `repo` scope
- Understanding of GitHub's Dependency Submission API
- PURL-to-GitHub ecosystem mapping

**Implementation plan:**
1. Generate a Dependency Snapshot from Bomber's scan results
2. POST to `https://api.github.com/repos/{owner}/{repo}/dependency-graph/snapshots`
3. Handle the response and report success/failure

**Watch out for:**
- GitHub's snapshot format has specific requirements for manifest file paths
- Rate limits on the Dependency Submission API

### Integrate with Dependency-Track

**The goal:** Upload Bomber-generated SBOMs to an OWASP Dependency-Track instance for continuous monitoring.

**What you'll need:**
- A running Dependency-Track instance (Docker: `docker run -p 8080:8080 dependencytrack/apiserver`)
- API key from Dependency-Track settings

**Implementation plan:**
1. Add `bomber upload --server <url> --project <name>` command
2. Generate CycloneDX SBOM (Dependency-Track's preferred format)
3. POST to Dependency-Track's BOM upload API
4. Report the project URL for the uploaded SBOM

## Challenge Completion

Track your progress:

- [ ] Easy: Blocked packages policy rule
- [ ] Easy: Markdown report output
- [ ] Easy: Direct-only flag
- [ ] Intermediate: Rust ecosystem support
- [ ] Intermediate: SARIF output
- [ ] Intermediate: License detection
- [ ] Advanced: Reachability analysis
- [ ] Advanced: Dependency diff tool
- [ ] Advanced: GitHub Actions integration
- [ ] Expert: Vulnerability database mirror
- [ ] Performance: 10,000-dependency monorepos
- [ ] Performance: Binary size reduction
- [ ] Security: SBOM signing
- [ ] Security: VEX support
- [ ] Integration: GitHub Dependency Graph
- [ ] Integration: Dependency-Track

Completed all of them? You've built a production-grade supply chain security tool. Consider contributing your extensions back to the project or building a standalone tool based on what you've learned.
