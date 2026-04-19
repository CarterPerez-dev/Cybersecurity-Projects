# System Architecture

This document breaks down how Bomber is designed, how data flows through the system, and why specific architectural decisions were made.

## High Level Architecture

```
                         bomber <command> [path]
                                │
                ┌───────────────▼───────────────┐
                │         CLI Layer             │
                │  internal/cli/                │
                │  root.go → scan/generate/     │
                │           vuln/check          │
                └───────────────┬───────────────┘
                                │
         ┌──────────────────────▼──────────────────────┐
         │              Scanner Engine                  │
         │  internal/scanner/scanner.go                 │
         │  Walks directories, skips vendor/node_modules│
         │  Dispatches to parser registry               │
         └──────────────────────┬───────────────────────┘
                                │
              ┌─────────────────▼─────────────────┐
              │          Parser Registry          │
              │  internal/parser/registry.go      │
              │  Detect() → which parsers match   │
              │  Parse() → build dependency graph │
              └──────────┬───────────┬────────────┘
                         │           │
         ┌───────────────┤           ├───────────────┐
         ▼               ▼           ▼               │
   ┌──────────┐   ┌──────────┐   ┌──────────┐       │
   │ GoMod    │   │ Node     │   │ Python   │       │
   │ Parser   │   │ Parser   │   │ Parser   │       │
   │ go.mod   │   │ pkg.json │   │ pyproject│       │
   │ go.sum   │   │ pnpm-lock│   │ uv.lock  │       │
   └────┬─────┘   └────┬─────┘   └────┬─────┘       │
        │               │              │              │
        └───────────────┼──────────────┘              │
                        ▼                             │
         ┌──────────────────────────┐                 │
         │   Dependency Graphs      │                 │
         │   pkg/types/types.go     │                 │
         │   Nodes + Edges + Root   │                 │
         │   Depth levels, cycles   │                 │
         └──────────┬───────────────┘                 │
                    │                                 │
        ┌───────────┼────────────┐                    │
        ▼           ▼            ▼                    │
  ┌──────────┐ ┌──────────┐ ┌───────────┐            │
  │ SPDX 2.3 │ │CycloneDX │ │ Vuln      │            │
  │ Generator│ │1.5 Gen.  │ │ Matcher   │            │
  │ spdx.go  │ │cyclonedx │ │ osv.go    │            │
  │          │ │ .go      │ │ nvd.go    │            │
  └──────────┘ └──────────┘ │ cvss.go   │            │
                            │ cache.go  │            │
                            └─────┬─────┘            │
                                  │                  │
                                  ▼                  │
                         ┌────────────────┐          │
                         │ Policy Engine  │          │
                         │ engine.go      │          │
                         │ max_severity   │          │
                         │ max_depth      │          │
                         │ max_age_days   │          │
                         └────────┬───────┘          │
                                  │                  │
                                  ▼                  │
                         ┌────────────────┐          │
                         │ Report Layer   │          │
                         │ terminal.go    │──────────┘
                         │ json.go        │
                         └────────────────┘
```

### Component Breakdown

**CLI Layer** (`internal/cli/`)
- Purpose: Parse command-line arguments, wire up components, control output format
- Responsibilities: Signal handling (SIGINT/SIGTERM via `signal.NotifyContext`), global flag management, dispatching to the correct subcommand
- Interfaces: Consumes all internal packages, produces terminal/JSON output

**Scanner Engine** (`internal/scanner/`)
- Purpose: Walk directories and discover ecosystems
- Responsibilities: Recursive directory traversal, skipping known noise directories (`node_modules`, `.git`, `vendor`, `__pycache__`, `.venv`, etc.), dispatching detected directories to the parser registry
- Interfaces: Takes a `*parser.Registry`, returns a `*types.ScanResult`

**Parser Registry** (`internal/parser/`)
- Purpose: Manage ecosystem parsers and auto-detect which ones apply
- Responsibilities: Store registered parsers, detect applicable parsers per directory, delegate parsing to the correct implementation
- Interfaces: `DependencyParser` interface with `Detect(dir) bool`, `Parse(dir) (*DependencyGraph, error)`, and `Ecosystem() Ecosystem`

**SBOM Generators** (`internal/sbom/`)
- Purpose: Convert dependency graphs into spec-compliant SBOM documents
- Responsibilities: SPDX 2.3 and CycloneDX 1.5 JSON serialization, namespace generation, relationship mapping
- Interfaces: Each generator has a `Generate([]*DependencyGraph) ([]byte, error)` method

**Vulnerability Matcher** (`internal/vuln/`)
- Purpose: Query external databases and match packages to known vulnerabilities
- Responsibilities: OSV batch queries, NVD per-package queries, CVSS v3.1 score calculation, SQLite caching, rate limiting
- Interfaces: `Client` interface with `Query(ctx, packages) ([]VulnMatch, error)` and `Source() string`

**Policy Engine** (`internal/policy/`)
- Purpose: Evaluate vulnerability findings against configurable rules
- Responsibilities: YAML policy loading, severity threshold checks, dependency depth limits, vulnerability age enforcement
- Interfaces: `Evaluate(policy, report, graphs) *CheckResult`

**Report Layer** (`internal/report/`)
- Purpose: Format output for humans or machines
- Responsibilities: Colored terminal output with severity grouping, JSON report serialization
- Interfaces: Each formatter writes to an `io.Writer`

## Data Flow

### Scan Command Flow

Step by step walkthrough of `bomber scan ./project`:

```
1. CLI parses args          → internal/cli/scan.go (runScan)
   path = "./project", format from --format flag

2. Create parser registry   → internal/parser/registry.go (RegisterAll)
   Registers GoModParser, NodeParser, PythonParser

3. Scanner walks directory  → internal/scanner/scanner.go (Scan)
   discoverDirs("./project") recursively walks subdirectories
   Skips: node_modules, .git, vendor, __pycache__, .venv, dist, build, .tox, target

4. For each directory:
   registry.Detect(dir)     → Each parser checks for its manifest file
   GoMod: os.Stat("go.mod")
   Node: os.Stat("package.json")
   Python: os.Stat("pyproject.toml")

5. Matched parser.Parse()  → Ecosystem-specific parsing
   Returns *DependencyGraph with nodes (packages) and edges (dependencies)

6. Aggregate results       → types.ScanResult
   TotalPkgs, DirectPkgs, Ecosystems

7. Output                  → report/terminal.go or report/json.go
```

### Vulnerability Scan Flow

Step by step walkthrough of `bomber vuln ./project`:

```
1. Scan phase (same as above, steps 1-6)

2. Collect all packages    → internal/cli/vuln.go (queryVulns)
   Flatten all graphs into []types.Package via graph.AllPackages()

3. Initialize cache        → internal/vuln/cache.go
   SQLite at ~/.bomber/cache.db with 24h TTL
   (skipped if --no-cache)

4. For each vulnerability client (OSV, optionally NVD):

   a. Check cache first    → cache.Get(purl, source)
      Cache hit: add to matches, skip API call
      Cache miss: add to uncached list

   b. Query API            → client.Query(ctx, uncachedPackages)
      OSV: POST /v1/querybatch with PURLs, batch size 1000
      NVD: GET per package with CPE, rate-limited

   c. Cache responses      → cache.Put(purl, source, matches)
      Keyed by (purl, source) composite primary key

5. Deduplicate matches     → deduplicateMatches()
   Cross-reference IDs and aliases (CVE, GHSA, GO-)
   Keep entry with higher CVSS score or fix version

6. Output                  → Scan summary + vuln report
   Grouped by severity: CRITICAL → HIGH → MEDIUM → LOW
   Sorted by CVSS score within each group
```

### SBOM Generation Flow

Step by step walkthrough of `bomber generate ./project --sbom-format spdx`:

```
1. Scan phase (same steps 1-6)

2. Select generator        → internal/cli/generate.go
   "spdx" → NewSPDXGenerator()
   "cyclonedx" → NewCycloneDXGenerator()

3. Generate document       → generator.Generate(graphs)

   SPDX:
   - Build document namespace with SHA-256 hash
   - Create DESCRIBES relationship (document → root)
   - For each node: create spdxPackage with PURL external ref
   - For each edge: create DEPENDS_ON relationship
   - Serialize to indented JSON

   CycloneDX:
   - Generate UUID for serial number
   - For each non-root node: create cdxComponent with PURL + bom-ref
   - For each edge set: create cdxDependency with dependsOn list
   - Serialize to indented JSON

4. Output                  → stdout or --output file
```

### Policy Check Flow

Step by step walkthrough of `bomber check ./project --policy policy.yaml`:

```
1. Load policy             → internal/policy/rules.go (LoadPolicy)
   Parse YAML: max_severity, max_depth, max_age_days

2. Scan phase + Vuln phase (same as vuln flow)

3. Evaluate policy         → internal/policy/engine.go (Evaluate)

   max_severity check:
   - Parse threshold (e.g., "medium" → SeverityMedium, rank 2)
   - For each vuln match: if severity.Rank() > threshold.Rank() → violation

   max_age_days check:
   - Compute cutoff date: now - maxAgeDays
   - For each vuln match: if published before cutoff → violation
   - Skip vulns with zero published date

   max_depth check:
   - For each graph: compute MaxDepth()
   - If depth > maxDepth → violation

4. Output + Exit code      → report + os.Exit(1) if any violations
```

## Design Patterns

### Registry Pattern

**What it is:** A central registry that stores implementations of an interface and dispatches work based on runtime detection.

**Where we use it:** `internal/parser/registry.go` stores `DependencyParser` implementations. The scanner calls `registry.Detect(dir)` to find which parsers match a directory, then calls `Parse()` on each match.

**Why we chose it:** New ecosystems (Rust, Java, Ruby) can be added by implementing the `DependencyParser` interface and registering in `RegisterAll()`. Zero changes to the scanner, CLI, or any other package.

```go
type DependencyParser interface {
    Detect(dir string) bool
    Parse(dir string) (*types.DependencyGraph, error)
    Ecosystem() types.Ecosystem
}
```

**Trade-offs:**
- Pros: Open/closed principle. Adding Rust support means one new file, one line in `RegisterAll()`
- Cons: All parsers must fit the same interface shape. If a parser needs fundamentally different inputs (like a network fetch), the interface doesn't accommodate that

### Functional Options Pattern

**What it is:** Configuration via variadic function arguments that modify a struct's defaults.

**Where we use it:** Both vulnerability clients use this pattern:

```go
client := vuln.NewOSVClient(WithOSVBaseURL(server.URL))
client := vuln.NewNVDClient(WithNVDBaseURL(url), WithNVDAPIKey(key))
```

**Why we chose it:** Tests need to point clients at `httptest.Server` URLs. Production code uses defaults from `internal/config/config.go`. The option functions make both cases clean without exposing internal fields or requiring a config struct.

**Trade-offs:**
- Pros: Clean defaults, testable, backward-compatible when adding options
- Cons: Slightly more boilerplate than a config struct

### Strategy Pattern

**What it is:** Interchangeable implementations behind a common interface, selected at runtime.

**Where we use it:** The `vuln.Client` interface lets `vuln.go` treat OSV and NVD identically:

```go
var clients []vuln.Client
clients = append(clients, osvClient)
if nvdKey != "" {
    clients = append(clients, vuln.NewNVDClient(vuln.WithNVDAPIKey(nvdKey)))
}
for _, client := range clients {
    matches, err := client.Query(ctx, uncached)
    ...
}
```

**Why we chose it:** OSV and NVD have completely different APIs (batch POST vs per-package GET), different authentication models (none vs API key), and different rate limits. The `Client` interface abstracts all of this away.

## Layer Separation

```
┌─────────────────────────────────────────┐
│    CLI Layer (internal/cli/)            │
│    - Parses arguments and flags         │
│    - Wires components together          │
│    - Controls output format             │
│    - Does NOT contain business logic    │
└─────────────────────┬───────────────────┘
                      ↓
┌─────────────────────────────────────────┐
│    Core Layer (internal/*)              │
│    - scanner, parser, graph, sbom,      │
│      vuln, policy                       │
│    - All business logic lives here      │
│    - Each package has a single concern  │
│    - Does NOT import cli or report      │
└─────────────────────┬───────────────────┘
                      ↓
┌─────────────────────────────────────────┐
│    Types Layer (pkg/types/)             │
│    - Shared data structures             │
│    - No business logic, no imports      │
│    - Package, Vulnerability, ScanResult │
└─────────────────────────────────────────┘
```

### What Lives Where

**CLI Layer:**
- Files: `internal/cli/*.go`
- Imports: Everything in `internal/` and `pkg/types`
- Forbidden: Business logic. The CLI should only orchestrate calls to core packages.

**Core Layer:**
- Files: `internal/scanner/`, `internal/parser/`, `internal/graph/`, `internal/sbom/`, `internal/vuln/`, `internal/policy/`
- Imports: `pkg/types` and `internal/config`. Some core packages import other core packages (e.g., `scanner` imports `parser` and `graph`)
- Forbidden: Importing `internal/cli/` or `internal/report/`. Core logic should never know how it's being invoked.

**Types Layer:**
- Files: `pkg/types/types.go`
- Imports: Only standard library (`time`, `strings`)
- Forbidden: Importing anything from `internal/`. Types are the foundation everything else builds on.

## Data Models

### Package

```go
type Package struct {
    Name       string
    Version    string
    Ecosystem  Ecosystem
    PURL       string
    Checksums  []Checksum
    Direct     bool
    DepthLevel int
}
```

**Fields explained:**
- `Name`: The package identifier within its ecosystem (e.g., `github.com/spf13/cobra`, `express`, `requests`)
- `Version`: The resolved version from the lockfile (e.g., `v1.10.2`, `4.18.2`, `2.31.0`)
- `Ecosystem`: Enum: `EcosystemGo`, `EcosystemNode`, `EcosystemPython`
- `PURL`: The Package URL used as the universal identifier and map key
- `Checksums`: Hash values from lockfiles (go.sum SHA-256, pnpm-lock integrity SHA-512)
- `Direct`: Whether this package is listed in the manifest (not just the lockfile)
- `DepthLevel`: BFS distance from the root package (0 = root, 1 = direct, 2+ = transitive)

### DependencyGraph

```go
type DependencyGraph struct {
    Root  Package
    Nodes map[string]Package    // keyed by PURL
    Edges map[string][]string   // parent PURL → []child PURLs
}
```

The graph is an adjacency list. `Nodes` stores every package keyed by its PURL. `Edges` maps each parent to its list of children. The `Root` field identifies the project being scanned.

### Vulnerability

```go
type Vulnerability struct {
    ID            string
    Aliases       []string
    Severity      Severity
    Score         float64
    AffectedRange string
    FixVersion    string
    Summary       string
    Source        string
    Published     time.Time
}
```

A single vulnerability can have multiple identifiers. `ID` is the primary (e.g., `GO-2023-2102`), `Aliases` holds cross-references (e.g., `["CVE-2023-44487", "GHSA-qppj-fm5r-hxr3"]`). `Source` tracks where the data came from (`"osv"` or `"nvd"`).

## Security Architecture

### Threat Model

What we're protecting against:
1. **Known vulnerabilities in dependencies** - The primary threat. A package in your dependency tree has a published CVE with a known fix version.
2. **Deep transitive dependency risk** - Packages buried deep in the dependency tree that you never explicitly chose and may not know about.
3. **Stale vulnerability findings** - Known vulnerabilities that go unpatched for extended periods, giving attackers time to develop exploits.

What we're NOT protecting against (out of scope):
- **Zero-day vulnerabilities** - Bomber queries known vulnerability databases. If a vulnerability hasn't been published yet, Bomber won't find it.
- **Malicious packages with no CVE** - A deliberately backdoored package that hasn't been reported to any vulnerability database won't be detected by Bomber.
- **Build pipeline compromise** - Bomber analyzes source manifests, not build outputs. A compromised build system could inject dependencies not present in source.

### External API Security

**OSV API:** No authentication required. Bomber sends only PURLs (package identifiers that are already public information). No sensitive data leaves the system.

**NVD API:** Optional API key sent via `apiKey` header. The key is read from the `BOMBER_NVD_API_KEY` environment variable, never from config files or command-line arguments (which would appear in process listings).

**Cache:** The SQLite cache at `~/.bomber/cache.db` stores vulnerability responses. It contains only publicly available vulnerability data, not source code or credentials.

## Storage Strategy

### SQLite Cache

**What we store:**
- Vulnerability matches keyed by `(purl, source)` composite primary key
- Serialized as JSON blobs
- Timestamp for TTL expiration

**Why SQLite:**
SQLite is embedded (no server process), uses a single file, and `modernc.org/sqlite` is a pure-Go implementation (no CGo dependency). This means Bomber is a single statically-linked binary with no external dependencies.

**Schema:**
```sql
CREATE TABLE IF NOT EXISTS vuln_cache (
    purl TEXT NOT NULL,
    source TEXT NOT NULL,
    data BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (purl, source)
)
```

The `INSERT OR REPLACE` strategy at `internal/vuln/cache.go` means re-scanning the same project updates stale entries without requiring explicit deletion.

## Configuration

### Environment Variables

```bash
BOMBER_NVD_API_KEY    # NVD API key for higher rate limits (200ms vs 1.7s)
BOMBER_INSTALL_DIR    # Override install location (default: ~/.bomber/bin)
BOMBER_VERSION        # Pin install script to a specific version
```

### Configuration Strategy

Bomber uses a flags-only approach for configuration. There's no config file for the tool itself (unlike Portia's `.portia.toml`). This is deliberate: Bomber is designed for CI/CD pipelines where configuration comes from environment variables and command-line flags, not project-local config files.

The only file-based configuration is the policy file (`policy.yaml`), which defines security rules rather than tool behavior.

## Performance Considerations

### Bottlenecks

Where this system gets slow under load:

1. **NVD API queries** - One request per package, rate-limited to 1.7s/request without an API key. A project with 200 dependencies takes ~340 seconds. With an API key: ~40 seconds. This is why OSV (batch queries, no rate limit) is the primary source.

2. **`go mod graph` execution** - The Go parser shells out to `go mod graph` to build accurate edge relationships. This is an `exec.Command` call at `internal/parser/gomod.go` that can take seconds for large Go projects because it resolves the module graph.

### Optimizations

What we did to make it faster:

- **OSV batch API**: Instead of querying one package at a time, Bomber sends up to 1000 PURLs in a single POST request. This turns N HTTP round-trips into ceil(N/1000).

- **SQLite response caching**: Repeated scans of the same project skip API calls entirely for packages already cached within the TTL window. The cache uses a composite key `(purl, source)` so OSV and NVD results are cached independently.

- **Directory skip list**: The scanner skips 9 known noise directories (`node_modules`, `.git`, `vendor`, etc.) to avoid traversing millions of files in large monorepos.

### Scalability

**Vertical scaling:**
Bomber is single-threaded for API queries (both OSV and NVD). The OSV batch API makes this acceptable. NVD's rate limit is the binding constraint, not CPU or memory.

**Horizontal scaling:**
For scanning hundreds of repositories, run Bomber as a parallel CI step per repository. Each instance maintains its own cache. There's no shared state between runs.

## Design Decisions

### Decision 1: OSV as Primary, NVD as Supplementary

**What we chose:** OSV is always queried. NVD is only queried if `BOMBER_NVD_API_KEY` is set.

**Alternatives considered:**
- NVD only - Rejected because NVD doesn't support PURL (requires CPE translation, which is lossy) and has strict rate limits
- Both always - Rejected because NVD without an API key is too slow for interactive use
- OSV only - Viable but loses the enrichment NVD provides (more detailed CVSS data, broader coverage for some ecosystems)

**Trade-offs:** Users who want comprehensive coverage need an NVD API key. Users who want fast, good-enough results get OSV by default with no setup.

### Decision 2: Pure-Go SQLite (modernc.org/sqlite)

**What we chose:** A pure-Go SQLite implementation with no CGo dependency.

**Alternatives considered:**
- `mattn/go-sqlite3` - Requires CGo and a C compiler. Cross-compilation becomes painful. Rejected for distribution simplicity.
- BoltDB/BadgerDB - Key-value stores without SQL. Rejected because the `(purl, source)` composite key with TTL expiration maps naturally to SQL.
- No cache - Rejected because vulnerability API calls are expensive (network latency + rate limits).

**Trade-offs:** `modernc.org/sqlite` is slower than the CGo version for heavy workloads, but Bomber's cache queries are trivial (point lookups and upserts). The distribution benefit (single static binary) far outweighs the performance difference.

### Decision 3: Dependency Graph as Adjacency List

**What we chose:** `map[string]Package` for nodes and `map[string][]string` for edges, both keyed by PURL.

**Alternatives considered:**
- Adjacency matrix - O(1) edge lookups but O(n^2) memory. Rejected for a system that commonly handles 50-500 packages.
- Third-party graph library - Adds dependency for a relatively simple data structure. Rejected in favor of stdlib-only implementation.

**Trade-offs:** Adjacency lists are space-efficient and fast for BFS/DFS traversal (which is all Bomber needs). Edge existence checks are O(degree) instead of O(1), but no operation in Bomber requires frequent edge-existence queries.

## Error Handling Strategy

### Error Types

1. **Parse errors** - A manifest file exists but can't be parsed (malformed TOML, invalid JSON). Handled by returning `nil, error` from `Parse()`. The scanner logs and continues to the next parser.

2. **Network errors** - OSV or NVD API is unreachable. The vuln command continues with whatever results it has. Individual client errors don't abort the entire scan.

3. **Cache errors** - SQLite can't be opened or queried. The scan proceeds without caching. Cache errors are silently ignored because they don't affect correctness.

4. **Policy violations** - Not errors in the traditional sense. The policy engine returns a `CheckResult` with `Passed: false`, and the CLI exits with code 1.

### Recovery Strategy

The general approach is **best-effort degradation**:
- If `go mod graph` fails, the Go parser still returns packages from `go.mod` parsing. It just won't have accurate edge data.
- If NVD returns an error for one package, Bomber logs it and continues with the rest. It doesn't abort.
- If the cache can't be initialized, the scan proceeds without caching.

## Extensibility

### Adding a New Ecosystem Parser

Want to add Rust support? Here's where it goes:

1. Create `internal/parser/cargo.go` implementing `DependencyParser`:
   - `Detect()`: check for `Cargo.toml`
   - `Parse()`: read `Cargo.toml` and `Cargo.lock`, build graph with `pkg:cargo/` PURLs
   - `Ecosystem()`: return a new `EcosystemRust` constant

2. Add `EcosystemRust` to the `Ecosystem` enum in `pkg/types/types.go`

3. Register in `internal/parser/registry.go`:
   ```go
   func RegisterAll(reg *Registry) {
       reg.Register(NewGoModParser())
       reg.Register(NewNodeParser())
       reg.Register(NewPythonParser())
       reg.Register(NewCargoParser())  // add this
   }
   ```

No changes needed to the scanner, SBOM generators, vulnerability matchers, policy engine, or CLI. The registry pattern handles dispatch.

### Adding a New Vulnerability Source

Want to add GitHub Advisory Database support?

1. Create `internal/vuln/ghsa.go` implementing the `Client` interface:
   - `Query()`: call the GitHub GraphQL API
   - `Source()`: return `"ghsa"`

2. Add it to the client list in `internal/cli/vuln.go`:
   ```go
   ghToken := os.Getenv("BOMBER_GITHUB_TOKEN")
   if ghToken != "" {
       clients = append(clients, vuln.NewGHSAClient(vuln.WithGHToken(ghToken)))
   }
   ```

The deduplication logic already handles aliases, so overlapping results between OSV and GHSA are merged automatically.

## Comparison to Similar Systems

### Syft (Anchore)

Syft is a mature SBOM generator that supports 20+ ecosystems and generates SPDX, CycloneDX, and its own JSON format. It scans container images, file systems, and archives.

How Bomber is different:
- Bomber combines SBOM generation with vulnerability matching and policy enforcement in one binary. Syft focuses on SBOM generation and delegates vulnerability scanning to Grype.
- Bomber is a focused learning project targeting three ecosystems deeply. Syft is a production tool covering breadth.

### Grype (Anchore)

Grype is a vulnerability scanner that consumes SBOMs or scans images directly. It pairs with Syft.

How Bomber is different:
- Bomber generates SBOMs and scans vulnerabilities in a single pipeline. Grype expects pre-generated SBOMs or raw file system access.
- Bomber's policy engine is built-in. Grype relies on external tooling for policy enforcement.

### Trivy (Aqua Security)

Trivy is a comprehensive security scanner that covers vulnerabilities, misconfigurations, secrets, and licenses.

How Bomber is different:
- Bomber is a single-purpose tool: dependencies and vulnerabilities. Trivy is a multi-scanner covering container images, Kubernetes manifests, IaC files, and more.
- Bomber is a ~2000 line Go project suitable for reading end-to-end. Trivy is a large production codebase.

## Key Files Reference

Quick map of where to find things:

- `cmd/bomber/main.go` - Entry point (3 lines)
- `pkg/types/types.go` - All shared data structures
- `internal/config/config.go` - Constants and API URLs
- `internal/cli/root.go` - CLI setup, signal handling, flag definitions
- `internal/scanner/scanner.go` - Directory walker and ecosystem dispatcher
- `internal/parser/parser.go` - DependencyParser interface (4 lines)
- `internal/parser/registry.go` - Parser registry and auto-detection
- `internal/parser/gomod.go` - Go parser (go.mod, go.sum, go mod graph, BFS depth)
- `internal/parser/node.go` - Node parser (package.json, pnpm-lock.yaml)
- `internal/parser/python.go` - Python parser (pyproject.toml, uv.lock)
- `internal/graph/graph.go` - Graph utilities (all/direct/transitive, cycles, merge)
- `internal/sbom/spdx.go` - SPDX 2.3 JSON generator
- `internal/sbom/cyclonedx.go` - CycloneDX 1.5 JSON generator
- `internal/vuln/client.go` - Vulnerability client interface (4 lines)
- `internal/vuln/osv.go` - OSV batch API client
- `internal/vuln/nvd.go` - NVD REST API client with rate limiting
- `internal/vuln/cvss.go` - CVSS v3.1 base score calculator
- `internal/vuln/cache.go` - SQLite cache with TTL
- `internal/policy/rules.go` - Policy YAML loader
- `internal/policy/engine.go` - Policy evaluation engine
- `internal/report/terminal.go` - Colored terminal output
- `internal/report/json.go` - JSON report format

## Next Steps

Now that you understand the architecture:
1. Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for code walkthrough
2. Try modifying the Go parser to skip indirect dependencies and observe how the scan summary changes
3. Try adding a new policy rule (e.g., `blocked_packages: ["lodash"]`) and follow the patterns in `engine.go`
