# Implementation Guide

This document walks through the actual code. We'll follow the data from CLI invocation through parsing, graph construction, SBOM generation, vulnerability matching, and policy evaluation.

## File Structure Walkthrough

```
sbom-generator-vulnerability-matcher/
├── cmd/bomber/
│   └── main.go                    # Entry point (3 lines)
├── internal/
│   ├── cli/
│   │   ├── root.go                # Root command, flags, signal handling
│   │   ├── scan.go                # Dependency scan command
│   │   ├── generate.go            # SBOM generation command
│   │   ├── vuln.go                # Vulnerability scan + deduplication
│   │   └── check.go               # Policy evaluation command
│   ├── config/
│   │   └── config.go              # Constants: URLs, timeouts, format versions
│   ├── graph/
│   │   └── graph.go               # Graph traversal and cycle detection
│   ├── parser/
│   │   ├── parser.go              # DependencyParser interface
│   │   ├── registry.go            # Parser registration and detection
│   │   ├── gomod.go               # Go: go.mod, go.sum, go mod graph
│   │   ├── node.go                # Node: package.json, pnpm-lock.yaml
│   │   └── python.go              # Python: pyproject.toml, uv.lock
│   ├── policy/
│   │   ├── rules.go               # Policy YAML structure and loading
│   │   └── engine.go              # Policy evaluation rules
│   ├── report/
│   │   ├── terminal.go            # Colored terminal report
│   │   └── json.go                # JSON report format
│   ├── sbom/
│   │   ├── spdx.go                # SPDX 2.3 JSON generator
│   │   └── cyclonedx.go           # CycloneDX 1.5 JSON generator
│   ├── ui/
│   │   ├── banner.go              # ASCII art banner
│   │   ├── color.go               # Color function wrappers
│   │   ├── spinner.go             # Terminal spinner for long operations
│   │   └── symbol.go              # Unicode symbols (check, cross, etc.)
│   └── vuln/
│       ├── client.go              # Client interface
│       ├── osv.go                 # OSV batch API client
│       ├── nvd.go                 # NVD REST API client
│       ├── cvss.go                # CVSS v3.1 calculator
│       └── cache.go               # SQLite response cache
├── pkg/types/
│   └── types.go                   # Core data structures
└── testdata/                      # Fixtures for all ecosystems
```

## Building the Type System

### Core Types (`pkg/types/types.go`)

Every data structure in Bomber flows through `pkg/types`. This is the foundation.

The `Ecosystem` type is an iota enum with a `String()` method for human-readable output. The `Severity` type follows the same pattern but adds `Rank()` for numeric comparison and `ParseSeverity()` for converting strings from API responses:

```go
type Severity int

const (
    SeverityNone Severity = iota
    SeverityLow
    SeverityMedium
    SeverityHigh
    SeverityCritical
)
```

The iota ordering is deliberate: `SeverityNone < SeverityLow < ... < SeverityCritical`. This means `Rank()` (which returns the int value) can be used for direct comparison in the policy engine. When the policy says `max_severity: medium` and a vulnerability is `HIGH`, the engine compares `SeverityHigh.Rank() > SeverityMedium.Rank()` which is `3 > 2` which is `true`, so it generates a violation.

The `Package` struct carries everything Bomber knows about a dependency:

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

`PURL` serves double duty: it's the universal identifier for external API queries and the map key for graph nodes. `Direct` distinguishes packages you explicitly declared from ones pulled in transitively. `DepthLevel` is computed via BFS after graph construction.

The `DependencyGraph` is an adjacency list with a designated root:

```go
type DependencyGraph struct {
    Root  Package
    Nodes map[string]Package
    Edges map[string][]string
}
```

Both maps are keyed by PURL strings. `NewDependencyGraph` initializes the maps and inserts the root node, ensuring the graph is never in an invalid state.

## Building the Parser System

### The Interface (`internal/parser/parser.go`)

The entire parser interface is four lines:

```go
type DependencyParser interface {
    Detect(dir string) bool
    Parse(dir string) (*types.DependencyGraph, error)
    Ecosystem() types.Ecosystem
}
```

`Detect` checks if a directory contains this parser's manifest files. `Parse` reads those files and returns a fully constructed dependency graph. `Ecosystem` returns which ecosystem this parser handles.

### The Registry (`internal/parser/registry.go`)

The registry stores parsers and provides detection:

```go
func (r *Registry) Detect(dir string) []DependencyParser {
    var matched []DependencyParser
    for _, p := range r.parsers {
        if p.Detect(dir) {
            matched = append(matched, p)
        }
    }
    return matched
}
```

A monorepo directory might match multiple parsers. If a directory has both `go.mod` and `package.json`, both the Go and Node parsers are returned. Each produces its own `DependencyGraph`.

`RegisterAll` wires up all three parsers. This is the single place where adding a new ecosystem requires a change.

### Go Parser (`internal/parser/gomod.go`)

The Go parser is the most complex because Go has three sources of dependency information: `go.mod` (manifest), `go.sum` (checksums), and `go mod graph` (edge relationships).

**Phase 1: Parse go.mod**

The parser reads `go.mod` line by line with `bufio.Scanner`. It tracks whether it's inside a `require (...)` block and classifies each dependency as direct or indirect based on the `// indirect` comment:

```go
if strings.Contains(line, "// indirect") {
    indirectDeps[name] = version
} else {
    directDeps[name] = version
}
```

This is the same heuristic that `go mod` itself uses. Go doesn't have a separate manifest vs lockfile distinction: `go.mod` contains both direct and indirect dependencies, annotated with comments.

**Phase 2: Parse go.sum for checksums**

`parseGoSum` reads `go.sum` and extracts SHA-256 hashes. Each line in `go.sum` looks like:

```
github.com/spf13/cobra v1.10.2 h1:abc123base64...
```

The `h1:` prefix indicates a hash format. The parser base64-decodes the hash and converts it to hex:

```go
raw := strings.TrimPrefix(hash, "h1:")
decoded, err := base64.StdEncoding.DecodeString(raw)
checksums[key] = append(checksums[key], types.Checksum{
    Algorithm: "SHA-256",
    Value:     hex.EncodeToString(decoded),
})
```

**Phase 3: Build edges with `go mod graph`**

`go.mod` only tells you which packages exist. For accurate parent-child relationships, the parser shells out to `go mod graph`:

```go
cmd := exec.Command("go", "mod", "graph")
cmd.Dir = dir
out, err := cmd.Output()
```

Each line of output is `parent@version child@version`. The parser converts these to PURLs and adds edges. If `go mod graph` fails (e.g., no Go toolchain available), the parser still returns the packages from phase 1, just without edge data. This is the best-effort degradation strategy.

**Phase 4: Compute depth levels via BFS**

After the graph is built, `computeDepthLevels` runs BFS from the root node:

```go
func computeDepthLevels(graph *types.DependencyGraph) {
    depths := make(map[string]int)
    depths[graph.Root.PURL] = 0
    queue := []string{graph.Root.PURL}

    for len(queue) > 0 {
        current := queue[0]
        queue = queue[1:]
        currentDepth := depths[current]

        for _, child := range graph.Edges[current] {
            if _, visited := depths[child]; !visited {
                depths[child] = currentDepth + 1
                queue = append(queue, child)
            }
        }
    }
    ...
}
```

BFS guarantees that each node gets the shortest path depth from root. A package reachable via both a depth-2 and depth-4 path gets depth 2.

### Node Parser (`internal/parser/node.go`)

The Node parser reads `package.json` for project metadata and direct dependency declarations, then `pnpm-lock.yaml` for resolved versions and transitive dependencies.

**package.json parsing** uses `encoding/json` to unmarshal into a struct:

```go
type packageJSON struct {
    Name            string            `json:"name"`
    Version         string            `json:"version"`
    Dependencies    map[string]string `json:"dependencies"`
    DevDependencies map[string]string `json:"devDependencies"`
}
```

Both `dependencies` and `devDependencies` are treated as direct dependencies. This is intentional: dev dependencies can also have vulnerabilities, and in a development environment, they're on the attack surface.

**pnpm-lock.yaml parsing** is more involved. The lock file has two key sections: `packages` (resolved package metadata) and `snapshots` (dependency relationships).

The `splitPnpmKey` function handles pnpm's key format, which uses `@` as both a scoped package prefix and a version separator:

```go
func splitPnpmKey(key string) (string, string) {
    atIdx := strings.LastIndex(key, "@")
    if atIdx <= 0 {
        return "", ""
    }
    return key[:atIdx], key[atIdx+1:]
}
```

Using `LastIndex` handles scoped packages correctly: `@angular/core@17.0.0` splits at the last `@` into name `@angular/core` and version `17.0.0`.

**PURL encoding for scoped packages:**

npm scoped packages start with `@`, but PURL's `@` denotes a version separator. The `encodePURLName` function percent-encodes the leading `@`:

```go
func encodePURLName(name string) string {
    if strings.HasPrefix(name, "@") {
        return strings.Replace(name, "@", "%40", 1)
    }
    return name
}
```

**Fallback:** If `pnpm-lock.yaml` doesn't exist, the parser falls back to `parseFromPackageJSON`, which uses `package.json` dependencies directly. Version constraints (like `^4.18.2`) are cleaned using a regex that extracts the semver portion:

```go
var nodeSemverRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

func cleanNodeVersion(constraint string) string {
    match := nodeSemverRe.FindString(constraint)
    if match != "" {
        return match
    }
    return strings.TrimLeft(constraint, "^~>=< ")
}
```

### Python Parser (`internal/parser/python.go`)

The Python parser reads `pyproject.toml` for project metadata and `uv.lock` for resolved versions.

**pyproject.toml parsing** uses `go-toml/v2`:

```go
type pyprojectTOML struct {
    Project struct {
        Name         string   `toml:"name"`
        Version      string   `toml:"version"`
        Dependencies []string `toml:"dependencies"`
    } `toml:"project"`
    DependencyGroups map[string][]string `toml:"dependency-groups"`
}
```

Python dependency specifiers include version constraints inline: `requests>=2.31.0`. The `extractPyPkgName` function strips everything after the first version operator:

```go
var pyVersionRe = regexp.MustCompile(`[><=!~;]`)

func extractPyPkgName(spec string) string {
    loc := pyVersionRe.FindStringIndex(spec)
    if loc != nil {
        return strings.TrimSpace(spec[:loc[0]])
    }
    return strings.TrimSpace(spec)
}
```

**uv.lock parsing** handles virtual packages (the project root itself, which has `source.virtual` set) by skipping them:

```go
if pkg.Source.Virtual != "" {
    continue
}
```

The parser builds a `purlMap` (name -> PURL) during the first pass, then uses it to resolve edges in a second pass based on each package's `dependencies` list.

**Name normalization:** PyPI treats package names case-insensitively and normalizes hyphens/underscores. The parser lowercases all names before PURL construction and before matching against the direct dependency set.

## Building the Graph Package

### Graph Utilities (`internal/graph/graph.go`)

The graph package provides pure functions that operate on `*types.DependencyGraph`. It doesn't own any state.

**AllPackages, DirectPackages, TransitivePackages** are simple filters over `g.Nodes`. `DirectPackages` excludes the root node itself (you don't want "my-project" counted as a dependency of itself).

**DetectCycles** uses DFS with a "current stack" tracking pattern:

```go
func DetectCycles(g *types.DependencyGraph) [][]string {
    var cycles [][]string
    visited := make(map[string]bool)
    inStack := make(map[string]bool)

    var dfs func(purl string, path []string)
    dfs = func(purl string, path []string) {
        if inStack[purl] {
            for i, p := range path {
                if p == purl {
                    cycle := make([]string, len(path)-i)
                    copy(cycle, path[i:])
                    cycles = append(cycles, cycle)
                    return
                }
            }
            return
        }
        if visited[purl] {
            return
        }

        visited[purl] = true
        inStack[purl] = true
        path = append(path, purl)

        for _, child := range g.Edges[purl] {
            dfs(child, path)
        }

        inStack[purl] = false
    }
    ...
}
```

The `visited` set prevents re-exploring completed subtrees. The `inStack` set tracks the current DFS path. If we encounter a node that's already in the current stack, we've found a cycle. The `path` slice records the actual nodes in the cycle for reporting.

**MergeGraphs** combines multiple graphs under a synthetic root. This is used when scanning a monorepo where each ecosystem gets its own graph. The merged graph has a root at `pkg:merged/root` with edges to each original root.

## Building the Scanner

### Scanner Engine (`internal/scanner/scanner.go`)

The scanner ties parsers to directory discovery:

```go
func (s *Scanner) Scan(dir string) (*types.ScanResult, error) {
    result := &types.ScanResult{}
    ecosystemSet := make(map[types.Ecosystem]bool)

    dirs := discoverDirs(dir)

    for _, d := range dirs {
        matched := s.registry.Detect(d)
        for _, p := range matched {
            g, err := p.Parse(d)
            if err != nil {
                continue
            }
            result.Graphs = append(result.Graphs, g)
            ecosystemSet[p.Ecosystem()] = true
        }
    }
    ...
}
```

`discoverDirs` recursively walks the directory tree, skipping known noise directories. It returns a flat list of directories to check. The scanner then runs detection and parsing on each one.

Parse errors are silently ignored (`continue`). This is intentional: a monorepo might have directories with partial or broken manifest files. The scanner should process what it can.

The skip list is hard-coded:

```go
var skipDirs = map[string]bool{
    "node_modules": true, ".git": true, "vendor": true,
    "__pycache__": true, ".venv": true, "dist": true,
    "build": true, ".tox": true, "target": true,
}
```

These are well-known directories that either contain resolved dependencies (which would cause double-counting) or build artifacts (which aren't source).

## Building the SBOM Generators

### SPDX 2.3 Generator (`internal/sbom/spdx.go`)

The SPDX generator maps dependency graphs to the SPDX 2.3 JSON format.

**Document namespace generation** creates a globally unique identifier:

```go
nsHash := fmt.Sprintf("%x", sha256.Sum256([]byte(docName+now)))
namespace := fmt.Sprintf("https://spdx.org/spdxdocs/%s-%s", docName, nsHash[:16])
```

The namespace combines the project name and timestamp, hashed with SHA-256 and truncated to 16 hex characters. This ensures uniqueness without relying on random UUIDs (SPDX convention).

**SPDX ID sanitization** is required because SPDX IDs must match `[a-zA-Z0-9.-]+`. PURLs contain characters like `/`, `@`, `:`, and `%` that aren't allowed:

```go
func sanitizeSPDXID(purl string) string {
    r := strings.NewReplacer(
        "/", "-", "@", "-", ":", "-", ".", "-", "%", "-",
    )
    return "SPDXRef-" + r.Replace(purl)
}
```

**Relationships** use two SPDX relationship types:
- `DESCRIBES`: Links the document to the root package
- `DEPENDS_ON`: Links parent packages to child packages

Every edge in every graph becomes a `DEPENDS_ON` relationship. This is the standard way to represent dependency trees in SPDX.

### CycloneDX 1.5 Generator (`internal/sbom/cyclonedx.go`)

CycloneDX uses a different model: components (the packages) and dependencies (the relationships) are separate top-level arrays.

**Key difference from SPDX:** CycloneDX uses `bom-ref` as the linking identifier between components and dependencies. Bomber uses the PURL directly as the `bom-ref`:

```go
comp := cdxComponent{
    Type:    "library",
    Name:    pkg.Name,
    Version: pkg.Version,
    PURL:    pkg.PURL,
    BOMRef:  pkg.PURL,
}
```

The root package is excluded from the components list (`if pkg.PURL == graph.Root.PURL { continue }`). CycloneDX represents the root project in the metadata section, not as a component.

**UUID generation** uses `google/uuid` for the serial number:

```go
SerialNum: fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
```

Each generated SBOM gets a unique identifier, which is useful for tracking document revisions and provenance.

## Building the Vulnerability Matcher

### Client Interface (`internal/vuln/client.go`)

```go
type Client interface {
    Query(ctx context.Context, packages []types.Package) ([]types.VulnMatch, error)
    Source() string
}
```

`Source()` returns a string identifier (`"osv"` or `"nvd"`) used for cache keying and deduplication attribution.

### OSV Client (`internal/vuln/osv.go`)

The OSV client implements batch queries. It chunks packages into groups of 1000 (the API limit) and sends POST requests:

```go
func (c *OSVClient) Query(ctx context.Context, packages []types.Package) ([]types.VulnMatch, error) {
    var allMatches []types.VulnMatch

    for i := 0; i < len(packages); i += config.OSVBatchSize {
        if err := ctx.Err(); err != nil {
            return allMatches, err
        }

        end := i + config.OSVBatchSize
        if end > len(packages) {
            end = len(packages)
        }
        batch := packages[i:end]

        matches, err := c.queryBatch(ctx, batch)
        ...
    }
    return allMatches, nil
}
```

The context check at each iteration enables graceful cancellation: if the user hits Ctrl+C, the signal handler cancels the context, and the next batch iteration returns early.

**Response parsing** correlates results with input packages by index. The OSV batch API returns results in the same order as the query:

```go
for i, result := range batchResp.Results {
    if i >= len(packages) {
        break
    }
    pkg := packages[i]
    for _, v := range result.Vulns {
        ...
    }
}
```

**Severity extraction** follows a priority chain: first check `database_specific.severity` (which some ecosystem databases provide as a simple label), then fall back to parsing the CVSS v3 vector from the `severity` array:

```go
func parseSeverityFromOSV(v osvVuln) types.Severity {
    if v.DBSpec.Severity != "" {
        return types.ParseSeverity(v.DBSpec.Severity)
    }
    for _, s := range v.Severity {
        if s.Type == "CVSS_V3" {
            score := parseCVSSScore(s.Score)
            return scoreToSeverity(score)
        }
    }
    return types.SeverityNone
}
```

### NVD Client (`internal/vuln/nvd.go`)

The NVD client queries one package at a time because the NVD API doesn't support batching.

**CPE construction** converts a PURL-style identifier to CPE format:

```go
func buildCPEString(pkg types.Package) string {
    product := pkg.Name
    if idx := strings.LastIndex(product, "/"); idx >= 0 {
        product = product[idx+1:]
    }
    product = strings.ToLower(product)

    version := strings.TrimPrefix(pkg.Version, "v")
    if version == "" {
        version = "*"
    }

    return fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", product, version)
}
```

For Go modules like `golang.org/x/net`, this extracts `net` as the product name. The vendor is wildcarded because CPE vendor names are inconsistent across NVD records. This is a best-effort approach; some packages won't match their NVD entries.

**Rate limiting** uses a mutex-protected timer:

```go
func (c *NVDClient) rateLimit(ctx context.Context) {
    c.mu.Lock()
    defer c.mu.Unlock()

    elapsed := time.Since(c.lastReq)
    if elapsed < c.rateDelay {
        wait := c.rateDelay - elapsed
        timer := time.NewTimer(wait)
        defer timer.Stop()

        select {
        case <-ctx.Done():
            return
        case <-timer.C:
        }
    }
    c.lastReq = time.Now()
}
```

The `select` with `ctx.Done()` ensures the rate limiter respects cancellation. Without it, Ctrl+C during NVD scanning would block until the timer expires.

The rate delay is configured differently based on authentication: 200ms with an API key, 1700ms without. This matches NVD's documented limits.

### CVSS v3.1 Calculator (`internal/vuln/cvss.go`)

The calculator implements the CVSS v3.1 specification from FIRST.org.

**Vector parsing** extracts the 8 metric values from a CVSS vector string and converts them to numeric weights:

```go
func parseCVSSVector(vector string) *cvssMetrics {
    if !strings.HasPrefix(vector, "CVSS:3") {
        return nil
    }

    parts := strings.Split(vector, "/")
    if len(parts) < 9 {
        return nil
    }

    vals := make(map[string]string, 8)
    for _, part := range parts[1:] {
        kv := strings.SplitN(part, ":", 2)
        if len(kv) == 2 {
            vals[kv[0]] = kv[1]
        }
    }
    ...
}
```

The function returns `nil` for invalid vectors (wrong prefix, missing metrics, unknown values). This means unparseable vectors produce a score of 0.0.

**Privileges Required** weights depend on Scope. If the scope is changed, privilege requirements are less effective at reducing risk:

```go
prMap := prWeightsUnchanged
if s == scopeChanged {
    prMap = prWeightsChanged
}
```

For example, `PR:L` with `S:U` maps to weight 0.62, but `PR:L` with `S:C` maps to 0.68. This reflects the CVSS specification's view that scope changes make privilege requirements less meaningful.

**Score calculation** follows the spec exactly:

```go
iss := 1 - ((1 - metrics.C) * (1 - metrics.I) * (1 - metrics.A))

var impact float64
if metrics.S == scopeUnchanged {
    impact = 6.42 * iss
} else {
    impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
}

if impact <= 0 {
    return 0
}

exploitability := 8.22 * metrics.AV * metrics.AC * metrics.PR * metrics.UI
```

If impact is zero or negative (all CIA impacts are None), the score is 0 regardless of exploitability. You can't have a vulnerability if nothing is affected.

**CVSS round-up** is a spec-defined operation that rounds to one decimal place, always rounding up:

```go
func cvssRoundUp(val float64) float64 {
    shifted := math.Round(val*100000) / 100000
    return math.Ceil(shifted*10) / 10
}
```

The intermediate `Round` at 5 decimal places handles floating-point precision issues before the final `Ceil`.

### SQLite Cache (`internal/vuln/cache.go`)

The cache stores vulnerability results to avoid redundant API calls:

```go
func NewCache(dbPath string, ttl time.Duration) (*Cache, error) {
    dir := filepath.Dir(dbPath)
    if err := os.MkdirAll(dir, 0o755); err != nil {
        return nil, fmt.Errorf("create cache dir: %w", err)
    }

    db, err := sql.Open("sqlite", dbPath)
    ...
}
```

`MkdirAll` creates `~/.bomber/` if it doesn't exist. The SQLite driver is `modernc.org/sqlite`, a pure-Go implementation that requires no CGo.

**Cache reads** check TTL before returning results:

```go
func (c *Cache) Get(purl, source string) ([]types.VulnMatch, bool, error) {
    ...
    created := time.UnixMilli(createdAt)
    if time.Since(created) > c.ttl {
        return nil, false, nil
    }
    ...
}
```

Expired entries aren't deleted on read. They're left in place and overwritten on the next write (`INSERT OR REPLACE`). This avoids the need for a separate cleanup goroutine.

## Building the Policy Engine

### Policy Loading (`internal/policy/rules.go`)

```go
type Policy struct {
    MaxSeverity string `yaml:"max_severity"`
    MaxAgeDays  int    `yaml:"max_age_days"`
    MaxDepth    int    `yaml:"max_depth"`
}
```

The policy file is YAML. An empty field means the rule is disabled. A minimal policy might be just `max_severity: medium`.

### Policy Evaluation (`internal/policy/engine.go`)

The engine checks three rule types sequentially:

**Severity check** compares each vulnerability's severity rank against the threshold:

```go
if p.MaxSeverity != "" {
    threshold := types.ParseSeverity(p.MaxSeverity)
    for _, m := range report.Matches {
        if m.Vulnerability.Severity.Rank() > threshold.Rank() {
            ...
            result.Passed = false
        }
    }
}
```

Setting `max_severity: medium` allows None, Low, and Medium but fails on High or Critical.

**Age check** computes a cutoff date and compares against each vulnerability's published date:

```go
if p.MaxAgeDays > 0 {
    cutoff := time.Now().AddDate(0, 0, -p.MaxAgeDays)
    for _, m := range report.Matches {
        if !m.Vulnerability.Published.IsZero() && m.Vulnerability.Published.Before(cutoff) {
            ...
        }
    }
}
```

The `IsZero()` check handles vulnerabilities where the published date isn't available (some OSV entries lack this field). Unknown dates don't trigger the rule.

**Depth check** operates on the graph structure, not individual vulnerabilities:

```go
if p.MaxDepth > 0 {
    for _, g := range graphs {
        depth := graph.MaxDepth(g)
        if depth > p.MaxDepth {
            ...
        }
    }
}
```

This rule is ecosystem-wide: if any dependency in any graph exceeds the depth limit, the check fails.

## Building the Vulnerability Orchestrator

### Cache-First Query Strategy (`internal/cli/vuln.go`)

The `queryVulns` function in `vuln.go` orchestrates the full vulnerability scanning pipeline. It iterates each client, checks cache first, queries uncached packages, and stores results:

```go
for _, client := range clients {
    var uncached []types.Package
    for _, pkg := range allPkgs {
        if cache != nil {
            cached, ok, err := cache.Get(pkg.PURL, client.Source())
            if err == nil && ok {
                vulnReport.Matches = append(vulnReport.Matches, cached...)
                continue
            }
        }
        uncached = append(uncached, pkg)
    }

    if len(uncached) == 0 {
        continue
    }

    matches, err := client.Query(ctx, uncached)
    ...
}
```

### Deduplication

When both OSV and NVD report the same vulnerability, `deduplicateMatches` merges them:

```go
func deduplicateMatches(matches []types.VulnMatch) []types.VulnMatch {
    seen := make(map[string]int)
    var deduped []types.VulnMatch

    for _, m := range matches {
        ids := make([]string, 0, 1+len(m.Vulnerability.Aliases))
        ids = append(ids, m.Vulnerability.ID)
        ids = append(ids, m.Vulnerability.Aliases...)

        existingIdx := -1
        for _, id := range ids {
            if idx, ok := seen[id]; ok {
                existingIdx = idx
                break
            }
        }

        if existingIdx >= 0 {
            existing := deduped[existingIdx]
            if m.Vulnerability.Score > existing.Vulnerability.Score ||
                (m.Vulnerability.FixVersion != "" && existing.Vulnerability.FixVersion == "") {
                deduped[existingIdx] = m
            }
            continue
        }
        ...
    }
}
```

The `seen` map tracks every ID and alias for every vulnerability. When a new match arrives, all its IDs and aliases are checked against the map. If there's overlap, the better entry wins: higher CVSS score takes priority, and entries with fix versions are preferred over those without.

## Building the Report Layer

### Terminal Output (`internal/report/terminal.go`)

**Scan summary** is concise: total packages, direct vs transitive breakdown, detected ecosystems, and cycle warnings:

```go
func PrintScanSummary(w io.Writer, result *types.ScanResult) {
    fmt.Fprintf(w, "  %s Scanned %d packages (%d direct",
        ui.Check, result.TotalPkgs, result.DirectPkgs)

    transitive := result.TotalPkgs - result.DirectPkgs
    if transitive > 0 {
        fmt.Fprintf(w, ", %d transitive", transitive)
    }
    ...
}
```

**Vulnerability report** groups by severity (critical first), sorts by CVSS score within each group, and color-codes headers:

```go
switch sev {
case types.SeverityCritical:
    fmt.Fprintf(w, "  %s\n", ui.Red(header))
case types.SeverityHigh:
    fmt.Fprintf(w, "  %s\n", ui.Yellow(header))
case types.SeverityMedium:
    fmt.Fprintf(w, "  %s\n", ui.Cyan(header))
default:
    fmt.Fprintf(w, "  %s\n", ui.Dim(header))
}
```

Each vulnerability shows the affected PURL, vulnerability ID, truncated summary (60 char max), CVSS score, and fix version if available.

### JSON Output (`internal/report/json.go`)

The JSON reporter wraps all three result types into a single envelope:

```go
type JSONReport struct {
    Scan   *types.ScanResult   `json:"scan,omitempty"`
    Vulns  *types.VulnReport   `json:"vulnerabilities,omitempty"`
    Policy *types.CheckResult  `json:"policy,omitempty"`
}
```

Fields are `omitempty` so that `bomber scan --format json` only includes the scan section, while `bomber check --format json` includes all three.

## Testing Strategy

### Unit Tests

Each package has focused unit tests that verify behavior without external dependencies:

- **Parser tests** use `testdata/` fixtures: real `go.mod`, `package.json`, `pyproject.toml`, and lockfiles. Tests verify correct package counts, version extraction, direct/transitive classification, and checksum parsing.
- **Graph tests** construct graphs programmatically and verify traversal, cycle detection, and merging.
- **CVSS tests** verify known CVE vectors against expected scores (e.g., CVE-2023-44487 = 7.5, Log4Shell = 10.0).
- **Cache tests** use `t.TempDir()` for isolated SQLite databases and verify put/get, expiry, miss, and overwrite behavior.

### Integration Tests

`internal/scanner/integration_test.go` tests the full pipeline: scan testdata directories, build graphs, verify no cycles, generate SPDX and CycloneDX output, validate JSON.

### Vulnerability Client Tests

OSV and NVD tests use `net/http/httptest` servers that return fixture responses. This avoids flaky tests from real API calls while still testing the full HTTP request/response cycle, including URL construction, header setting, and response parsing.

### Running Tests

```bash
just test         # go test -race ./...
just test-v       # with verbose output
just cover        # with coverage summary
just cover-html   # generate HTML coverage report
```

## Dependencies

### Why Each Dependency

- **cobra** (v1.10.2): CLI framework. Bomber has four subcommands with persistent flags, custom help rendering, and signal handling. Cobra handles all of this.
- **fatih/color** (v1.19.0): Terminal color output. Used via wrapper functions at `internal/ui/color.go`. Respects `NO_COLOR` environment variable and `--no-color` flag.
- **go-toml/v2** (v2.3.0): TOML parser for `pyproject.toml` and `uv.lock`. Uses struct tags for clean deserialization.
- **yaml.v3** (v3.0.1): YAML parser for `pnpm-lock.yaml` and `policy.yaml`.
- **modernc.org/sqlite** (v1.48.1): Pure-Go SQLite implementation. No CGo, no C compiler needed, single static binary output.
- **google/uuid** (v1.6.0): UUID generation for CycloneDX serial numbers.
- **testify** (v1.11.1): Test assertions and requirements. Used throughout the test suite for `assert.Equal`, `require.NoError`, etc.

## Next Steps

You've seen how the code works. Now:

1. **Try the challenges** - [04-CHALLENGES.md](./04-CHALLENGES.md) has extension ideas from easy to expert
2. **Modify the code** - Change the Go parser to use `go list -m -json all` instead of `go mod graph` and compare the output
3. **Read related projects** - The secrets-scanner project uses similar patterns (Cobra CLI, registry, testdata fixtures) in a different security domain
