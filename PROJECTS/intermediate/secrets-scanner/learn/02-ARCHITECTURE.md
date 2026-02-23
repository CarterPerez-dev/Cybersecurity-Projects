# System Architecture

This document breaks down how Portia is designed and why certain architectural decisions were made. We'll trace requests through the system and explain the tradeoffs.

## High Level Architecture

```
┌──────────────────────────────────────────────────────┐
│                       CLI                            │
│           root.go, scan.go, git.go                   │
└───────────────────────┬──────────────────────────────┘
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
      ┌──────────────┐   ┌──────────────┐
      │   Directory   │   │     Git      │
      │    Source     │   │    Source     │
      │ directory.go  │   │   git.go     │
      └──────┬───────┘   └──────┬───────┘
             │                   │
             └─────────┬─────────┘
                       │
                       ▼ chan types.Chunk
              ┌─────────────────┐
              │    Pipeline     │
              │  pipeline.go    │
              ├─────────────────┤
              │                 │
              │  ┌───────────┐  │
              │  │ Worker 1  │  │
              │  │ detector  │  │
              │  └───────────┘  │
              │  ┌───────────┐  │
              │  │ Worker 2  │  │
              │  │ detector  │  │
              │  └───────────┘  │
              │  ┌───────────┐  │
              │  │ Worker N  │  │
              │  │ detector  │  │
              │  └───────────┘  │
              │                 │
              └────────┬────────┘
                       │
                       ▼ chan types.Finding
              ┌─────────────────┐
              │   Collector     │
              │  dedup + merge  │
              └────────┬────────┘
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
      ┌──────────────┐  ┌──────────────┐
      │  HIBP Check  │  │   Reporter   │
      │  (optional)  │  │  term/json/  │
      │  client.go   │  │    sarif     │
      └──────┬───────┘  └──────────────┘
             │                 ▲
             └─────────────────┘
```

## Component Breakdown

### CLI Layer (`internal/cli/`)

**Purpose:** Parse command line arguments and orchestrate the scan workflow.

**Responsibilities:**
- Route `scan`, `git`, `init`, `pyproject`, `config` commands to their handlers
- Merge CLI flags with TOML config file values (CLI flags take precedence)
- Create the appropriate Source, run the Pipeline, optionally check HIBP, produce output

**Interfaces:** Uses Cobra for argument parsing. Each command is a `cobra.Command` with a `RunE` function. The `executeScan` function in `scan.go` is shared between `scan` and `git` commands.

### Config Loader (`internal/config/`)

**Purpose:** Load and merge configuration from `.portia.toml` files.

**Responsibilities:**
- Search for config files in three locations: current directory, `.portia/config.toml`, `~/.config/portia/config.toml`
- Fall back to `pyproject.toml` (`[tool.portia]` table) when no `.portia.toml` is found
- Parse TOML into a `Config` struct with sections for Rules, Scan, Output, HIBP, Allowlist
- Provide default templates for `portia init` and `portia pyproject`

**Interfaces:** `Load(path string) (*Config, error)` returns a config or error. Empty path triggers auto-discovery.

### Source Interface (`internal/source/`)

**Purpose:** Produce chunks of text from various inputs (directories, git history).

**Responsibilities:**
- Walk filesystem or git object tree
- Skip binary files, excluded paths, oversized files
- Split content into 50-line chunks with file path and line number metadata
- Send chunks into a channel for pipeline consumption

**Interfaces:**
```go
type Source interface {
    Chunks(ctx context.Context, out chan<- types.Chunk) error
    String() string
}
```

**Directory source** (`directory.go`):
- Uses `filepath.WalkDir` for filesystem traversal
- Skips `.git`, `node_modules`, `vendor`, `__pycache__`, `.venv`
- Checks file size against configurable max (default 1MB)
- Chunks files into 50-line segments using a buffered scanner

**Git source** (`git.go`):
- Uses go-git v5 for in-process git operations
- `scanHistory`: walks commit log backwards, extracts file content from each commit's tree
- `scanStaged`: reads git index entries for staged-only scanning
- Supports `--branch`, `--since`, `--depth` filters

### Rule Registry (`internal/rules/`)

**Purpose:** Store detection rules and provide fast keyword-based lookup.

**Responsibilities:**
- Store rules in a map keyed by rule ID
- Provide `MatchKeywords(content)` that returns only rules whose keywords appear in the content
- Support enabling/disabling rules
- Maintain global path and value allowlists

**Interfaces:** `Register(rule)`, `Get(id)`, `All()`, `MatchKeywords(content)`, `Disable(ids...)`, `Len()`

### Detection Engine (`internal/engine/`)

**Purpose:** Apply rules to chunks and produce findings.

**Detector** (`detector.go`):
- Takes a chunk, runs keyword pre-filter via registry
- For each matched rule, scans line by line with regex
- Extracts secret from capture group
- Validates entropy if the rule has an entropy threshold
- Runs through FilterFinding for false positive reduction

**Filter** (`filter.go`):
- `IsPlaceholder` - checks against GlobalValueAllowlist patterns
- `IsTemplated` - checks for `${...}`, `{{...}}`, `os.getenv()`, `process.env.`
- `IsStopword` - splits secret on `_-./` delimiters, checks parts against 700+ stopwords
- `IsAllowedPath` - checks file path against GlobalPathAllowlist
- `FilterFinding` - orchestrates all checks, returns true if finding is real

**Pipeline** (`pipeline.go`):
- Creates errgroup with source goroutine + N worker goroutines + collector goroutine
- Workers pull chunks from channel, run detector, push findings to findings channel
- Collector merges all findings, deduplicates by ruleID+filePath+secret+commitSHA

### HIBP Client (`internal/hibp/`)

**Purpose:** Check detected secrets against the Have I Been Pwned breach database.

**Responsibilities:**
- SHA-1 hash computation
- k-anonymity API queries (5-char prefix)
- LRU cache (10,000 entries) for repeated lookups
- Circuit breaker (5 failures = 60s cooldown)
**Interfaces:** `Check(ctx, secret) (Result, error)`

### Reporters (`internal/reporter/`)

**Purpose:** Format scan results for output.

**Terminal** (`terminal.go`): Colored output with severity-based colors (red for CRITICAL, yellow for MEDIUM), secret masking (show first/last few characters), SHA truncation for git commits, HIBP breach status.

**JSON** (`json.go`): Structured JSON with `findings` array and `summary` object. Secrets are masked in output.

**SARIF** (`sarif.go`): SARIF v2.1.0 compliant output with tool metadata, rule definitions, results with locations and properties.

**Interfaces:** `Reporter` interface with `Report(w io.Writer, result *types.ScanResult) error`. Factory function `New(format) Reporter` returns the appropriate implementation.

## Data Flow

### Tracing: `portia scan ./myproject`

Step-by-step walkthrough of what happens when you run a directory scan:

```
1. CLI parses arguments
   root.go:init() → cobra.OnInitialize(initConfig)
   scan.go:runScan() receives path="./myproject"

2. Config loading
   root.go:initConfig() → config.Load(cfgFile)
   Merges CLI flags with TOML config
   Format defaults to "terminal", maxSize defaults to 1MB

3. Registry setup
   scan.go:runScan() → rules.NewRegistry() + rules.RegisterBuiltins(reg)
   Loads 150 rules into the registry map
   Applies disabled rules from config: reg.Disable(cfg.Rules.Disable...)

4. Source creation
   scan.go:runScan() → source.NewDirectory(path, maxSize, excludes)
   Creates Directory struct with path, max file size, exclude patterns

5. Pipeline execution
   scan.go:executeScan() → engine.NewPipeline(reg).Run(ctx, src)

   5a. Source goroutine starts
       Calls src.Chunks(ctx, chunks)
       WalkDir traverses ./myproject
       Skips .git, node_modules, vendor, binary extensions
       Splits each file into 50-line chunks
       Sends each chunk into the chunks channel

   5b. Worker goroutines start (2-16 based on NumCPU)
       Each pulls chunks from the channel
       Calls detector.Detect(chunk):
         - reg.MatchKeywords(chunk.Content) → only rules with matching keywords
         - For each matched rule, scan each line with rule.Pattern regex
         - Extract secret from capture group
         - If rule has entropy threshold, compute Shannon entropy and compare
         - Run FilterFinding: IsPlaceholder → IsTemplated → IsStopword → path allowlist
         - If all checks pass, create Finding and send to findings channel

   5c. Collector goroutine
       Pulls findings from findings channel
       Appends to allFindings slice (mutex-protected)

   5d. Wait for all goroutines (errgroup.Wait)
       Dedup findings by ruleID+filePath+secret+commitSHA

6. HIBP verification (if --hibp flag)
   scan.go:checkHIBP(ctx, result)
   For each finding, calls client.Check(ctx, finding.Secret)
   Updates finding.HIBPStatus and finding.BreachCount

7. Reporter output
   scan.go:executeScan() → reporter.New(format).Report(os.Stdout, result)
   Terminal: colored table with severity, rule, file:line, masked secret
   JSON: structured JSON to stdout
   SARIF: SARIF v2.1.0 JSON to stdout
```

## Concurrency Model

The pipeline uses Go's errgroup pattern for structured concurrency:

```
                    errgroup
                   ┌────────────────────────────────┐
                   │                                │
  Source goroutine │  ──chunks──▶  Worker 1          │
                   │              Worker 2          │
                   │              ...               │
                   │              Worker N          │
                   │              ──findings──▶     │
                   │                    Collector   │
                   │                                │
                   └────────────────────────────────┘
```

**Why bounded workers?** CPU-bound regex matching doesn't benefit from unbounded parallelism. Too many goroutines competing for CPU time causes context switching overhead. The formula `min(max(NumCPU, 2), 16)` gives 2 workers on single-core machines and caps at 16 on large servers.

**Why errgroup?** It provides two things: (1) if any goroutine returns an error, the context is cancelled and all goroutines wind down cleanly, and (2) `g.Wait()` blocks until all goroutines complete, giving you a single point to check for errors.

**Channel sizing:** Channels are buffered at `workers * 4`. This allows the source to stay ahead of workers (avoiding blocking on sends) without unbounded memory growth. If workers are slow, the source will block once the buffer fills, providing natural backpressure.

**The detectWg dance:** Workers share a separate `sync.WaitGroup` so we know when all detection is done. The collector goroutine runs in the same errgroup but only closes after all workers finish. This prevents the collector from exiting early while findings are still being produced. See `pipeline.go:52-77`.

## Configuration Resolution

Configuration is resolved in this order (later overrides earlier):

```
1. Defaults (hardcoded)
   Format: "terminal"
   MaxSize: 1MB (1 << 20)
   Workers: min(max(NumCPU, 2), 16)
   HIBP: disabled
   Verbose: false
   NoColor: false

2. Config file (.portia.toml)
   Searched in order:
     .portia.toml (current directory)
     .portia/config.toml
     ~/.config/portia/config.toml
   First found is loaded. Later paths are not checked.
   If none found, falls back to pyproject.toml ([tool.portia] table).

3. CLI flags
   --format, --verbose, --no-color, --exclude, --max-size, --hibp, --config
   These always win over config file values.
```

This merge logic is in `internal/cli/root.go:initConfig()`. The pattern is: check if the CLI flag was explicitly set (non-zero/non-empty), and only fall back to config file value if the flag wasn't set.

## Rule Matching Strategy

The detection pipeline is optimized for speed. Regex matching is expensive, so the goal is to avoid running regex against content that will never match.

```
Content chunk (50 lines of code)
        │
        ▼
┌───────────────────┐
│  Keyword Filter   │  ← O(rules * keywords) string.Contains
│  ~95% eliminated  │
└────────┬──────────┘
         │ Only rules whose keywords appear in this chunk
         ▼
┌───────────────────┐
│  Line-by-Line     │  ← O(lines * matched_rules) regex
│  Regex Matching   │
└────────┬──────────┘
         │ Raw matches with capture groups
         ▼
┌───────────────────┐
│  Secret Extract   │  ← Extract from capture group
│  + Entropy Check  │     Discard if below threshold
└────────┬──────────┘
         │ Validated candidates
         ▼
┌───────────────────┐
│  Filter Chain     │  ← IsPlaceholder → IsTemplated
│  5-layer check    │     → IsStopword → Allowlists
└────────┬──────────┘
         │ Real findings only
         ▼
      Finding
```

The keyword filter is the key performance optimization. If a 50-line chunk of HTML doesn't contain any strings like `password`, `secret`, `key`, `token`, `AKIA`, `ghp_`, `sk_live`, etc., then zero rules will match and zero regex patterns need to run against it. In practice, this eliminates the vast majority of chunks.
