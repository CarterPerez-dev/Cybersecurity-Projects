# 02-ARCHITECTURE.md

# Architecture

This document covers the system design of credenum: how components connect, why they're structured this way, and the trade-offs behind the design decisions.

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          CLI (harvester.nim)                             │
│  Parse arguments → Validate config → Route to dry-run or scan           │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │ HarvestConfig
                                   ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         Runner (runner.nim)                              │
│  Iterate enabled modules → Dispatch to collectors → Aggregate results   │
└───────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┘
        │          │          │          │          │          │
        ▼          ▼          ▼          ▼          ▼          ▼
  ┌──────────┐┌─────────┐┌───────┐┌─────────┐┌─────────┐┌──────────┐
  │ browser  ││  ssh    ││ cloud ││ history ││ keyring ││   git    │
  └──────────┘└─────────┘└───────┘└─────────┘└─────────┘└──────────┘
        │          │          │          │          │          │
        └──────────┴──────────┴──────────┴──────────┴──────────┘
                                   │
                            ┌──────┴──────┐
                            │  apptoken   │
                            └─────────────┘
                                   │
                    All collectors share base.nim utilities
                    All return CollectorResult
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         Report Assembly                                  │
│  Combine CollectorResults → Calculate severity summary → Add metadata   │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │ Report
                    ┌──────────┴──────────┐
                    ▼                     ▼
          ┌─────────────────┐   ┌─────────────────┐
          │ terminal.nim    │   │ json.nim         │
          │ Box-drawn color │   │ Structured JSON  │
          │ output to stdout│   │ to stdout/file   │
          └─────────────────┘   └─────────────────┘
                    │                     │
                    ▼                     ▼
             Exit code 0/1         Exit code 0/1
          (0=clean, 1=high/critical findings)
```

## Component Breakdown

### CLI Layer (harvester.nim)

**Purpose:** Parse command-line arguments, build configuration, and orchestrate the scan lifecycle.

**Responsibilities:**
- Parse CLI flags using Nim's `parseopt` (no external dependencies)
- Construct a `HarvestConfig` with validated settings
- Short-circuit for `--help`, `--version`, and `--dry-run`
- Call the runner, render output, and determine exit code

**Interfaces:**
- Input: Raw command-line arguments
- Output: Exit code (0 or 1), rendered output to stdout

The CLI layer is deliberately thin. It does no scanning and no output formatting. It builds config, calls the runner, picks the formatter, and exits.

### Runner (runner.nim)

**Purpose:** Map enabled module categories to their collector implementations and aggregate results.

**Responsibilities:**
- Maintain the `Category → CollectorProc` routing table via `getCollector`
- Iterate through `config.enabledModules` and invoke each collector
- Time the full scan duration
- Sum severity counts into the report summary

**Interfaces:**
- Input: `HarvestConfig`
- Output: `Report` (metadata + results + summary)

The runner doesn't know how collectors work internally. It gets a function pointer from `getCollector`, calls it, and collects the result. This means adding a new collector category requires only adding a case to the routing table and importing the module.

### Collectors (collectors/*.nim)

**Purpose:** Each collector scans for one category of credential exposure and returns findings.

**Responsibilities:**
- Scan known file paths for the category
- Analyze file contents and permissions
- Construct `Finding` objects with severity classification
- Return a `CollectorResult` with all findings and any errors

**Shared interface:** Every collector exports a `collect` proc with the signature:

```nim
proc collect*(config: HarvestConfig): CollectorResult {.nimcall, raises: [].}
```

This uniform signature is what makes the routing table work. The runner doesn't need to know which collector it's calling.

### Base Utilities (collectors/base.nim)

**Purpose:** Provide shared file system operations and finding construction helpers.

**Responsibilities:**
- Safe file/directory existence checks (catch filesystem exceptions)
- POSIX stat-based permission inspection
- File metadata extraction (size, modification time, permissions string)
- Finding and credential factory functions
- Permission-based severity calculation
- Value redaction for credential previews

The base module is the only place that directly calls POSIX syscalls. All collectors go through `safeFileExists`, `readFileContent`, `getNumericPerms`, and the `makeFinding`/`makeFindingWithCred` constructors rather than using `os` and `posix` directly.

### Output Renderers (output/*.nim)

**Purpose:** Transform a `Report` into human-readable or machine-readable output.

**terminal.nim:**
- Renders the ASCII banner, module headers with box drawing, severity badges with ANSI colors, finding details, and a summary footer
- Handles visual-length calculation for strings containing ANSI escape codes and multi-byte UTF-8 characters
- Respects `--quiet` (suppress banner) and `--verbose` (show empty modules)

**json.nim:**
- Converts the entire `Report` to a nested JSON structure
- Writes to stdout and optionally to a file via `--output`
- Uses Nim's stdlib `json` module for serialization

Both renderers are read-only consumers of the `Report` type. They don't modify data or trigger side effects beyond writing to stdout/file.

## Data Flow

### Primary Flow: Full Scan

1. User runs `credenum --modules ssh,cloud --format terminal`
2. `parseCli()` parses arguments into `HarvestConfig` with `enabledModules = @[catSsh, catCloud]`
3. `main()` calls `runCollectors(config)`
4. Runner iterates `[catSsh, catCloud]`:
   - Looks up `ssh.collect` via `getCollector(catSsh)`, calls it
   - `ssh.collect` calls `scanKeys`, `scanConfig`, `scanAuthorizedKeys`, `scanKnownHosts`
   - Each sub-scanner uses `base.nim` to check files, read contents, analyze permissions
   - Returns `CollectorResult` with findings and timing
   - Same for `cloud.collect` → `scanAws`, `scanGcp`, `scanAzure`, `scanKubernetes`
5. Runner sums severity counts into `Report.summary`
6. `main()` adds UTC timestamp to metadata
7. `renderTerminal(report, quiet, verbose)` writes formatted output
8. If any CRITICAL or HIGH findings exist, exit with code 1

### Secondary Flow: Dry Run

1. User runs `credenum --dry-run`
2. `parseCli()` sets `config.dryRun = true`
3. `main()` calls `renderDryRun(config)` which prints the module list and target directory
4. Exit with code 0 (no scanning occurs)

### Finding Construction Flow

When a collector discovers a credential file:

```
File exists? (safeFileExists)
    │
    ▼ yes
Read content (readFileContent)
    │
    ▼
Analyze content (is it a private key? does it contain tokens?)
    │
    ▼
Check permissions (getNumericPerms → isWorldReadable, isGroupReadable)
    │
    ▼
Determine severity (content analysis + permission analysis)
    │
    ▼
Build Finding:
  ├── makeFinding(path, desc, category, severity)        [no credential detail]
  └── makeFindingWithCred(path, desc, category, sev, cred)  [with credential detail]
        │
        ▼
  Finding includes:
    path, category, severity, description,
    permissions (from getPermsString),
    modified (from getModifiedTime),
    size (from getFileSizeBytes),
    credential (optional: source, type, preview, metadata)
```

## Type System Design

### Core Types (types.nim)

```
                        ┌───────────────┐
                        │    Report     │
                        ├───────────────┤
                        │ metadata      │──── ReportMetadata
                        │ results       │──── seq[CollectorResult]
                        │ summary       │──── array[Severity, int]
                        └───────────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
          ┌─────────────────┐   ┌─────────────────┐
          │ ReportMetadata  │   │ CollectorResult  │
          ├─────────────────┤   ├─────────────────┤
          │ timestamp       │   │ name             │
          │ target          │   │ category         │
          │ version         │   │ findings         │──── seq[Finding]
          │ durationMs      │   │ durationMs       │
          │ modules         │   │ errors           │
          └─────────────────┘   └─────────────────┘
                                        │
                                        ▼
                              ┌─────────────────┐
                              │    Finding       │
                              ├─────────────────┤
                              │ path            │
                              │ category        │──── Category enum
                              │ severity        │──── Severity enum
                              │ description     │
                              │ credential      │──── Option[Credential]
                              │ permissions     │
                              │ modified        │
                              │ size            │
                              └─────────────────┘
                                        │
                              ┌─────────┴────────┐
                              ▼                  ▼
                    ┌──────────────┐    ┌──────────────┐
                    │  Severity    │    │  Credential   │
                    ├──────────────┤    ├──────────────┤
                    │ svInfo       │    │ source       │
                    │ svLow        │    │ credType     │
                    │ svMedium     │    │ preview      │
                    │ svHigh       │    │ metadata     │
                    │ svCritical   │    └──────────────┘
                    └──────────────┘
```

### Why This Structure

**Severity as an enum with string values:** Each severity level maps directly to a display label (`"info"`, `"low"`, `"medium"`, `"high"`, `"critical"`). Using an enum rather than strings means severity comparisons are integer operations, severity can be used as an array index (for colors, labels, and summary counts), and invalid severity values are caught at compile time.

**Finding with Optional Credential:** Not every finding has credential details. An SSH directory with wrong permissions is a finding but doesn't have a credential to display. A `.pgpass` file has specific entries worth showing. The `Option[Credential]` type makes this explicit rather than using an empty Credential struct.

**Credential with metadata Table:** Different credential types have different attributes. An AWS credential has profile count, static/session key counts. An SSH key has encryption status. A Kubernetes config has context and user counts. A `Table[string, string]` metadata field handles this variation without needing a different Credential type per category.

**CollectorResult with errors seq:** Filesystem operations can fail (permissions denied, broken symlinks, missing directories). Rather than aborting, collectors catch errors and add them to the errors list. The output renderer shows these errors alongside findings so the user knows what couldn't be scanned.

**Report.summary as array[Severity, int]:** Using the Severity enum as an array index gives O(1) lookup for severity counts and makes iteration natural: `for sev in Severity: report.summary[sev]`.

### Configuration Types

```nim
HarvestConfig = object
  targetDir: string           # Which home directory to scan
  enabledModules: seq[Category]  # Which collectors to run
  excludePatterns: seq[string]   # Paths/names to skip
  outputFormat: OutputFormat     # terminal, json, or both
  outputPath: string           # File path for JSON output
  dryRun: bool                 # Preview mode
  quiet: bool                  # Suppress banner
  verbose: bool                # Show empty modules
```

The config object is passed to every collector by value. Collectors never modify it.

```nim
CollectorProc = proc(config: HarvestConfig): CollectorResult {.nimcall, raises: [].}
```

The `CollectorProc` type alias defines the contract every collector must satisfy. The `raises: []` pragma means the proc cannot raise exceptions. This is enforced at compile time by `{.push raises: [].}` at the top of every file.

## Design Patterns

### Strategy Pattern (Collector Dispatch)

The runner uses the strategy pattern for collector dispatch. Each Category maps to a collector function with an identical signature:

```
getCollector(catBrowser) → browser.collect
getCollector(catSsh)     → ssh.collect
getCollector(catCloud)   → cloud.collect
...
```

This is a case statement rather than a table because Nim's exhaustive case checking ensures every Category has a handler. If you add a new Category to the enum, the compiler forces you to handle it in `getCollector`.

### Factory Pattern (Finding Construction)

The `makeFinding` and `makeFindingWithCred` functions in base.nim are factories that handle the boilerplate of constructing a Finding: looking up permissions, modification time, and file size. Collectors call the factory with just the path, description, category, and severity. This prevents inconsistencies where one collector forgets to set the modification time or uses a different permissions format.

### Layered Scanning (Within Collectors)

Each collector internally uses a layered scanning approach where sub-scanners handle specific aspects:

```
ssh.collect
  ├── scanKeys         # Private key files
  ├── scanConfig       # SSH client configuration
  ├── scanAuthorizedKeys   # Authorized public keys
  └── scanKnownHosts      # Known host entries
```

Sub-scanners modify the `CollectorResult` in-place via `var` parameter rather than returning separate results. This avoids allocation overhead from merging multiple sequences.

## Severity Classification Model

The severity model has two inputs: content analysis and permission analysis. The higher severity wins.

```
Content-based severity:
  ┌─────────────────────────────────────────────────┐
  │ Unencrypted SSH key           → HIGH            │
  │ Encrypted SSH key             → INFO            │
  │ Plaintext Git credentials     → HIGH            │
  │ AWS static keys (AKIA)        → HIGH            │
  │ GCP service account key       → HIGH            │
  │ Database password file        → HIGH            │
  │ Secret in shell history       → HIGH            │
  │ Config file (no secrets)      → INFO            │
  └─────────────────────────────────────────────────┘

Permission-based override:
  ┌─────────────────────────────────────────────────┐
  │ World-readable (0o004 bit)    → CRITICAL        │
  │ Group-readable (0o040 bit)    → MEDIUM or HIGH  │
  │ Looser than expected          → LOW             │
  │ Owner-only                    → (no override)   │
  └─────────────────────────────────────────────────┘
```

The final severity is the maximum of content-based and permission-based. An encrypted SSH key (INFO from content) that's world-readable (CRITICAL from permissions) becomes CRITICAL.

## Configuration Architecture

### Zero External Configuration

The tool has no configuration files, no environment variables, and no dotfiles. All configuration comes from CLI flags with sensible defaults:

| Setting | Default | Override |
|---------|---------|----------|
| Target directory | Current user's home | `--target <path>` |
| Enabled modules | All 7 | `--modules ssh,git,...` |
| Exclude patterns | None | `--exclude .cache,vendor` |
| Output format | Terminal | `--format json\|both` |
| Output file | None (stdout only) | `--output report.json` |

This is intentional. A security tool that reads config from the filesystem creates a circular dependency: you're scanning for exposed configuration while relying on configuration that could itself be tampered with.

### Constants Architecture

All scan targets, patterns, and thresholds are defined as compile-time constants in `config.nim`. This means:

- No runtime configuration parsing
- No allocation for path lists or pattern arrays
- Compiler can inline and optimize all constant lookups
- Adding a new scan target is a one-line change to a constant array

The constants are organized by category (SSH, AWS, GCP, browser, etc.) with clear groupings. UI constants (colors, box-drawing characters, severity labels) are also in config.nim to keep them centralized.

## Error Handling Strategy

### No Exceptions, Ever

Every file in the project starts with `{.push raises: [].}`. This Nim pragma tells the compiler that no proc in this file is allowed to raise an exception. Any call to a function that might raise (file I/O, string operations, etc.) must be wrapped in try/except.

This is enforced at compile time. If you add a call to `readFile()` without a try/except, the compiler will reject it with an error showing exactly which function could raise and where.

### Error Recovery Pattern

Every file system operation follows the same pattern:

1. Try the operation
2. On success, process the result
3. On failure, either return a safe default or add to the error list

```
safeFileExists()  → returns false on exception
readFileContent() → returns "" on exception
getNumericPerms() → returns -1 on exception
walkDir()         → caught at collector level, added to errors[]
```

Collectors never abort. A failed directory walk adds an error message and continues scanning other paths. The final report shows both findings and errors, so the user knows what was scanned and what was skipped.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no HIGH or CRITICAL findings |
| 1 | Scan completed, HIGH or CRITICAL findings detected |

The exit code is determined after all output is rendered. This allows the tool to be used in scripts and CI pipelines: `credenum --quiet --format json -o report.json && echo "clean" || echo "findings detected"`.

## Performance Considerations

### Sequential Collector Execution

Collectors run sequentially, not in parallel. This is a deliberate choice:

- Most collectors complete in under 10ms (the target is a single home directory, not a network scan)
- Sequential execution produces deterministic output ordering
- No thread synchronization overhead
- No risk of TOCTOU races on file metadata
- Total scan time is typically under 100ms for a full home directory

If parallel execution were needed (e.g., for network shares or very large home directories), the uniform `CollectorProc` signature makes parallelization straightforward: spawn each collector in a thread and collect results.

### Memory Efficiency

- All constant data (paths, patterns, colors) is compiled into the binary, not allocated at runtime
- File contents are read entirely into strings (not streamed) because credential files are small (typically under 1KB)
- Shell history scanning caps at 50,000 lines to prevent unbounded memory usage on extremely large history files
- Recursive directory walking (for .env files and .kdbx databases) is depth-limited to 5 levels
- Findings are collected into sequences that grow as needed, with no pre-allocation

### Binary Size

| Build | Size | Notes |
|-------|------|-------|
| Debug | ~2MB | Full symbols, bounds checking |
| Release | ~500KB | Optimized, LTO, stripped |
| Static release | ~400KB | musl, no glibc dependency |
| Compressed | ~150KB | UPX on top of static release |

The compressed binary is small enough to transfer over slow connections or embed in other tools.

## Extensibility

### Adding a New Collector

To add a new collector (e.g., for container credentials):

1. Add a new value to the `Category` enum in `types.nim`
2. Add the module name and description to the arrays in `config.nim`
3. Create `collectors/container.nim` implementing `proc collect*(config: HarvestConfig): CollectorResult`
4. Add the import and case branch in `runner.nim`'s `getCollector`

The compiler will guide you: adding a Category enum value without handling it in the case statement produces a compile error.

### Adding a New Output Format

To add a new output format (e.g., SARIF):

1. Add a value to the `OutputFormat` enum
2. Create `output/sarif.nim` with a `proc renderSarif*(report: Report, outputPath: string)` 
3. Add the case branch in `harvester.nim`'s main function

The output module receives the complete `Report` and has full freedom in how it renders it.

### Adding New Scan Targets

To scan for a new credential file within an existing category:

1. Add the path constant to `config.nim`
2. Add scanning logic in the relevant collector
3. Add a test fixture in `tests/docker/planted/` and a check in `validate.sh`

No other files need to change.

## Limitations

**Linux-only.** The tool targets Linux credential storage paths. macOS stores credentials differently (Keychain, different browser paths). Windows has an entirely different model (Credential Manager, DPAPI). Supporting other platforms would require platform-specific collector implementations.

**Read-only.** The tool detects but doesn't remediate. It won't fix permissions, encrypt keys, or rotate credentials. This is intentional: a scanning tool should never modify the filesystem it's inspecting.

**Static paths.** Credential paths are compiled into the binary as constants. Non-standard installations (e.g., Firefox installed via Flatpak, Snap-based browsers, custom HOME directory layouts) may store credentials in different locations that the tool doesn't check.

**No credential decryption.** The tool identifies encrypted credential stores but doesn't attempt to decrypt them. It checks whether encryption is present and whether file permissions expose the encrypted data, but it doesn't evaluate encryption strength or attempt brute-force.

## Key Files Reference

| File | Purpose |
|------|---------|
| `src/harvester.nim` | Entry point, CLI parsing, main loop |
| `src/runner.nim` | Collector dispatch and result aggregation |
| `src/types.nim` | All type definitions |
| `src/config.nim` | All constants (paths, patterns, colors, UI) |
| `src/collectors/base.nim` | Shared utilities for all collectors |
| `src/collectors/*.nim` | One file per credential category |
| `src/output/terminal.nim` | Terminal renderer with box drawing |
| `src/output/json.nim` | JSON serializer |
| `tests/test_all.nim` | Unit tests |
| `tests/docker/` | Docker integration test infrastructure |
| `config.nims` | Nim compiler configuration |
| `Justfile` | Build automation commands |

## Next Steps

- Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) to see how each component is implemented, with code walkthroughs of the CLI parser, collector modules, permission analysis, and output rendering
- Read [04-CHALLENGES.md](./04-CHALLENGES.md) for extension ideas
