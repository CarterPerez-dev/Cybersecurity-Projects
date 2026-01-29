# angela

A fast Python dependency updater and vulnerability scanner, written in Go.

angela scans your `pyproject.toml` or `requirements.txt`, updates all dependencies to their latest stable versions, and checks for known CVEs using [OSV.dev](https://osv.dev) — in a single command.

## Highlights

- **One command updates everything** in `pyproject.toml` or `requirements.txt`, like `pnpm update` for Python.
- Fast parallel queries against the [PyPI Simple API](https://peps.python.org/pep-0691/) with local ETag caching.
- Built-in vulnerability scanning via [OSV.dev](https://osv.dev) batch queries — no API key required.
- Full [PEP 440](https://peps.python.org/pep-0440/) version parsing with pre-release filtering and epoch support.
- Comment-preserving file updates — inline comments, section headers, and formatting stay intact.
- Configurable via `.angela.toml` or `[tool.angela]` in `pyproject.toml`.
- Single binary with zero runtime dependencies.

## Installation

```bash
go install github.com/CarterPerez-dev/angela/cmd/angela@latest
```

Or build from source:

```bash
git clone https://github.com/CarterPerez-dev/angela.git
cd angela
go build -o angela ./cmd/angela
```

## Quick start

```bash
# Initialize a new pyproject.toml
angela init

# Update all dependencies to latest stable versions
angela update

# Preview updates without writing changes
angela check

# Scan for known vulnerabilities
angela scan

# Update + scan for vulnerabilities in one pass
angela update --vulns
```

## Commands

### `angela init`

Create a new `pyproject.toml` with angela configuration in the current directory.

```console
$ angela init

  Created pyproject.toml
```

### `angela update`

Update all dependencies in `pyproject.toml` to their latest stable versions.

```console
$ angela update

  Scanning 9 dependencies...

  Updates available:
    django    3.2.0  -> 6.0.1   (major)
    requests  2.28.0 -> 2.32.5  (minor)
    flask     2.0.0  -> 3.1.0   (major)
    click     8.0.0  -> 8.1.8   (patch)

  Updated pyproject.toml
    9 packages checked
    4 updated
    Done in 1.8s
```

Flags:

```
-f, --file string    Path to dependency file (default "pyproject.toml")
    --safe           Skip major version bumps
    --vulns          Also scan for vulnerabilities
    --include-prerelease   Include pre-release versions (alpha, beta, rc, dev)
```

### `angela check`

Show available updates without modifying any files.

```console
$ angela check
```

Accepts the same flags as `update`. Useful for CI or previewing changes before applying them.

### `angela scan`

Scan all dependencies for known vulnerabilities via OSV.dev.

```console
$ angela scan

  Scanning 9 dependencies...

  Vulnerabilities: 36 across 4 packages

    django (30 vulns: 5 critical, 15 high, 10 moderate)
      CRITICAL  CVE-2022-28346  SQL Injection in Django          Fixed: 2.2.28
      CRITICAL  CVE-2022-34265  Trunc()/Extract() SQL Injection  Fixed: 3.2.14
      HIGH      CVE-2023-24580  Resource exhaustion               Fixed: 3.2.18
      HIGH      CVE-2022-36359  Reflected File Download attack   Fixed: 3.2.15
      HIGH      CVE-2023-46695  Potential denial-of-service       Fixed: 4.2.8
      ...and 25 more

    requests (3 vulns: 3 moderate)
      MODERATE  CVE-2024-35195  Session verify=False bypass      Fixed: 2.32.0
      MODERATE  CVE-2023-32681  Proxy-Authorization header leak  Fixed: 2.31.0
      MODERATE  CVE-2024-47081  .netrc credentials leak via URLs  Fixed: 2.32.4

  Run angela scan -v for full details.

    9 packages checked
    36 vulnerabilities found
    Done in 2.4s
```

Use `-v` for full vulnerability details including advisory links:

```console
$ angela scan -v
```

Flags:

```
-f, --file string    Path to dependency file (default "pyproject.toml")
```

### `angela cache clear`

Remove all cached PyPI responses from `~/.angela/cache/`.

### Global flags

```
-v, --verbose            Show full vulnerability details
    --min-severity       Minimum severity to report (critical, high, moderate, low)
```

### Subcommand aliases

| Command | Alias |
|---------|-------|
| `angela update` | `angela u` |
| `angela check` | `angela c` |
| `angela scan` | `angela s` |

## File support

angela works with both `pyproject.toml` and `requirements.txt`. The file type is detected automatically by extension:

```bash
# pyproject.toml (default)
angela update

# requirements.txt
angela update -f requirements.txt
```

For `pyproject.toml`, angela reads `[project.dependencies]` and `[project.optional-dependencies]`. For `requirements.txt`, it parses standard pip-format lines, skipping comments, blank lines, and pip options (`-r`, `-e`, `--index-url`).

Both parsers handle PEP 508 dependency strings including extras (`[security,socks]`) and environment markers (`; python_version >= "3.8"`).

## Configuration

angela supports project-level configuration through either a standalone `.angela.toml` file or a `[tool.angela]` section in `pyproject.toml`.

### `.angela.toml`

```toml
min-severity = "moderate"

ignore = [
    "django",
    "numpy",
]

ignore-vulns = [
    "CVE-2024-3772",
]
```

### `[tool.angela]` in pyproject.toml

```toml
[tool.angela]
min-severity = "moderate"
ignore = ["django", "numpy"]
ignore-vulns = ["CVE-2024-3772"]
```

### Options

| Key | Type | Description |
|-----|------|-------------|
| `min-severity` | string | Minimum severity to report: `critical`, `high`, `moderate`, `low` |
| `ignore` | string array | Package names to skip during updates |
| `ignore-vulns` | string array | Vulnerability IDs to suppress (CVE or GHSA) |

### Resolution order

1. CLI flags (`--min-severity`)
2. `.angela.toml`
3. `[tool.angela]` in `pyproject.toml`
4. Defaults

## How it works

```
1. Parse dependency file
   Read pyproject.toml or requirements.txt
   Extract package names and version specifiers

2. Query PyPI (parallel)
   Fetch version lists from the Simple API with JSON format
   Cache responses locally with ETag support (1-hour TTL)

3. Resolve updates
   Parse versions per PEP 440 (epochs, pre-releases, post-releases)
   Filter to stable releases by default
   Classify changes as major, minor, or patch

4. Scan for vulnerabilities (optional)
   Batch query OSV.dev for all dependencies in a single request
   Hydrate results with full advisory details
   Deduplicate overlapping CVE/GHSA identifiers

5. Write updates
   Regex-based surgery preserves all comments and formatting
   Atomic write via temp file + rename
```

## Project structure

```
cmd/angela/main.go           Entry point
internal/
  cli/
    update.go                Commands and orchestration
    output.go                Terminal formatting
  config/
    config.go                Configuration loading
  pypi/
    client.go                PyPI Simple API client with retry
    version.go               PEP 440 parser and comparator
    cache.go                 File-backed ETag cache
  osv/
    client.go                OSV.dev batch vulnerability scanner
  pyproject/
    parser.go                TOML parsing and PEP 508 splitting
    writer.go                Comment-preserving regex updater
  requirements/
    parser.go                requirements.txt parsing
    writer.go                requirements.txt updater
pkg/types/
  types.go                   Shared domain types
testdata/                    Test fixtures
learn/                       Educational deep dives
```

## Development

Requires Go 1.24+ and [just](https://github.com/casey/just).

```bash
just test        # Run all tests with race detector
just lint        # Run golangci-lint
just build       # Build binary to bin/angela
just cover       # Generate coverage report
just ci          # Lint + test in one step
just run check   # Run angela check via go run
```

## Part of Cybersecurity-Projects

This tool is project #1 in [Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects) — a collection of 60 security-focused projects built for learning and reference.

The code is written to be educational: clear structure, proper error handling, and thorough testing. See the [`learn/`](learn/) directory for deep dives into the techniques used.

## License

MIT
