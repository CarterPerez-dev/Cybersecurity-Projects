# docksec

A command line tool that scans Docker environments for security misconfigurations. It checks running containers, images, Dockerfiles, and compose files against the CIS Docker Benchmark v1.6.0 and generates actionable reports.

## What It Does

```
docksec scans Docker environments for security misconfigurations,
validates against CIS Docker Benchmark controls, and generates
actionable remediation reports.

Usage:
  docksec [command]

Available Commands:
  benchmark   CIS Docker Benchmark information
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  scan        Scan Docker environment for security issues
  version     Print version information

Flags:
  -h, --help   help for docksec

Use "docksec [command] --help" for more information about a command.
```

## Installation

### Option 1: Build from source (if you cloned this repo)

You need Go 1.21 or later installed.

```bash
go build -o docksec ./cmd/docksec
./docksec scan
```

This builds a binary in the current directory. The `./` is required because the binary is not in your PATH.

### Option 2: Go install (for Go developers) This same project lives in a seperate repo https://github.com/CarterPerez-dev/docksec - in order to be able to:

```bash
go install github.com/CarterPerez-dev/docksec/cmd/docksec@latest
docksec scan
```

Because downloads the source, compiles it on your machine, and puts the binary in `~/go/bin/`. If that directory is in your PATH, you can run `docksec` directly without `./`.

The `/cmd/docksec` path is needed because the main package lives in that subdirectory, not at the repo root.

### Option 3: Docker (no installation needed)

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docksec scan
```

The `-v /var/run/docker.sock:/var/run/docker.sock` part gives the container access to your host's Docker daemon so it can inspect containers and images. Without this mount, it cannot see anything to scan.

## Quick Start

Scan everything (containers, images, daemon):

```bash
docksec scan
```

Scan only running containers:

```bash
docksec scan --targets containers
```

Scan a Dockerfile:

```bash
docksec scan --file ./Dockerfile
```

Scan a compose file:

```bash
docksec scan --file ./docker-compose.yml
```

Output as JSON:

```bash
docksec scan --output json
```

Output as SARIF (for GitHub Security tab integration):

```bash
docksec scan --output sarif --output-file results.sarif
```

Only show HIGH and CRITICAL findings:

```bash
docksec scan --severity high,critical
```

Exit with code 1 if any CRITICAL findings exist (useful for CI):

```bash
docksec scan --fail-on critical
```

## What Gets Checked

The scanner looks for common security misconfigurations organized by CIS Docker Benchmark sections:

**Container Runtime (Section 5)**
- Privileged containers
- Dangerous Linux capabilities (SYS_ADMIN, SYS_PTRACE, etc.)
- Docker socket mounted inside container
- Sensitive host paths mounted (/etc, /var, /proc, etc.)
- Missing AppArmor or seccomp profiles
- Host namespace sharing (network, PID, IPC, UTS)
- Missing resource limits (memory, CPU, PIDs)
- Writable root filesystem

**Docker Daemon (Section 2)**
- Insecure registries configured
- Inter-container communication enabled
- User namespace remapping disabled
- Live restore disabled
- Experimental features enabled

**Dockerfiles (Section 4)**
- Running as root (no USER instruction)
- Using ADD instead of COPY
- Secrets in environment variables or build args
- Using latest tag
- Missing HEALTHCHECK
- Package manager cache not cleaned

**Compose Files**
- Privileged services
- Dangerous capabilities
- Host network mode
- Sensitive volume mounts
- Missing resource limits

## Output Formats

| Format | Use Case |
|--------|----------|
| terminal | Interactive use, colored output |
| json | Parsing with jq, integration with other tools |
| sarif | GitHub Security tab, VS Code SARIF viewer |
| junit | CI/CD test reporting (Jenkins, GitLab CI) |

## How It Works (High Level)

1. **Connect to Docker** using the official Docker SDK. The scanner uses the same socket that `docker` CLI uses (`/var/run/docker.sock`).

2. **Run analyzers** in parallel. Each analyzer focuses on one target type:
   - ContainerAnalyzer inspects running containers
   - ImageAnalyzer checks image configurations and history
   - DaemonAnalyzer queries daemon settings
   - DockerfileAnalyzer parses Dockerfile instructions
   - ComposeAnalyzer parses docker-compose.yml files

3. **Match against rules**. Each check maps to a CIS control with severity, description, and remediation guidance.

4. **Aggregate findings** and filter by severity if requested.

5. **Generate report** in the chosen format.

## Project Structure

```
cmd/docksec/          CLI entry point, command definitions
internal/
  analyzer/           Security analyzers for each target type
  benchmark/          CIS Docker Benchmark control definitions
  config/             Runtime configuration
  docker/             Docker SDK wrapper
  finding/            Finding types and severity levels
  parser/             Dockerfile and compose file parsers
  proc/               Linux /proc filesystem inspection
  reporter/           Output formatters (JSON, SARIF, JUnit, terminal)
  rules/              Security rules (capabilities, paths, secrets)
  scanner/            Orchestrates analyzers with worker pool
```

## Learning

The `learn/` directory contains documentation explaining how the codebase works. Start with:

- `learn/architecture.md` for the overall design
- `learn/security-concepts.md` for Docker security fundamentals
- `learn/codebase-guide.md` for a tour of the code

## Requirements

- Go 1.21+ (for building)
- Docker (for scanning)
- Linux (for /proc filesystem inspection of container processes)

## License

MIT
