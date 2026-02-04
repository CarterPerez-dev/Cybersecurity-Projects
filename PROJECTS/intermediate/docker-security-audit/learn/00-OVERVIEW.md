# Codebase Guide

A walkthrough of the code structure and what each package does. Start here if you want to understand how the pieces fit together.

## Directory Layout

```
cmd/docksec/          Entry point and CLI commands
internal/
  analyzer/           Security checks for different target types
  benchmark/          CIS Docker Benchmark control definitions
  config/             Runtime configuration and constants# Docker Security Audit Tool (docksec)
```

## What This Is

A Go-based CLI tool that scans Docker environments for security misconfigurations and validates them against the CIS Docker Benchmark. It analyzes running containers, daemon settings, images, Dockerfiles, and docker-compose files to identify vulnerabilities like privileged containers, dangerous capabilities, Docker socket mounts, and hardcoded secrets.

## Why This Matters

Docker containers don't provide security by default. A single misconfiguration can give an attacker complete control over your host system. This tool catches those mistakes before they become breaches.

**Real world scenarios where this applies:**

- **Container escape via Docker socket mount**: In 2018, Tesla's Kubernetes cluster was compromised when attackers found a pod with `/var/run/docker.sock` mounted, letting them escape to the host and mine cryptocurrency.

- **Privilege escalation through capabilities**: The 2014 "Shocker" exploit used `CAP_DAC_READ_SEARCH` to read arbitrary files from the host filesystem, bypassing container isolation completely.

- **Secret exposure in images**: In 2019, over 100,000 Docker images on Docker Hub contained embedded API keys, passwords, and private keys discoverable through simple text searches.

## What You'll Learn

This project teaches you how container security actually works under the hood. By building and extending it, you'll understand:

**Security Concepts:**
- **CIS Docker Benchmark compliance** - industry standard security controls covering host config, daemon settings, images, and runtime. You'll learn which of the 100+ controls matter most and why.
- **Linux capabilities model** - how the 41 discrete privileges work, which ones enable container escape (like `CAP_SYS_ADMIN` and `CAP_SYS_PTRACE`), and how to audit them programmatically.
- **Namespace isolation boundaries** - what PID, network, IPC, and mount namespaces protect against, and how sharing host namespaces breaks that protection.
- **Security profiles (seccomp, AppArmor, SELinux)** - how syscall filtering and mandatory access control actually prevent attacks, not just theoretical defense-in-depth concepts.
- **Secret detection techniques** - pattern matching with regex, entropy analysis using Shannon entropy, and why both are needed to catch different types of leaked credentials.

**Technical Skills:**
- **Docker API interaction** - using the official Docker client library to introspect containers, images, and daemon configuration without shell commands.
- **Static analysis of build files** - parsing Dockerfiles with AST (abstract syntax tree) to detect security issues at build time, before images ever run.
- **Concurrent scanning** - using Go's errgroup and rate limiters to scan hundreds of containers efficiently without overwhelming the daemon.
- **Security reporting formats** - generating SARIF (Static Analysis Results Interchange Format) for GitHub Security, JUnit for CI/CD, and structured JSON for automation.

**Tools and Techniques:**
- **moby/buildkit parser** - the same parser Docker uses to understand Dockerfile syntax, giving you access to instruction metadata and line numbers for precise findings.
- **CIS Benchmark mapping** - translating security controls into automated checks, including determining which findings are "scored" vs "not scored" in compliance reporting.
- **YAML node traversal** - navigating docker-compose files as structured data rather than text, handling both mapping and sequence formats for the same logical configuration.

## Prerequisites

Before starting, you should understand:

**Required knowledge:**
- **Go basics** - structs, interfaces, goroutines, channels. You'll be reading and modifying Go code that uses errgroups for concurrency and rate limiters for API throttling.
- **Docker fundamentals** - images vs containers, how volumes work, what ports do. You need to know the difference between `docker run --privileged` and `--cap-add=NET_ADMIN`.
- **Linux security model** - what root can do, basic permission concepts, why running as UID 0 is dangerous. Understanding `/proc` and `/sys` helps but isn't required.
- **Command line proficiency** - comfortable with `docker inspect`, reading JSON output, understanding exit codes and stderr vs stdout.

**Tools you'll need:**
- **Go 1.23+** - the project uses generics and newer error handling patterns
- **Docker Engine** - running locally or accessible via `DOCKER_HOST`. Docker Desktop on Mac/Windows works fine.
- **Make** (optional) - for running build and test commands conveniently
- **Git** - to clone the repository and track your changes

**Helpful but not required:**
- Experience with security scanning tools like Trivy, Snyk, or Anchore
- Familiarity with the CIS Benchmark PDFs (the tool teaches you the controls)
- Knowledge of Go testing and benchmarking

## Quick Start

Get the project running locally:

```bash
# Clone and navigate
cd PROJECTS/intermediate/docker-security-audit

# Build the binary
go build -o docksec ./cmd/docksec

# Scan all running containers
./docksec scan

# Scan specific targets
./docksec scan --target containers
./docksec scan --target daemon
./docksec scan --target images

# Scan a Dockerfile
./docksec scan --file Dockerfile

# Scan a docker-compose file
./docksec scan --file docker-compose.yml

# Generate JSON output for automation
./docksec scan --output json --output-file results.json

# Generate SARIF for GitHub Security
./docksec scan --output sarif --output-file results.sarif

# Filter by severity
./docksec scan --severity high,critical

# Fail CI builds on findings
./docksec scan --fail-on medium
```

Expected output: Terminal report grouped by category (Container Runtime, Docker Daemon, etc.) showing findings with severity levels, CIS control IDs, descriptions, and remediation steps. Zero findings if your Docker environment is properly secured.

## Project Structure

```
docker-security-audit/
├── cmd/
│   └── docksec/
│       └── main.go              # CLI entry point, Cobra commands
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go          # Analyzer interface
│   │   ├── container.go         # Running container checks
│   │   ├── daemon.go            # Docker daemon config checks
│   │   ├── image.go             # Image metadata checks
│   │   ├── dockerfile.go        # Dockerfile static analysis
│   │   └── compose.go           # docker-compose.yml checks
│   ├── benchmark/
│   │   └── controls.go          # CIS Docker Benchmark control registry
│   ├── config/
│   │   ├── config.go            # Configuration struct and filters
│   │   └── constants.go         # Rate limits, timeouts, thresholds
│   ├── docker/
│   │   └── client.go            # Docker API client wrapper
│   ├── finding/
│   │   └── finding.go           # Finding data model and collection
│   ├── proc/
│   │   ├── capabilities.go      # Linux capabilities parsing
│   │   ├── proc.go              # /proc filesystem reading
│   │   └── security.go          # Security profile inspection
│   ├── report/
│   │   ├── reporter.go          # Reporter interface and factory
│   │   ├── terminal.go          # Human-readable output
│   │   ├── json.go              # Structured JSON output
│   │   ├── sarif.go             # SARIF 2.1.0 format
│   │   └── junit.go             # JUnit XML for CI/CD
│   ├── rules/
│   │   ├── capabilities.go      # 41 Linux capabilities with risk levels
│   │   ├── paths.go             # 200+ sensitive host paths
│   │   └── secrets.go           # 80+ secret patterns and entropy
│   └── scanner/
│       └── scanner.go           # Main scan orchestration
├── Dockerfile                   # Multi-stage build for container deployment
├── go.mod                       # Dependencies
└── go.sum
```

## Next Steps

1. **Understand the concepts** - Read [01-CONCEPTS.md](./01-CONCEPTS.md) to learn how Linux capabilities, namespaces, and security profiles actually work at the kernel level.

2. **Study the architecture** - Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) to see how the scanner orchestrates concurrent analyzers, applies rules, and generates findings.

3. **Walk through the code** - Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for detailed implementation walkthroughs with actual code from the project.

4. **Extend the project** - Read [04-CHALLENGES.md](./04-CHALLENGES.md) for specific ideas to add features like runtime monitoring, Kubernetes integration, and custom policies.

## Common Issues

**Docker daemon not accessible**
```
Error: docker daemon not accessible: Cannot connect to the Docker daemon
```
Solution: Check that Docker is running (`docker ps` works), your user is in the `docker` group, or set `DOCKER_HOST` if using remote Docker.

**No findings on known vulnerable containers**
Solution: Check your `--severity` and `--target` flags. The default scans all targets at all severities. Use `--verbose` to see which analyzers run.

**Build fails with "module not found"**
Solution: Run `go mod download` to fetch dependencies. Make sure you're using Go 1.23 or later (`go version`).

**SARIF file not showing in GitHub Security**
Solution: Upload it in a GitHub Actions workflow using `github/codeql-action/upload-sarif@v2`. SARIF files don't auto-upload, they need explicit CI integration.

## Related Projects

If you found this interesting, check out:

- **Trivy** - comprehensive vulnerability scanner that includes configuration scanning. This project focuses specifically on runtime and build-time Docker security.
- **Falco** - runtime security monitoring using eBPF. Complements this tool by detecting threats during execution.
- **Docker Bench Security** - official Docker security checker. This project improves on it with structured output, CI/CD integration, and programmatic access.
  docker/             Docker SDK wrapper
  finding/            The Finding type and severity levels
  parser/             Dockerfile and compose file parsers
  proc/               Linux /proc filesystem inspection
  report/             Output formatters (terminal, JSON, SARIF, JUnit)
  rules/              Security rule data (capabilities, paths, secrets)
  scanner/            Orchestration layer that ties everything together
```

## cmd/docksec

The CLI is built with Cobra. Each command is a separate file.

`main.go` defines version variables that get overwritten at build time:

```go
var (
    version   = "dev"
    commit    = "none"
    buildDate = "unknown"
)
```

When you run `go build -ldflags "-X main.version=1.0.0"`, the compiler replaces the string literal before creating the binary.

`scan.go` is where the actual work starts. It creates a Config from flags, instantiates a Scanner, and calls Run:

```go
cfg := &config.Config{
    Targets:  targets,
    Files:    files,
    Output:   outputFormat,
    // ...
}
scanner, _ := scanner.New(cfg)
scanner.Run(ctx)
```

## internal/scanner

This is the orchestration layer. It creates analyzers based on config, runs them concurrently, collects findings, filters them, and sends to a reporter.

The concurrency model uses `errgroup` with a semaphore:

```go
g, ctx := errgroup.WithContext(ctx)
g.SetLimit(s.cfg.Workers)  // Max concurrent goroutines

for _, a := range analyzers {
    a := a
    g.Go(func() error {
        s.limiter.Wait(ctx)  // Rate limit Docker API calls
        findings, _ := a.Analyze(ctx)
        results <- findings
        return nil
    })
}
```

The rate limiter prevents overwhelming the Docker daemon. Even if you set 50 workers, they spread their API calls over time.

## internal/analyzer

Each analyzer implements this interface:

```go
type Analyzer interface {
    Name() string
    Analyze(ctx context.Context) (finding.Collection, error)
}
```

There are five implementations:

| File | Target | What it checks |
|------|--------|----------------|
| container.go | Running containers | Privileged mode, capabilities, mounts, namespaces, security profiles, resource limits |
| image.go | Local images | User instruction, secrets in history, base image tags |
| daemon.go | Docker daemon | Insecure registries, ICC, user namespaces, experimental features |
| dockerfile.go | Dockerfile files | USER instruction, ADD vs COPY, secrets in ENV/ARG, HEALTHCHECK |
| compose.go | Compose files | Same as container checks, but for service definitions |

Container analyzer is the most complex. It lists all containers, inspects each one, and runs checks:

```go
func (a *ContainerAnalyzer) Analyze(ctx context.Context) (finding.Collection, error) {
    containers, _ := a.client.ListContainers(ctx, true)

    var findings finding.Collection
    for _, c := range containers {
        info, _ := a.client.InspectContainer(ctx, c.ID)
        findings = append(findings, a.analyzeContainer(info)...)
    }
    return findings, nil
}

func (a *ContainerAnalyzer) analyzeContainer(info types.ContainerJSON) finding.Collection {
    // Each method checks one thing
    findings = append(findings, a.checkPrivileged(target, info)...)
    findings = append(findings, a.checkCapabilities(target, info)...)
    findings = append(findings, a.checkMounts(target, info)...)
    // ...
}
```

Each check looks up the relevant CIS control for metadata:

```go
func (a *ContainerAnalyzer) checkPrivileged(...) finding.Collection {
    if info.HostConfig.Privileged {
        control, _ := benchmark.Get("5.4")
        f := finding.New("CIS-5.4", control.Title, finding.SeverityCritical, target).
            WithDescription(control.Description).
            WithRemediation(control.Remediation)
        return finding.Collection{f}
    }
    return nil
}
```

## internal/benchmark

Contains all CIS Docker Benchmark v1.6.0 controls as Go structs. They register themselves during init:

```go
func init() {
    registerHostControls()
    registerDaemonControls()
    registerContainerRuntimeControls()
    // ...
}

func registerContainerRuntimeControls() {
    Register(Control{
        ID:          "5.4",
        Section:     "Container Runtime",
        Title:       "Ensure that privileged containers are not used",
        Severity:    finding.SeverityCritical,
        Description: "Privileged containers have all Linux kernel capabilities...",
        Remediation: "Do not run containers with --privileged flag...",
        Scored:      true,
        Level:       1,
    })
}
```

The global registry allows lookup by ID:

```go
control, ok := benchmark.Get("5.4")
```

This keeps rule metadata in one place. If CIS updates the benchmark, you change the registry, not every analyzer.

## internal/finding

The Finding struct carries everything about a discovered issue:

```go
type Finding struct {
    ID          string       // Hash for deduplication
    RuleID      string       // CIS control ID
    Title       string       // Short description
    Description string       // Full explanation
    Severity    Severity     // INFO, LOW, MEDIUM, HIGH, CRITICAL
    Category    string       // Container Runtime, Dockerfile, etc.
    Target      Target       // What was scanned
    Location    *Location    // For files: path and line number
    Remediation string       // How to fix it
    References  []string     // Documentation links
    CISControl  *CISControl  // Original benchmark control
    Timestamp   time.Time    // When discovered
}
```

Findings are created with a builder pattern:

```go
f := finding.New("CIS-5.4", "Privileged container", finding.SeverityCritical, target).
    WithDescription("...").
    WithRemediation("...").
    WithReferences("https://...")
```

The ID is generated from a hash of rule, target, and location. This makes findings stable across scans:

```go
func (f *Finding) generateID() string {
    data := fmt.Sprintf("%s|%s|%s|%s", f.RuleID, f.Target.Type, f.Target.Name, f.Target.ID)
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:8])
}
```

Same issue on same target produces same ID. Useful for tracking remediation over time.

## internal/rules

Contains security rule data organized by category:

### capabilities.go

Maps all 40+ Linux capabilities to severity and descriptions:

```go
var Capabilities = map[string]CapabilityInfo{
    "CAP_SYS_ADMIN": {
        Severity:    finding.SeverityCritical,
        Description: "Effectively root - mount filesystems, quotas, namespaces...",
    },
    "CAP_NET_RAW": {
        Severity:    finding.SeverityMedium,
        Description: "Craft arbitrary packets, ARP/DNS spoofing, packet sniffing.",
    },
    // ...
}
```

Pre computed lookup maps make checks fast:

```go
var dangerousCapabilities = func() map[string]struct{} {
    m := make(map[string]struct{})
    for cap, info := range Capabilities {
        if info.Severity >= finding.SeverityHigh {
            m[cap] = struct{}{}
        }
    }
    return m
}()

func IsDangerousCapability(cap string) bool {
    _, exists := dangerousCapabilities[strings.ToUpper(cap)]
    return exists
}
```

### paths.go

Catalogs 200+ sensitive host paths with severity and descriptions:

```go
var SensitiveHostPaths = map[string]PathInfo{
    "/etc/shadow": {
        Severity:    finding.SeverityCritical,
        Description: "Password hashes. Direct credential access.",
    },
    "/var/run/docker.sock": {
        Severity:    finding.SeverityCritical,
        Description: "Docker daemon socket. Full control over Docker, container escape possible.",
    },
    // ...
}
```

Path matching handles prefixes:

```go
func IsSensitivePath(path string) bool {
    if _, exists := sensitivePathLookup[path]; exists {
        return true
    }
    // Check if path is under a sensitive directory
    for sensitivePath := range sensitivePathLookup {
        if strings.HasPrefix(path, sensitivePath+"/") {
            return true
        }
    }
    return false
}
```

So `/etc/shadow` matches, but so does `/etc/foo` (because `/etc` is sensitive).

### secrets.go

Pattern matching for secrets in Dockerfiles:

```go
var SecretPatterns = []SecretPattern{
    {
        Type:        SecretTypeAWSKey,
        Pattern:     regexp.MustCompile(`(?i)(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`),
        Description: "AWS Access Key ID",
    },
    {
        Type:        SecretTypeGitHub,
        Pattern:     regexp.MustCompile(`(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}`),
        Description: "GitHub Personal Access Token",
    },
    // 100+ more patterns
}
```

Also includes entropy calculation for detecting random strings that might be secrets:

```go
func CalculateEntropy(s string) float64 {
    freq := make(map[rune]float64)
    for _, c := range s {
        freq[c]++
    }
    var entropy float64
    for _, count := range freq {
        p := count / float64(len(s))
        entropy -= p * math.Log2(p)
    }
    return entropy
}
```

High entropy strings (random characters) are likely secrets. Low entropy strings (repeated patterns) are not.

## internal/parser

### dockerfile.go

Parses Dockerfiles into an AST using BuildKit's parser:

```go
func ParseDockerfile(path string) (*DockerfileAST, error) {
    file, _ := os.Open(path)
    result, _ := parser.Parse(file)

    ast := &DockerfileAST{
        Path: path,
        Root: result.AST,
    }
    ast.extractStructure()  // Build Commands and Stages slices
    return ast, nil
}
```

The AST provides helpers for common queries:

```go
ast.HasInstruction("USER")           // Does it set a user?
ast.GetInstructions("ENV")           // All ENV instructions
ast.GetLastInstruction("USER")       // Last USER instruction
ast.FinalStage()                     // For multi-stage builds
```

### compose.go

Parses docker-compose.yml files using the YAML library:

```go
type ComposeFile struct {
    Path     string
    Services map[string]*Service
    Volumes  map[string]*Volume
    Networks map[string]*Network
}

type Service struct {
    Name        string
    Image       string
    Privileged  bool
    CapAdd      []string
    CapDrop     []string
    Volumes     []VolumeMount
    Ports       []PortMapping
    NetworkMode string
    // ...
}
```

Parsing handles both long and short syntax for volumes and ports:

```go
# Short syntax
volumes:
  - ./host:/container

# Long syntax
volumes:
  - type: bind
    source: ./host
    target: /container
```

## internal/docker

Wraps the Docker SDK with timeout handling:

```go
type Client struct {
    api *client.Client
}

func (c *Client) InspectContainer(ctx context.Context, containerID string) (types.ContainerJSON, error) {
    // Create derived context with timeout
    inspectCtx, cancel := context.WithTimeout(ctx, config.InspectTimeout)
    defer cancel()

    return c.api.ContainerInspect(inspectCtx, containerID)
}
```

Uses a singleton pattern so the whole program shares one connection:

```go
var (
    instance *Client
    once     sync.Once
)

func NewClient() (*Client, error) {
    once.Do(func() {
        cli, _ := client.NewClientWithOpts(
            client.FromEnv,
            client.WithAPIVersionNegotiation(),
        )
        instance = &Client{api: cli}
    })
    return instance, nil
}
```

## internal/proc

Reads process information from the `/proc` filesystem. This works directly on the host kernel, bypassing Docker's abstractions.

```go
func GetProcessInfo(pid int) (*ProcessInfo, error) {
    procPath := fmt.Sprintf("/proc/%d", pid)

    info := &ProcessInfo{PID: pid}
    info.readStatus(procPath)   // /proc/PID/status
    info.readCmdline(procPath)  // /proc/PID/cmdline
    info.readCgroups(procPath)  // /proc/PID/cgroup
    info.readNamespaces(procPath) // /proc/PID/ns/*
    return info, nil
}
```

Can detect if a process is in a container by checking cgroup paths:

```go
func (p *ProcessInfo) IsInContainer() bool {
    for _, cg := range p.Cgroups {
        if strings.Contains(cg.Path, "docker") ||
           strings.Contains(cg.Path, "containerd") {
            return true
        }
    }
    return false
}
```

This package uses graceful degradation. If a file cannot be read (permissions, not Linux, etc.), it continues with what it can get rather than failing.

## internal/report

Each output format implements the Reporter interface:

```go
type Reporter interface {
    Report(findings finding.Collection) error
}
```

### terminal.go

Colored output for interactive use:

```go
func (r *TerminalReporter) Report(findings finding.Collection) error {
    for _, f := range findings {
        color := f.Severity.Color()  // ANSI escape code
        fmt.Printf("%s[%s]%s %s\n", color, f.Severity, reset, f.Title)
    }
    return nil
}
```

### sarif.go

SARIF (Static Analysis Results Interchange Format) for GitHub Security tab:

```go
type SARIFReport struct {
    Schema  string `json:"$schema"`
    Version string `json:"version"`
    Runs    []Run  `json:"runs"`
}
```

GitHub automatically picks up SARIF files and displays findings in the Security tab.

### junit.go

JUnit XML for CI/CD integration:

```go
type JUnitTestSuites struct {
    XMLName  xml.Name         `xml:"testsuites"`
    Tests    int              `xml:"tests,attr"`
    Failures int              `xml:"failures,attr"`
    Suites   []JUnitTestSuite `xml:"testsuite"`
}
```

Jenkins, GitLab CI, and others understand JUnit format for test reporting.

## Adding a New Check

Say you want to add a check for containers using the `latest` tag.

1. Find the relevant analyzer (`container.go` for running containers)

2. Add a check method:

```go
func (a *ContainerAnalyzer) checkImageTag(target finding.Target, info types.ContainerJSON) finding.Collection {
    if strings.HasSuffix(info.Config.Image, ":latest") || !strings.Contains(info.Config.Image, ":") {
        control, _ := benchmark.Get("5.27")
        f := finding.New("CIS-5.27", control.Title, finding.SeverityLow, target).
            WithDescription(control.Description)
        return finding.Collection{f}
    }
    return nil
}
```

3. Call it from analyzeContainer:

```go
findings = append(findings, a.checkImageTag(target, info)...)
```

The CIS control should already exist in `benchmark/controls.go`. If adding a custom check, register a new control first.

## Adding a New Secret Pattern

In `rules/secrets.go`, add to the SecretPatterns slice:

```go
{
    Type:        SecretTypeAPIKey,
    Pattern:     regexp.MustCompile(`myservice_[A-Za-z0-9]{32}`),
    Description: "MyService API Key",
},
```

The Dockerfile analyzer will automatically pick it up.

## Adding a New Output Format

1. Create a new file in `internal/report/` (e.g., `csv.go`)

2. Implement the Reporter interface:

```go
type CSVReporter struct {
    output io.Writer
}

func (r *CSVReporter) Report(findings finding.Collection) error {
    w := csv.NewWriter(r.output)
    w.Write([]string{"ID", "Severity", "Title", "Target"})
    for _, f := range findings {
        w.Write([]string{f.ID, f.Severity.String(), f.Title, f.Target.String()})
    }
    return w.Flush()
}
```

3. Update `NewReporter` in `reporter.go` to handle the new format:

```go
case "csv":
    return &CSVReporter{output: out}, nil
```

4. Add the format to CLI flag validation in `cmd/docksec/scan.go`

## Testing Strategy

The codebase does not have extensive tests yet. If adding them:

**Unit tests** for rules packages (capabilities, paths, secrets):
```go
func TestIsDangerousCapability(t *testing.T) {
    tests := []struct{cap string; want bool}{
        {"SYS_ADMIN", true},
        {"NET_BIND_SERVICE", false},
    }
    for _, tt := range tests {
        got := rules.IsDangerousCapability(tt.cap)
        if got != tt.want {
            t.Errorf("IsDangerousCapability(%q) = %v, want %v", tt.cap, got, tt.want)
        }
    }
}
```

**Integration tests** for analyzers using Docker SDK mocks or testcontainers.

**E2E tests** by running the binary against known bad configurations.
