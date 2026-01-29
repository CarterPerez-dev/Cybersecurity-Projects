# How the Scanner Works

This document explains the architecture of docksec. Not how to use it, but how it is built and why certain decisions were made.

## The Big Picture

The scanner follows a simple pipeline:

```
Config → Docker Client → Analyzers → Findings → Filter → Reporter
```

1. Parse CLI flags into a Config struct
2. Create a single Docker client connection
3. Build a list of analyzers based on what targets were requested
4. Run all analyzers concurrently with a worker pool
5. Collect findings from all analyzers
6. Filter by severity if requested
7. Format and output via the chosen reporter

## Why a Single Docker Client

The Docker SDK uses HTTP connections over a Unix socket. Creating multiple clients would mean multiple connections, which wastes resources and can hit connection limits.

```go
// internal/docker/client.go
var (
    instance *Client
    once     sync.Once
    initErr  error
)

func NewClient() (*Client, error) {
    once.Do(func() {
        cli, err := client.NewClientWithOpts(
            client.FromEnv,
            client.WithAPIVersionNegotiation(),
        )
        // ...
        instance = &Client{api: cli}
    })
    return instance, initErr
}
```

The `sync.Once` ensures only one client exists for the entire program. Every call to `NewClient()` returns the same instance. This is safe because the Docker SDK client is thread safe.

The `WithAPIVersionNegotiation()` option is important. Docker daemons and clients can have different API versions. Without negotiation, a newer client talking to an older daemon would fail. Negotiation picks the highest version both sides support.

## Concurrency Model

Scanning can be slow. Each container inspection is a round trip to the Docker daemon. With dozens of containers, sequential scanning takes too long.

The scanner uses `golang.org/x/sync/errgroup` for concurrent execution:

```go
// internal/scanner/scanner.go
func (s *Scanner) runAnalyzers(ctx context.Context, analyzers []analyzer.Analyzer) (finding.Collection, error) {
    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(s.cfg.Workers)

    results := make(chan finding.Collection, len(analyzers))

    for _, a := range analyzers {
        a := a  // capture loop variable
        g.Go(func() error {
            if err := s.limiter.Wait(ctx); err != nil {
                return err
            }
            findings, err := a.Analyze(ctx)
            // ...
            results <- findings
            return nil
        })
    }
    // ...
}
```

### Why errgroup instead of raw goroutines

Raw goroutines require manual coordination:
- You need a WaitGroup to know when all goroutines finish
- You need to manually propagate errors
- Context cancellation is your responsibility

errgroup handles all of this:
- `g.Wait()` blocks until all goroutines complete
- If any goroutine returns an error, the context gets cancelled
- `g.SetLimit(n)` caps concurrent goroutines (built in worker pool)

### The loop variable capture

```go
for _, a := range analyzers {
    a := a  // This line is crucial
    g.Go(func() error {
        // use a
    })
}
```

Without `a := a`, all goroutines would share the same loop variable. By the time they execute, the loop has finished and `a` points to the last analyzer. Every goroutine would analyze the same thing.

The `a := a` creates a new variable scoped to each iteration, capturing the correct value.

Note: Go 1.22 fixed this behavior for `for` loops, but this code supports Go 1.21+ so the capture is still needed.

## Rate Limiting

Even with a worker pool, you can overwhelm the Docker daemon with too many concurrent requests. The scanner uses a token bucket rate limiter:

```go
limiter := rate.NewLimiter(
    rate.Limit(config.RateLimitPerSecond),  // 50/sec
    config.RateLimitBurst,                   // burst of 50
)
```

Before each analyzer runs, it must acquire a token:

```go
if err := s.limiter.Wait(ctx); err != nil {
    return err
}
```

The token bucket works like this:
- Bucket holds up to 50 tokens (burst)
- Tokens refill at 50/second
- Each request consumes one token
- If no tokens available, Wait() blocks until one appears

This smooths out bursts. Even if 50 analyzers start simultaneously, they spread their Docker API calls over time.

## The Analyzer Interface

All analyzers implement the same interface:

```go
// internal/analyzer/analyzer.go
type Analyzer interface {
    Name() string
    Analyze(ctx context.Context) (finding.Collection, error)
}
```

This abstraction lets the scanner treat all analyzers uniformly. It does not care if an analyzer inspects containers, parses Dockerfiles, or queries the daemon. They all take a context and return findings.

Adding a new analyzer is straightforward:
1. Implement the interface
2. Add it to `buildAnalyzers()` in the scanner

The scanner never imports specific analyzer types beyond construction. It only works with the interface.

## How Container Analysis Works

The container analyzer demonstrates the typical flow:

```go
// internal/analyzer/container.go
func (a *ContainerAnalyzer) Analyze(ctx context.Context) (finding.Collection, error) {
    containers, err := a.client.ListContainers(ctx, true)
    if err != nil {
        return nil, err
    }

    var findings finding.Collection
    for _, c := range containers {
        info, err := a.client.InspectContainer(ctx, c.ID)
        if err != nil {
            continue  // Skip failed inspections
        }
        findings = append(findings, a.analyzeContainer(info)...)
    }
    return findings, nil
}
```

1. List all containers (including stopped ones)
2. Inspect each container for detailed configuration
3. Run security checks against the inspection data
4. Aggregate all findings

Each check method looks at specific fields:

```go
func (a *ContainerAnalyzer) checkPrivileged(target finding.Target, info types.ContainerJSON) finding.Collection {
    if info.HostConfig.Privileged {
        control, _ := benchmark.Get("5.4")
        f := finding.New("CIS-5.4", control.Title, finding.SeverityCritical, target).
            WithDescription(control.Description).
            WithRemediation(control.Remediation).
            // ...
        return finding.Collection{f}
    }
    return nil
}
```

The check:
1. Examines a specific configuration field
2. If misconfigured, looks up the CIS control for context
3. Creates a finding with all relevant metadata

## The Finding Type

Findings carry everything needed to understand and fix an issue:

```go
// internal/finding/finding.go
type Finding struct {
    ID          string       // Unique hash for deduplication
    RuleID      string       // CIS control ID (e.g., "CIS-5.4")
    Title       string       // Short description
    Description string       // Full explanation
    Severity    Severity     // INFO, LOW, MEDIUM, HIGH, CRITICAL
    Category    string       // Grouping (Container Runtime, Dockerfile, etc.)
    Target      Target       // What was scanned (container:nginx, image:alpine, etc.)
    Location    *Location    // For files: path, line, column
    Remediation string       // How to fix it
    References  []string     // Links to documentation
    CISControl  *CISControl  // Original benchmark control
    Timestamp   time.Time    // When discovered
}
```

The ID is generated from a hash of the rule, target, and location:

```go
func (f *Finding) generateID() string {
    data := fmt.Sprintf("%s|%s|%s|%s", f.RuleID, f.Target.Type, f.Target.Name, f.Target.ID)
    if f.Location != nil {
        data += fmt.Sprintf("|%s:%d", f.Location.Path, f.Location.Line)
    }
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:8])
}
```

This makes findings stable across scans. The same issue produces the same ID, which is useful for tracking remediation over time.

## CIS Control Registry

The CIS Docker Benchmark has around 150 controls organized by section. Rather than hardcode them everywhere, they live in a central registry:

```go
// internal/benchmark/controls.go
var controlRegistry = make(map[string]Control)

func Register(c Control) {
    controlRegistry[c.ID] = c
}

func Get(id string) (Control, bool) {
    c, ok := controlRegistry[id]
    return c, ok
}
```

Controls register themselves during `init()`:

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
        // ...
    })
}
```

When an analyzer finds an issue, it looks up the control:

```go
control, _ := benchmark.Get("5.4")
```

This keeps the rule metadata in one place. If the CIS benchmark updates, you change the registry, not every analyzer.

## Reporter Abstraction

Output formats vary wildly (terminal colors vs JSON vs SARIF XML), but they all do the same thing: take findings and produce output.

```go
// internal/report/reporter.go
type Reporter interface {
    Report(findings finding.Collection) error
}
```

Each format implements this interface:
- `TerminalReporter` uses ANSI colors and tables
- `JSONReporter` marshals to JSON
- `SARIFReporter` produces SARIF for GitHub Security
- `JUnitReporter` produces JUnit XML for CI

The scanner picks a reporter at startup based on `--output`:

```go
reporter, err := report.NewReporter(cfg.Output, cfg.OutputFile)
```

Adding a new format means implementing Reporter and updating the factory function. The rest of the codebase stays unchanged.

## Graceful Degradation

Some data sources are not always available. The `/proc` filesystem only exists on Linux. Some containers might not have all fields populated.

Instead of failing, the scanner degrades gracefully:

```go
// internal/proc/proc.go
func GetProcessInfo(pid int) (*ProcessInfo, error) {
    // Status is required
    if err := info.readStatus(procPath); err != nil {
        return nil, fmt.Errorf("reading status: %w", err)
    }

    // These are optional - errors ignored
    if err := info.readCmdline(procPath); err != nil {
    }
    if err := info.readCgroups(procPath); err != nil {
    }
    // ...
}
```

The pattern: require critical data, ignore failures for optional data. This lets the scanner work in restricted environments (containers, non-Linux, limited permissions) while still providing value.

## Error Handling Philosophy

The codebase follows Go conventions:
- Return errors up the call stack
- Wrap errors with context using `fmt.Errorf("doing X: %w", err)`
- Let callers decide what to do with errors

Analyzer failures do not stop the scan:

```go
findings, err := a.Analyze(ctx)
if err != nil {
    s.logger.Warn("analyzer failed", "name", a.Name(), "error", err)
    return nil  // Return nil error, not the actual error
}
```

One broken analyzer should not prevent others from running. The scan continues, logs the failure, and includes whatever findings succeeded.

## Timeouts

Docker API calls have timeouts to prevent hangs:

```go
// internal/config/constants.go
const (
    DefaultTimeout    = 30 * time.Second
    InspectTimeout    = 10 * time.Second
    ConnectionTimeout = 5 * time.Second
)

// internal/docker/client.go
func (c *Client) InspectContainer(ctx context.Context, containerID string) (types.ContainerJSON, error) {
    inspectCtx, cancel := context.WithTimeout(ctx, config.InspectTimeout)
    defer cancel()

    info, err := c.api.ContainerInspect(inspectCtx, containerID)
    // ...
}
```

Each operation creates a derived context with a specific timeout. If the Docker daemon is slow or stuck, the call times out rather than blocking forever.

The `defer cancel()` is important. Even if the call completes before the timeout, you must call cancel to release the timer resources. Without it, you leak goroutines.
