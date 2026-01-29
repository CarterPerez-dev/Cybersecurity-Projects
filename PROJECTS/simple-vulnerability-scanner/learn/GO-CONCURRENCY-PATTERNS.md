# Go Concurrency Patterns Used in angela

angela fetches data from PyPI and OSV.dev in parallel. These patterns show up in production codebases at places like Uber and Cloudflare, but they're not complicated — they just require knowing which tool to reach for.

---

## The problem

angela needs to query PyPI for every dependency in your `pyproject.toml` or `requirements.txt`. A typical project has 20-50 dependencies. Doing those requests one at a time would take 10-25 seconds. Doing them all at once would hammer PyPI with 50 simultaneous connections.

The answer is **bounded concurrency** — run up to N requests in parallel, queue the rest.

---

## errgroup.SetLimit

The `golang.org/x/sync/errgroup` package is the go-to for bounded concurrent work in Go. Here's how angela uses it in `internal/pypi/client.go`:

```go
g, ctx := errgroup.WithContext(ctx)
g.SetLimit(c.maxWorkers)  // max 10 concurrent goroutines

for _, name := range names {
    g.Go(func() error {
        versions, err := c.FetchVersions(ctx, name)
        mu.Lock()
        results = append(results, FetchResult{
            Name: name, Versions: versions, Err: err,
        })
        mu.Unlock()
        return nil
    })
}

_ = g.Wait()
```

A few things to notice:

- **`SetLimit(10)`** caps concurrent HTTP requests. PyPI recommends 5-10.
- **Always returns nil** — individual failures get collected in results, not propagated. One package failing shouldn't kill the others.
- **Mutex on the shared slice** — `results` gets appended to from multiple goroutines, so it needs a lock.

### Why not channels?

Channels would work, but errgroup gets you the same thing with half the code:

```go
// Channel-based worker pool: ~30 lines
jobs := make(chan string, len(names))
results := make(chan FetchResult, len(names))
for range maxWorkers {
    go func() {
        for name := range jobs {
            // ... fetch ...
            results <- result
        }
    }()
}
// ... send jobs, collect results, close channels ...

// errgroup: ~15 lines
g.SetLimit(maxWorkers)
for _, name := range names {
    g.Go(func() error { /* ... */ })
}
g.Wait()
```

errgroup handles context cancellation for free and there's no channel lifecycle to think about.

---

## Panic recovery

Every goroutine angela launches wraps itself in a recover:

```go
g.Go(func() (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic fetching %s: %v", name, r)
        }
    }()

    versions, fetchErr := c.FetchVersions(ctx, name)
    // ...
    return nil
})
```

An unrecovered panic in a goroutine kills the entire process. For a CLI tool, that means the user gets a stack trace dump instead of an actual error message. The `defer recover()` turns panics into errors that flow through the normal path.

One subtle thing — the named return `(err error)` is what makes this work. Without it, the deferred function has no way to set the return value.

---

## Context cancellation

Every HTTP request uses context:

```go
req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
```

This does a lot of work for you:

- Ctrl+C cancels pending requests
- If errgroup's context gets cancelled, remaining work stops
- HTTP timeouts are enforced at the transport level

The context flows from `cobra.Command.Context()` → `runUpdate()` → `FetchAllVersions()` → `FetchVersions()` → the HTTP call itself. Standard Go pattern — context as the first parameter, threaded through everything.

---

## Retry with exponential backoff

`internal/pypi/client.go` retries transient failures:

```go
for attempt := range maxRetries {
    if attempt > 0 {
        delay := time.Duration(1<<shift) * baseRetryMs * time.Millisecond
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        case <-time.After(delay):
        }
    }

    resp, err := c.http.Do(req)
    if err != nil {
        lastErr = err
        continue
    }

    if resp.StatusCode >= 500 {
        lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
        continue
    }

    return resp, nil
}
```

The `1<<shift` doubles the delay each attempt — 500ms, 1s, 2s. The `select` means cancellation is still respected while waiting between retries. Only server errors (5xx) get retried; client errors (4xx) don't because retrying a 404 won't make the package appear. Three attempts is enough to ride out a transient blip without making the user wait forever.

---

## Mutex vs channel

angela uses `sync.Mutex` to protect the results slice:

```go
var mu sync.Mutex
results := make([]FetchResult, 0, len(names))

// In each goroutine:
mu.Lock()
results = append(results, result)
mu.Unlock()
```

Quick rule of thumb:

| Use Mutex | Use Channel |
|-----------|-------------|
| Protecting shared state (maps, slices) | Passing data between goroutines |
| Simple append/read operations | Producer-consumer pipelines |
| Order doesn't matter | Sequential processing needed |

For appending results where order doesn't matter, a mutex is simpler and cheaper.

---

## The bigger picture

All of these patterns boil down to the same idea: **know when your goroutine exits**. Every goroutine angela spawns has a clear owner (the errgroup), a clear exit condition (the function returns), and panic protection. That's how you avoid leaks.

`go test -race` catches most of what code review misses. Run it in CI, always.
