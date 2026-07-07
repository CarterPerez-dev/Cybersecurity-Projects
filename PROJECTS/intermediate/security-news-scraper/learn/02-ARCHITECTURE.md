<!-- ©AngelaMos | 2026 -->
<!-- 02-ARCHITECTURE.md -->

# Nadezhda: Architecture

This document is the map. It shows the pipeline end to end, the package that owns each stage, the data model underneath, and the design decisions that shaped all of it. Read [01-CONCEPTS.md](./01-CONCEPTS.md) first for the *why* of each stage; this file is the *how it fits together*.

## The pipeline

Everything flows one direction, from a list of feeds to a ranked set of surfaces.

```
             sources.yaml (embedded default, or a user file)
                    │
                    ▼
   ┌───────────────────────────────────┐
   │ fetch   N workers, per-host rate   │   internal/fetch
   │         limit, conditional GET     │
   │         (ETag / Last-Modified)     │
   └───────────────┬───────────────────┘
                   │ raw bytes + fetch_state
                   ▼
   ┌───────────────────────────────────┐
   │ parse   RSS / Atom (gofeed)        │   internal/parse
   │         HTML fallback (goquery)    │
   └───────────────┬───────────────────┘
                   │ raw items
                   ▼
   ┌───────────────────────────────────┐
   │ normalize  canonical URL, strip    │   internal/normalize
   │            HTML, content hash      │
   └───────────────┬───────────────────┘
                   │
                   ▼
   ┌───────────────────────────────────┐
   │ ingest   fan-out, dedup, store     │   internal/ingest
   └───────┬───────────────────┬───────┘
           │                   │
   CVE extract (regex)   cluster (union-find)   internal/cluster
           │                   │
           ▼                   ▼
   ┌───────────────────────────────────┐
   │ enrich   CVE list / KEV / EPSS     │   internal/enrich + internal/cve
   │          cached, keyless           │
   └───────────────┬───────────────────┘
                   │
                   ▼
   ┌───────────────────────────────────┐
   │ rank   deterministic weighted      │   internal/rank
   │        score, news first           │
   └───────────────┬───────────────────┘
                   │ ordered clusters
      ┌────────────┼────────────┬────────────┐
      ▼            ▼            ▼            ▼
   digest        tui          ai          watch
  (export)    (browse)    (ideation)    (daemon)
```

A single Go module owns all of it. There is no service boundary, no message queue, and no external database. The `scrape` command runs the whole left to right flow once; the `watch` daemon runs it on a timer.

## Packages and responsibilities

Each `internal` package has one job and a small exported surface.

| Package | Responsibility |
|---|---|
| `config` | Load and validate configuration and the source list. Every tunable lives here. |
| `source` | The source registry and the per source extractor selection. |
| `fetch` | Concurrent HTTP: worker pool, per host rate limit, conditional GET, retry with backoff. |
| `parse` | RSS and Atom via gofeed, an HTML fallback via goquery. |
| `normalize` | Canonical URL, HTML stripping, content and title hashing, time parsing. |
| `ingest` | The fan out orchestrator. Fail soft per source, dedup on insert. |
| `cluster` | Union find clustering by title similarity and shared CVE. |
| `cve` | The keyless CVE clients: CVE list, KEV, EPSS, and the optional NVD. |
| `enrich` | Enrichment orchestration and the TTL cache. |
| `rank` | The pure, deterministic scoring model. |
| `store` | SQLite: connection, migrations, and every typed query. |
| `ai` | The opt in ideation layer: a shared OpenAI compatible client plus a bespoke Anthropic client. |
| `setup` | The in binary credential wizard. |
| `watch` | The daemon scheduler, decoupled from the work it runs. |
| `tui` | The bubbletea terminal browser. |
| `export` | Markdown and JSON digest renderers. |

Orchestration does not live inside any leaf package. It lives in `cmd/nadezhda`, and the shared core of it is one function, `ingestAndCluster` in `pipeline.go`, which both `scrape` and `watch` call. That is the seam that keeps the two commands from drifting: when a step is added to the pipeline, both paths get it because there is only one place to add it.

## Design decisions

### A single static binary

The store is `modernc.org/sqlite`, a SQLite implementation written in pure Go. There is no CGO, so cross compilation is trivial and the release binaries for four platforms fall out of one build. There is no database server to run, no connection string to configure, and no container required for the core tool. The database is a file. This is the same tradeoff the ja3-ja4 project makes for its intelligence store, and it is the right one for a tool a person runs on their own machine.

### Keyless enrichment, folded into scrape

Early versions used the NVD API as the CVE source and split enrichment into its own command, because NVD without a key is rate limited to five requests per thirty seconds and you do not want that throttle on the news path. The keyless pivot removed the reason for both choices. The CVE Program's cvelistV5 records are keyless and unthrottled, so enrichment is fast, and because it is fast it folds directly into `scrape`. The default flow is now one command, `scrape`, then `tui`.

Enrichment inside `scrape` runs best effort under a five minute timeout, and its errors are non fatal. If the CVE list endpoint is down, the news still ingests, clusters, and ranks; you simply get less CVE detail that run. The news path never blocks or fails on enrichment, because the news is the product.

### The daemon knows nothing about the work

The `watch` package is a pure scheduler. It defines two interfaces, a `Ticker` and a `Notifier`, and it takes the pipeline as an injected function:

```go
type Options struct {
    Interval   time.Duration
    RunAtStart bool
    Cycle      func(context.Context) (Report, error)
    Notifier   Notifier
    NewTicker  func(time.Duration) Ticker
    Out        io.Writer
}
```

`internal/watch` imports nothing from `store`, `ingest`, or `enrich`. The command in `cmd/nadezhda/watch.go` builds the concrete `Cycle` closure that runs the real pipeline, and hands it to the scheduler. The payoff is testability: the scheduler is unit tested with a fake ticker whose channel a test drives by hand and a fake cycle that just counts, so the loop, the graceful shutdown, and the fail soft behavior are all verified with no clock, no network, and no database. This is the same discipline as splitting an engine from its I/O so the engine can be tested in isolation.

### Fetch time, not publish time, for alerts

The watch daemon posts a webhook when genuinely new, high signal stories appear. Defining "new" is where a subtle bug lives. A cluster's timestamps are derived from article *publish* time. But an advisory published last week and fetched for the first time today is new *to you*, even though its publish time is old. Filtering alerts by publish time would silently drop it.

So the daemon has a dedicated store query, `NewlyFetchedClusters`, that filters on `articles.fetched_at`, which is monotonic with each scrape cycle. A duplicate article never updates `fetched_at` (inserts are insert only, and an unchanged feed returns a 304 that touches nothing), so a story alerts exactly once, when it is first ingested. This is the kind of correctness detail that only shows up when you think carefully about what your watermark actually measures.

## The data model

```
sources(id, name, title, url, type, weight, tags, enabled)
fetch_state(source_id, etag, last_modified, last_fetched, last_status)
articles(id, source_id,
         canonical_url  UNIQUE,      -- exact dedup
         content_hash   UNIQUE,      -- exact dedup
         title, summary, body, author, published_at, fetched_at)
cves(id TEXT PRIMARY KEY,
     description,
     cvss_score, cvss_version, cvss_severity, cvss_vector,   -- score nullable
     cwe, is_kev, kev_date_added, kev_ransomware,
     epss, epss_percentile, nvd_published, nvd_modified,
     enriched_at, enrich_status)
article_cves(article_id, cve_id)                             -- many to many
clusters(id, cluster_key, first_seen, last_seen, size)
cluster_members(cluster_id, article_id)
ai_notes(id, cluster_id, provider, ...  UNIQUE(cluster_id, provider))
schema_migrations(version, applied_at)
```

Two design points matter here. First, deduplication is enforced by the database, not by application logic. An article is unique on both its canonical URL and its content hash, so re-ingesting the same item is a constraint violation the code catches and treats as a normal "already have it" outcome, not an error. Second, migrations are versioned and forward only, applied automatically when the store opens. A schema version mismatch on an existing database is a loud error, never a silent wipe. The store opens in WAL mode with a busy timeout, so the TUI or a dashboard can read while a scrape writes.

## A story from feed to dossier

Trace one item end to end.

1. `fetch` requests BleepingComputer's feed with the ETag it saved last time. The server returns 200 with new content (a 304 would end the story here, cheaply).
2. `parse` turns the RSS into items. `normalize` canonicalizes each URL, strips tracking parameters, and computes a content hash.
3. `ingest` inserts the new article. A CVE regex finds `CVE-2025-5777` in the title and links it. The insert of a second outlet's article about the same flaw succeeds as its own row.
4. `cluster` rebuilds. The two articles share `CVE-2025-5777`, so they join one cluster. Its size is 2, and its `last_seen` advances.
5. `enrich` sees `CVE-2025-5777` needs data, fetches its cvelistV5 record, reads the CVSS 4.0 score of 9.3 from the vendor container, checks the KEV catalog (listed, ransomware "Known"), and fetches its EPSS score. All of it caches with a TTL.
6. `rank` scores the cluster. Two outlets plus a fresh publish time plus a KEV listing plus a high CVSS put it near the top.
7. `tui` renders it: a colored row with a rank, two outlet dots, a CRITICAL severity marker, and a KEV chip. Pressing enter opens the dossier with both source links and the full CVE card.

## Performance and security considerations

- **Politeness is enforced, not optional.** Every fetch is rate limited per host, uses conditional GET so an unchanged feed costs one cheap 304, and carries an honest User-Agent. A retry honors `Retry-After` and never retries a timeout or a cancellation.
- **Credentials are handled carefully.** The AI wizard writes keys to `~/.config/nadezhda/credentials` with `0600` permissions, using a temp file and atomic rename so an existing file's permissions are tightened rather than left as they were. A shell exported key always wins over the file, and the file loader only accepts key names on an allowlist, which blocks a tampered credentials file from injecting something like `LD_PRELOAD` into the process environment.
- **The AI clients do not follow redirects.** A redirect could leak an `x-api-key` header to an unintended host, so the clients refuse to follow them.
- **Subprocess environments are sanitized.** The "open in browser" action in the TUI launches a child process with a scrubbed environment, not the full one, so a secret in the parent process is not handed to the browser launcher.
- **Failure is soft where it should be and loud where it must be.** One broken feed does not abort a scrape. A failing enrichment does not block the news. But a corrupt database or a failed migration stops the program, because continuing past those would silently corrupt your results.
