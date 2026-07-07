<!-- ©AngelaMos | 2026 -->
<!-- 03-IMPLEMENTATION.md -->

# Nadezhda: Implementation

This is the code walkthrough. It follows the same left to right order as the pipeline in [02-ARCHITECTURE.md](./02-ARCHITECTURE.md), naming the real functions so you can open each one as you read. Code is referenced by package and function, never by line number, because line numbers rot the moment anyone edits a file.

## Where to start reading

Open `cmd/nadezhda/scrape.go` and find `runScrape`. It is the whole tool in miniature: load config, load sources, open the store, build a fetch client, run the pipeline, print the summary, enrich. The one line that does the real work is:

```go
summary, cstats, err := ingestAndCluster(ctx, fc, st, cfg, targets, now)
```

`ingestAndCluster` lives in `pipeline.go`, and it is the shared seam that `watch` also calls. Everything below is what happens inside it and after it.

## Fetching politely

`internal/fetch` is a worker pool over `net/http`. The interesting behavior is conditional GET. On the first fetch of a source it stores the `ETag` and `Last-Modified` response headers in the `fetch_state` table. On the next fetch it sends them back as `If-None-Match` and `If-Modified-Since`. An unchanged feed answers `304 Not Modified` with no body, which costs almost nothing, and the source's row in the scrape summary shows `304` instead of a parse count.

The retry logic is deliberately conservative. It honors a `Retry-After` header when the server sends one, and it does *not* retry a timeout or a cancelled context, because retrying a timeout usually just means waiting for the same timeout again. Per host rate limiting uses `golang.org/x/time/rate`, so two feeds on the same domain do not hammer it in parallel.

## Parsing and normalizing

`internal/parse` uses `gofeed`, which handles RSS and Atom and most of their real world deviations. One lesson worth internalizing lives in the time parsing: feeds do not agree on date formats. CISA's feed uses RFC822 with a numeric zone, which an earlier version of the research wrongly assumed was RFC1123Z. The parser carries a list of fallback layouts and tries them in order, because a feed that fails to parse its dates silently loses its recency signal.

`internal/normalize` does three small but load bearing things. It canonicalizes URLs, stripping tracking parameters like `utm_*` and `fbclid`, so the same article shared with different tracking tails deduplicates correctly. It strips HTML from summaries with `goquery`. And it computes a SHA-256 content hash and a title hash, which are the exact dedup keys.

## Ingesting, fail soft

`internal/ingest`'s `Run` fans out across sources with an `errgroup`, but with a twist: the per source goroutines always return `nil`. A source's error is recorded in its result struct, not propagated up, so one broken feed never cancels the group and aborts every other source. The command sums the results and reports failures at the end. This is why you can lose The Register to a timeout and still get a full scrape from the other six.

Dedup happens at the database. `store.InsertArticle` is a plain `INSERT`, and when the unique constraint on `canonical_url` or `content_hash` fires, it returns a sentinel:

```go
if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
    return 0, ErrDuplicate
}
```

The caller treats `ErrDuplicate` as a normal "already have this" and increments the duplicate counter. There is no read before write race, because the database is the single source of truth for what exists.

## Clustering with union find

`internal/cluster` implements connected components. `Compute` takes the candidate items, tokenizes each title, and runs a `unionFind` over every pair inside the time window. Two items union when they share a CVE, or when they come from different sources and their title token sets have Jaccard overlap at or above the threshold:

```go
sharedCVE := shareAny(prepared[i].cves, prepared[j].cves)
crossSource := prepared[i].item.SourceID != prepared[j].item.SourceID
titleMatch := crossSource &&
    jaccard(prepared[i].tokens, prepared[j].tokens) >= jaccardThreshold
if sharedCVE || titleMatch {
    uf.union(i, j)
}
```

`buildCluster` then derives the cluster's `FirstSeen` and `LastSeen` from the earliest and latest member times and its `SourceCount` from the distinct sources. `Rebuild` is the entry point the pipeline calls: it pulls candidate articles with `ClusterCandidates`, runs `Compute`, and writes the result with `ReplaceClusters`, which clears and rewrites the cluster tables in a single transaction so the operation is idempotent. Re-running a scrape never produces drifting or duplicated clusters.

Note the timestamp expression in `ClusterCandidates`:

```sql
COALESCE(NULLIF(published_at, 0), fetched_at)
```

An item with no publish time falls back to its fetch time, so a feed that omits dates still clusters within the window instead of collapsing to the epoch.

## The keyless CVE clients

`internal/cve` holds three clients behind a common interface. The keyless CVE core, in the CVE list client, is where the research paid off. It parses the cvelistV5 record, which has a `containers.cna` block from the vendor and zero or more `containers.adp` blocks from authorized data publishers like CISA. It collects every CVSS metric from both, then applies the version precedence: prefer v4.0, then v3.1, then v3.0, then v2.0. This two place search is what correctly reads Log4Shell's 10.0 score out of the CISA-ADP container when the vendor container holds only a placeholder.

The KEV client downloads the catalog once and builds a membership map. It maps the ransomware field explicitly, because the source ships a string:

```go
ransomware := entry.KnownRansomwareCampaignUse == "Known"
```

The EPSS client parses the score and percentile with `ParseFloat`, because the API returns them as quoted strings. Read them as JSON numbers and they decode to zero with no error, which is the quiet kind of bug that survives to production.

## Enriching with a cache

`internal/enrich`'s `Run` asks the store which CVEs need work with `CVEsNeedingEnrichment`, which returns any CVE never enriched, or one whose positive result is older than the cache TTL, or one whose negative result (not found) is older than the shorter negative TTL. The negative cache is what stops the tool from hammering the CVE source every run for a CVE that does not exist yet.

KEV failure is fatal to the enrichment run by design. If the KEV catalog fetch fails, the code refuses to write `is_kev = false` for everything, because a wrong `false` would persist for a full TTL and silently hide exploited vulnerabilities. NVD and EPSS failures are soft and resumable.

## Ranking, purely

`internal/rank`'s `Score` is a pure function of a `Signals` struct and the config weights. `recency` is the exponential half life decay, and `velocity` divides cluster size by age with a floor so a one item cluster scores zero velocity:

```go
func recency(ageHours float64, halfLifeHours int) float64 {
    return math.Exp(-math.Ln2 * ageHours / float64(halfLifeHours))
}
```

`signalsFor` builds the signal struct for a cluster, walking its CVEs to take the maximum CVSS, the maximum EPSS, and whether any is KEV listed. `Rank` scores every cluster and stable sorts descending, breaking ties by the freshest `LastSeen`. Because it is pure, the golden order tests can assert an exact ordering from fixed inputs.

## The store queries that matter

`internal/store` hides all SQL. Two queries are worth knowing by name. `DigestClusters(since)` filters `WHERE last_seen >= ?`, which is publish time based, and it feeds the TUI and the digest. `NewlyFetchedClusters(sinceFetched)` filters `WHERE a.fetched_at >= ?`, which is fetch time based, and it feeds only the watch daemon's alerts. They exist as two separate queries on purpose, for the fetch time versus publish time reason explained in the architecture doc, and a store test asserts the distinction directly so nobody collapses them later.

## The watch daemon

`internal/watch`'s `Run` is the loop:

```go
for {
    select {
    case <-ctx.Done():
        return shutdown(out)
    case <-ticker.C():
        if stop, err := cycleAndNotify(ctx, opts, out); stop {
            return shutdown(out)
        } else if err != nil {
            fmt.Fprintf(out, "watch: cycle error: %v\n", err)
        }
    }
}
```

A cycle error is logged and the loop continues, which is the fail soft contract for a long running daemon. `ctx.Done()` returns `nil`, so Ctrl-C or SIGTERM is a clean exit, not an error. `Once` runs the same `cycleAndNotify` a single time for cron use.

The concrete cycle lives in `cmd/nadezhda/watch.go`. After running `ingestAndCluster` and enrichment, it calls `buildNotable`, which pulls `NewlyFetchedClusters`, ranks them, and keeps the notable ones up to a configured cap. `isNotable` is the policy: a cluster is notable if its score clears the threshold or, when `notify_on_kev` is set, if it contains a KEV listed CVE. `representativeArticle` picks the highest trust outlet's headline to represent the cluster in the alert.

## The AI layer

`internal/ai` defines one `Provider` interface with a `Generate` method. Three providers (qwen, openai, gemini) share one OpenAI compatible client, and Anthropic gets its own client, written against raw `net/http`, because it differs on auth header, system prompt placement, and response shape. Keys are read from the environment only. A model like a local Qwen tends to wrap its JSON in prose, so the result parser extracts JSON by scanning balanced braces and trying each candidate object rather than assuming the whole response is JSON.

## The setup wizard

`internal/setup` is the seamless install story. `nadezhda ai` runs an interactive, re-runnable wizard. It writes keys to a `0600` file with a temp file and atomic rename so it tightens an existing file's permissions instead of trusting them. `Load` runs on every command and sets each key into the environment only if unset, so a shell variable always wins, and it accepts only allowlisted key names so a tampered file cannot inject arbitrary environment variables into the process.

## Common pitfalls

These are the real bugs that were caught and fixed, and the ones you are most likely to reintroduce.

- **Parsing EPSS or KEV fields with the wrong type.** EPSS scores are strings; the ransomware flag is a string. Both decode wrong silently.
- **Reading CVSS from only the vendor container.** You will report "no score" for exactly the most important CVEs.
- **Using publish time for alerts.** A backfilled advisory fetched today has an old publish time. Alert on fetch time.
- **Writing `is_kev = false` when the KEV fetch failed.** A wrong negative persists for a full TTL. Fail the run instead.
- **Letting one broken feed abort the scrape.** Fan out fail soft, record the error per source.

## Debugging tips

- Run `nadezhda scrape` twice. The second run should show every source as `304` or all duplicates, proving idempotency. If it shows new articles both times, dedup is broken.
- Point `nadezhda cve CVE-2021-44228` at a known CVE after a scrape that mentions it. You should see CVSS 10.0, a KEV listing, and a high EPSS. If the score is missing, your container search is the suspect.
- For the daemon, run `nadezhda watch --once` against a scratch database and read the one line cycle report. It prints new, duplicate, cluster, enriched, KEV, and notable counts, which tells you which stage is misbehaving.
