<!-- ©AngelaMos | 2026 -->
<!-- 04-CHALLENGES.md -->

# Nadezhda: Challenges

Ways to extend the project, ordered roughly from an afternoon to a serious undertaking. Each one names the code you would touch and gives a hint, not a full solution. The best way to understand a pipeline is to add a stage to it.

## Warm up

**Add a source.** The source list is `sources.yaml`, embedded by default. Add an entry with a name, feed URL, type, and weight, then run `nadezhda sources` to persist it and `nadezhda scrape` to pull it. Pick a feed that overlaps with the existing seven (say, a second general security outlet) and watch it start joining clusters. The source `weight` feeds ranking, so a source you trust more nudges its stories up.

**Retune the ranking.** Every weight lives in `config`, under `rank.weights`. The defaults are news first (recency and velocity dominate). Flip that: crank `cvss`, `kev`, and `epss` up and `recency` down, scrape, and compare the top of `nadezhda digest`. You will see the list reorder toward raw severity. There is no code change here, which is the point: the model is data, not logic.

**Add a keyword watchlist.** Set `watchlist` in config to the vendors and products you actually run. `matchesWatchlist` in `internal/rank` scores a cluster higher when a term appears in its titles or CVEs. Confirm it works by adding a vendor you know is in today's news and watching its stories climb.

**Add an export format.** `internal/export` renders Markdown and JSON. Add a third, for instance a plain text digest or an RSS feed of the ranked clusters, so nadezhda can feed another tool. Keep the renderer a pure function of the scored clusters, the way `export.Markdown` is, so it stays testable.

## Medium

**Add an AI provider.** `internal/ai` has one `Provider` interface. Three providers share the OpenAI compatible client. Add a new OpenAI compatible endpoint (a different local runtime, or a hosted model) by wiring its base URL and model into the config and the factory. The harder version is a provider that is not OpenAI compatible, which is why Anthropic has its own client: you will learn where the response shapes actually differ.

**Turn on the HTML article scrape path.** The fetch client already has `Allowed`, a robots.txt gate, built and tested but intentionally never called, because the feed path does not use it. Wire it into a per source HTML extractor for a source whose feed is summary only, so you can pull the full article body and extract more CVEs. This is the one place robots.txt must be honored, so route the fetch through `Allowed` first. You are building the crawler path the architecture deliberately kept separate.

**Make the webhook smarter.** The watch daemon posts a `text`/`content`/`items` JSON payload that works for Slack, Discord, or a generic endpoint. Add a real Slack Block Kit or Discord embed formatter behind a config switch, so an alert renders as a rich card instead of a text line. The notable set is already capped and ranked, so you are formatting, not filtering.

**Report per source health.** `fetch_state` already stores each source's last status and last fetch time. Add a `nadezhda sources --health` view that flags a source that has returned an error or a 304 for many runs in a row, so a silently dead feed becomes visible.

## Hard

**Replace pairwise clustering with LSH.** `internal/cluster` compares every candidate pair inside the window, which is fine for hundreds of articles and quadratic for tens of thousands. The research deferred SimHash as a scale optimization for exactly this reason. Implement locality sensitive hashing over the title token sets so near duplicates land in the same bucket and you only compare within a bucket. Keep the existing `Compute` as the reference implementation and assert the LSH version produces the same clusters on the test fixtures before you trust it.

**Persist the alert watermark.** The daemon derives "new since last cycle" from the current cycle's wall clock, which is correct except across a backward clock step, where an article could alert twice. Add a small `watch_state` table that records the last notified point, and have `buildNotable` read it instead of the in memory cycle start. This also makes alerts survive a restart cleanly, so a daemon that crashes and comes back does not re-alert the backlog.

**Embed the real version in `go install` builds.** The release binaries carry their version because goreleaser injects it with `ldflags`. A plain `go install` build shows the development default, because `go install` does not inject anything. Read the module version from `runtime/debug.ReadBuildInfo` as a fallback in `internal/version` so a tagged `go install` build reports its tag. This is a small change that teaches you how Go embeds build metadata.

**Add full text search.** SQLite ships FTS5. Add a virtual table over article titles and bodies and a `nadezhda search "term"` command, so a user can search the whole archive by product, whether or not it is currently trending. Mind the migration: it is a new table, applied forward only, the way `internal/store` applies every other schema change.

## Expert

**Build a read only dashboard.** The store opens in WAL mode specifically so a reader can run while a scrape writes. Build a small web UI that reads `DigestClusters` and serves the same ranked dossier the TUI shows, with no write path of its own. The interesting constraint is that it must never migrate or write, so it opens the database read only and fails loudly if the schema is newer than it understands.

**Make clustering incremental.** `Rebuild` recomputes every cluster from scratch each scrape, which is correct and simple and eventually slow. Design an incremental version that only reclusters articles inside the active window and merges them into existing clusters, and prove it converges to the same result as a full rebuild. This is genuinely hard, because cluster identity has to stay stable across runs for the velocity signal to mean anything.

**Learn a relevance model.** The ranking is a fixed weighted sum. Collect which stories a user actually opens in the TUI and train a model that predicts relevance from the same signals plus the user's history. Keep the deterministic model as the cold start and the fallback, and treat the learned score as one more weighted input, so the system degrades gracefully when the model is absent or wrong.

**Ship a diff.** Add a `nadezhda digest --since-last` that shows only what changed since the previous digest: new clusters, clusters that grew, and CVEs that newly landed on KEV. This is the report a person actually wants each morning, and it forces you to think about what "changed" means for a cluster, which is the same watermark problem the watch daemon solves.

## Real world applications

- A morning triage feed for a small security team, replacing a folder of browser bookmarks with one ranked list and a Slack alert for KEV listed spikes.
- A research input for a writer or educator who needs to know what the security world is talking about today, with the CVE evidence attached.
- A personal monitor keyed to a watchlist of the exact products you run, so you hear about a trending flaw in one of them before your vendor's email arrives.

## Connections to other projects

- **sbom-generator-vulnerability-matcher** answers the question this project raises. Nadezhda tells you a CVE is trending and exploited. The SBOM matcher tells you whether that CVE is in something you actually ship. Together they are a prioritization loop.
- **ja3-ja4-tls-fingerprinting** is the same architecture applied to a different signal: a keyless intelligence engine over an embedded SQLite store, with the same discipline of pinning outputs to known answer vectors and keeping the engine testable in isolation. Read its clustering ideas alongside this one.
