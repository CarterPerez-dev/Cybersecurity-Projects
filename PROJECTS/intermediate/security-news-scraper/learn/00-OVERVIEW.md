<!-- ©AngelaMos | 2026 -->
<!-- 00-OVERVIEW.md -->

# Nadezhda: Overview

## What This Is

A security news and CVE intelligence engine written in Go. You point it at a set of RSS feeds, and it fetches them politely, clusters the same story as it appears across different outlets, extracts every CVE mentioned, enriches each one with authoritative exploit intelligence, ranks the whole set by real world significance, and hands you a browsable dossier in your terminal. It ships as a single static binary with a local SQLite store, and it needs no API key to do any of this.

The point of the project is to understand, by building it, how you turn a firehose of security headlines into a ranked signal. You get a working aggregator you can run against real feeds, a keyless enrichment pipeline seeded from the same authoritative sources a SOC would use, and a codebase small enough to read in an afternoon.

## Why This Matters

There is more security news published every day than any person can read, and almost all of it is noise relative to the one story that matters to you right now. The hard problem is not gathering headlines. It is deciding which three of the four hundred you should act on before lunch.

The signal is usually some combination of the same factors. A vulnerability that many outlets picked up in the same few hours is trending for a reason. A CVE that CISA just added to its Known Exploited Vulnerabilities catalog is being used against real targets today. A flaw with a high EPSS score is one the rest of the world is about to start exploiting. Nadezhda exists to compute that combination for you and sort by it.

The cost of missing the signal is not hypothetical.

- **Log4Shell, December 2021.** CVE-2021-44228, a remote code execution flaw in Apache Log4j 2, went from a GitHub issue to every security outlet on earth within hours. Its CVSS base score is a perfect 10.0, it landed on the CISA KEV catalog almost immediately, and its EPSS score sat near the top of the scale. A tool that ranks by cross outlet velocity plus KEV plus EPSS would have floated it to the top of the list on the first scrape, which is exactly the behavior this project is built to produce.
- **The Equifax breach, 2017.** Attackers walked in through a known Apache Struts vulnerability, CVE-2017-5638, that had a patch available for months. The information needed to prioritize that patch existed in public feeds the whole time. The failure was one of triage, not of intelligence.
- **MOVEit, 2023.** The Cl0p group mass exploited CVE-2023-34362 in the MOVEit Transfer product and hit hundreds of organizations. The advisories, the KEV listing, and the outlet coverage all arrived in a tight window. Velocity was the tell.

**Real world scenarios where this applies:**
- **Threat intelligence triage.** An analyst runs one scrape each morning and reads the top of a ranked dossier instead of forty browser tabs.
- **Content and research.** A writer or educator finds the cluster every outlet is covering, sees the CVEs and the exploit signals behind it, and turns it into a post or a lesson.
- **Personal situational awareness.** An engineer keeps a watchlist of the vendors and products they run, and gets alerted when a KEV listed flaw in one of them starts trending.

## What You'll Learn

This project teaches how a real aggregation and prioritization pipeline is built. By building it yourself, you will understand:

**Security concepts:**
- **The CVE intelligence stack.** How CVSS, CWE, the CVE Program record, the CISA KEV catalog, and FIRST EPSS each answer a different question about a vulnerability, and how to combine them without an API key.
- **Why KEV and EPSS beat CVSS alone.** A CVSS 9.8 that nobody is exploiting is less urgent than a CVSS 6.5 that is on the KEV catalog. The project encodes that judgment in its ranking.
- **Cross source clustering as a signal.** Why the same story appearing across many outlets quickly is itself the most useful thing you can measure, and how to measure it.
- **Polite automated retrieval.** Conditional requests, per host rate limiting, and where robots.txt does and does not apply.

**Technical skills:**
- **Concurrent, fail soft ingestion.** Fetching many feeds in parallel where one broken feed never aborts the run.
- **Deterministic ranking.** Building a scoring model whose output is a fixed function of its inputs, so the same corpus always sorts the same way and can be tested against golden order.
- **A single static binary with an embedded database.** Using pure Go SQLite so there is no CGO, no external database, and no runtime dependency.
- **A decoupled daemon.** Designing a scheduler that knows nothing about the work it runs, so it can be unit tested with a fake clock.

**Tools and techniques:**
- **`gofeed`** for RSS and Atom parsing, and **`goquery`** for the HTML fallback path.
- **`modernc.org/sqlite`**, a cgo free SQLite, in WAL mode so a reader and a writer coexist.
- **`bubbletea`** and **`lipgloss`** for the terminal UI.
- **Ollama** for a local, keyless language model, with OpenAI, Gemini, and Anthropic available as opt in alternatives.

## Prerequisites

You do not need prior threat intelligence experience. You do need some comfort with the following.

**Required knowledge:**
- **Go basics.** Structs, interfaces, goroutines, and errors. If you can read a `for` loop over a channel you can read this code.
- **SQL at a beginner level.** The store is plain SQLite with a handful of tables and hand written queries.
- **What a CVE is.** That CVE-2021-44228 names one vulnerability, that CVSS scores its severity, and that a patch usually exists. The rest is explained in [01-CONCEPTS.md](./01-CONCEPTS.md).

**Tools you'll need:**
- **A Go toolchain**, 1.25 or newer. The `install.sh` script installs one for you if it is missing.
- **Nothing else to run the core.** No API keys, no database server, no Docker. The default enrichment sources are all keyless.

**Helpful but not required:**
- **Docker**, only if you want the optional local language model, which runs as an Ollama container.
- A skim of the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and the [FIRST EPSS](https://www.first.org/epss/) documentation.

## Quick Start

```bash
# Install (grabs a prebuilt binary, no Go needed):
curl -fsSL https://angelamos.com/nadezhda/install.sh | bash
# or, with a Go toolchain:
go install github.com/CarterPerez-dev/nadezhda/cmd/nadezhda@latest

# Pull the latest news, cluster it, and enrich every CVE:
nadezhda scrape

# Browse the ranked dossier:
nadezhda tui

# Render a Markdown digest of the top stories:
nadezhda digest --top 20
```

Expected output: `scrape` prints a per source table (parsed, new, duplicate, CVE counts), then a line like `132 clusters (14 multi-source, largest 5)`, then an enrichment summary like `enriched 80/80 CVEs (14 KEV, 0 not found)`. `tui` opens a colored, scrollable list where each story shows its rank, its outlets, and its worst CVE, and pressing a key opens the full dossier for the selected cluster.

## Project Structure

```
security-news-scraper/
├── cmd/nadezhda/          # the CLI: one file per command, plus the shared pipeline seam
├── internal/
│   ├── fetch/             # concurrent, rate-limited, conditional HTTP
│   ├── parse/             # RSS/Atom via gofeed, HTML fallback via goquery
│   ├── normalize/         # canonical URLs, content hashing, time parsing
│   ├── ingest/            # the fan-out orchestrator (fail soft per source)
│   ├── cluster/           # union-find clustering by title and shared CVE
│   ├── cve/               # keyless CVE clients: CVE list, KEV, EPSS (+ optional NVD)
│   ├── enrich/            # enrichment orchestration and the TTL cache
│   ├── rank/              # the deterministic weighted scoring model
│   ├── store/             # SQLite: connection, migrations, typed queries
│   ├── ai/                # the opt-in ideation layer (four providers)
│   ├── setup/             # the in-binary credential wizard
│   ├── watch/             # the daemon scheduler (pure, injected pipeline)
│   ├── tui/               # the bubbletea browser
│   └── export/            # Markdown and JSON digest renderers
├── testdata/              # captured feed and API fixtures (drive offline tests)
├── install.sh             # the one-shot installer
└── justfile
```

The single most important thing to understand first is the pipeline in `cmd/nadezhda/pipeline.go` and `scrape.go`. Everything in `internal` exists to feed one function, `ingestAndCluster`, and everything downstream exists to rank and present what it produced.

## Next Steps

1. **Understand the ideas.** Read [01-CONCEPTS.md](./01-CONCEPTS.md) for the CVE intelligence stack, clustering as a signal, and the ranking model, each grounded in a real incident.
2. **See the design.** Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) for the package layout, the keyless enrichment decision, and the data flow from feed to dossier.
3. **Walk the code.** Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) to trace one CVE from a feed item to a ranked, enriched cluster.
4. **Extend it.** Read [04-CHALLENGES.md](./04-CHALLENGES.md) for projects from "add a source" to "replace the clustering with SimHash".

## Common Issues

**`scrape` shows a source with an error**
```
  theregister: fetch theregister: context deadline exceeded
```
Solution: one slow or broken feed never aborts a run. The other sources still ingest, the failed one is reported at the bottom, and the next scrape retries it. A persistent failure usually means the feed URL moved. Check `nadezhda sources`.

**`tui` says there is nothing to show**
```
no clusters yet. run: nadezhda scrape
```
Solution: the TUI reads what is already in the store. Run `nadezhda scrape` once first. Scrape enriches automatically, so there is no separate step.

**`ideate` says AI is not configured**
Solution: the AI layer is opt in and off by default. Run `nadezhda ai` to set up a provider (paste one key, or point it at a local Ollama). The aggregator is fully useful with AI disabled.

## Related Projects

If you found this interesting, look at:
- **sbom-generator-vulnerability-matcher**: the other half of the CVE story, matching the vulnerabilities in this feed against the dependencies you actually ship.
- **ja3-ja4-tls-fingerprinting**: the same shape of tool, a keyless intelligence engine over an embedded SQLite store, applied to network fingerprints instead of news.
