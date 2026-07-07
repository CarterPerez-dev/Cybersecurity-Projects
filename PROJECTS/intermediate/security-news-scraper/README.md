# nadezhda

Security news and CVE intelligence, aggregated in your terminal. Keyless by default.

Nadezhda pulls cybersecurity news from reliable RSS/Atom feeds, clusters the same
story across outlets, enriches every referenced CVE with authoritative exploit
intelligence, ranks what actually matters, and hands you a browsable dossier. It
ships as a single static binary with a local SQLite store, a colorful terminal UI,
Markdown/JSON export, an optional AI ideation layer, and an optional watch daemon.

No API key is required to run it. CVE enrichment comes from keyless authoritative
sources (the CVE Program list, CISA KEV, and FIRST EPSS); an NVD key is an optional
booster, never a requirement.

## Install

```
curl -fsSL https://angelamos.com/nadezhda/install.sh | bash
```

One command, zero further steps: it grabs a prebuilt binary for your platform (no Go
toolchain needed), drops it on your `PATH`, and leaves `nadezhda` runnable by name.

Prefer the Go toolchain? A real `go install` works too:

```
go install github.com/CarterPerez-dev/nadezhda/cmd/nadezhda@latest
```

Or build from a clone:

```
git clone https://github.com/CarterPerez-dev/nadezhda
cd nadezhda
just build        # -> ./nadezhda   (or: go build -o nadezhda ./cmd/nadezhda)
```

Requires Go 1.25+ only when building from source; the toolchain is fetched
automatically if you are on an older Go.

## Quick start

```
nadezhda scrape              # pull every enabled feed, cluster, enrich CVEs
nadezhda tui                 # browse the ranked dossier (press ? for keys, o to open a story)
nadezhda digest --top 20     # render a ranked digest to Markdown (or --format json)
nadezhda list --kev          # list stored articles, filtered
nadezhda cve CVE-2021-44228  # show one enriched CVE and the stories that mention it
```

The default flow is `scrape` then `tui`. Scrape already runs enrichment (best effort,
never blocking the news), so there is nothing else to wire up.

## Content ideation (optional AI)

Turn ranked clusters into summaries and content angles. Run the built-in setup wizard
once and paste a single key, or point it at a local Ollama:

```
nadezhda ai                  # interactive, re-runnable: Claude / OpenAI / Gemini / Ollama
nadezhda ideate --top 5      # generate angles for the top clusters
```

The default provider is a local Qwen model via Ollama (keyless). Keys, when used, are
read from your environment and a `0600` credentials file; they are never logged. With
AI disabled, nadezhda is a complete aggregator.

## Watch daemon (optional)

Run nadezhda as a long-lived daemon that re-ingests on an interval and, when a webhook
is configured, posts genuinely new high-signal stories to Slack, Discord, or any JSON
endpoint:

```
nadezhda watch --interval 1h
nadezhda watch --once        # a single cycle, for cron
```

Configure `watch.webhook_url` (and thresholds) in `config.yaml`. The daemon shuts down
cleanly on Ctrl-C / SIGTERM and never crashes on a transient feed or network error.

## How it works

```
feeds -> fetch (rate-limited, conditional GET) -> parse -> normalize -> dedup
      -> cluster (cross-outlet + shared-CVE) -> enrich (CVE list / KEV / EPSS)
      -> rank (news-first weighted score) -> tui | digest | ideate | watch
```

Ranking is pure and deterministic: recency, cross-outlet velocity, source trust, and a
keyword watchlist dominate, with CVSS / KEV / EPSS as supporting signals. Everything is
configurable in `config.yaml`; nothing is a magic constant in the code.

## Configuration

Nadezhda runs with sensible defaults and an embedded source list. To customize, pass
`--config config.yaml`. Notable keys: `watchlist`, `fetch.*`, `cluster.*`, `rank.*`,
`ai.*`, and `watch.*`. The Ollama host port defaults to a non-standard `39847`
(override with `OLLAMA_HOST_PORT`) so it never collides with an existing Ollama.

## Development

```
just build      # build the binary
just test       # go test ./...
just watch      # run the daemon from source
just ollama-up  # stand up the local Qwen runtime (Docker)
```

## License

AGPL-3.0. See [LICENSE](LICENSE).
