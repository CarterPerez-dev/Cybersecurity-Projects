# 02 - Architecture

## High level flow

```
 Google log_list.json                                    watchlist.yml
 (which CT logs exist,                                    (brands to
  which are "usable")                                      protect)
        |                                                       |
        v                                                       v
 +---------------+     leaf_input,      +--------------+   +-----------+
 |   ctlog.py    | --  extra_data  -->  |  detect.py   |<--|watchlist.py|
 | get-sth       |     (base64 TLS      | skeletonize  |   +-----------+
 | get-entries   |      structures)     | levenshtein  |
 | leaf parsing  |                      | score_domain |
 +---------------+                      +--------------+
        ^                                       |
        | HTTPS                                 v Finding(domain, brand,
        |                                          score, severity, reasons)
   CT log servers                                        |
   (Google, Cloudflare,                                  v
    DigiCert, ...)                              +----------------+
                                                 |   store.py     |
                                                 | SQLite, dedup  |
                                                 | on (domain,    |
                                                 |  brand)        |
                                                 +----------------+
                                                          |
                                       +------------------+------------------+
                                       v                                     v
                                 cli.py prints                        server.py
                                 new findings to                      read-only
                                 stderr as they                       dashboard
                                 happen                                (localhost)
```

Two entry points into `detect.py`: `cli.py stream` (live, from a CT log) and `cli.py scan-file` (offline, from a plain text file of domains). Both end up calling `score_against_watchlist()` the same way, which is deliberate: the detection engine does not know or care where a domain came from, and that seam is what makes it possible to unit test scoring without ever touching the network (see `tests/test_detect.py`).

## Why RFC 6962 directly, not a client library

There are existing Python CT client libraries. Two things pushed toward hand-rolling it instead:

1. **The protocol is small enough that hiding it behind a library loses more than it gains for a learning project.** `get-sth` and `get-entries` are two GET requests. The only real complexity is decoding `MerkleTreeLeaf`, and that decoding is maybe 40 lines once you have the RFC 6962 §3.4 structure diagram in front of you (reproduced in `03-IMPLEMENTATION.md`). Wrapping that in a dependency would trade "understand exactly what a CT log gives you" for "trust a black box," which is the wrong trade for the advanced tier of this repo.
2. **Log discovery matters and is easy to get wrong.** CT logs rotate: a log accepting submissions for 2026 will not accept submissions for 2027, and old logs eventually get marked `retired` or `readonly`. Hardcoding a log URL means the project silently breaks in a year. `ctlog.fetch_usable_logs()` reads Google's canonical, actively maintained `log_list.json` and filters to logs whose `state` includes `usable`, so the tool keeps working as logs rotate without a code change.

## Data flow: one certificate's journey

1. `stream` calls `get_sth()`, learns the log's current `tree_size`.
2. It calls `get_entries(start, end)` for a range of new leaf indexes.
3. Each entry has `leaf_input` (the `MerkleTreeLeaf`, always present) and `extra_data` (chain certificates; for precerts, the actual pre-certificate).
4. `parse_merkle_leaf()` decodes the leaf. For an `x509_entry`, the certificate DER is right there. For a `precert_entry`, the leaf only has the TBS bytes and an issuer key hash, not something `cryptography` can load; `parse_precert_extra_data()` pulls the real pre-certificate out of `extra_data` instead.
5. `load_certificate()` + `extract_dns_names()` turn DER bytes into a sorted list of lowercase domain strings from the SAN.
6. Each domain goes through `score_against_watchlist()`, one `Brand` at a time.
7. Any non-`None` `Finding` gets written to SQLite via `FindingsStore.record()`, which upserts on `(domain, brand)` so the same domain reappearing across renewals or multiple CAs bumps a counter instead of spamming duplicate alerts.
8. New (first-time) findings print immediately to stderr; the dashboard (`server.py`) reads the same SQLite file on demand, so `stream` and `serve` can run as two separate processes against one findings database.

## Design decisions and tradeoffs

**SQLite over Postgres.** This is a single-operator tool watching a personal or small-team watchlist. A file that `sqlite3 findings.db` can open without a server running is the right amount of infrastructure for that job. If this needed to scale to many concurrent watchers or a shared team dashboard, Postgres would be the obvious next step, exactly the kind of change `04-CHALLENGES.md` flags as an extension rather than something baked in from day one.

**`http.server` over FastAPI/Flask for the dashboard.** The dashboard is read-only, local, and has exactly two routes. A web framework earns its keep once there is real routing complexity, request validation, or an API surface other services depend on; none of that is true here yet.

**Detection engine has zero I/O.** `detect.py` never touches the network, the filesystem, or SQLite. Every function takes plain strings and dataclasses in, returns a `Finding` or `None` out. That is why `tests/test_detect.py` can hit dozens of known-answer cases in milliseconds with no mocking.

**Confusables table is generated, not hand-typed.** A hand-curated list of "the dozen most common lookalike characters" would miss coverage and would be a maintenance burden. `scripts/build_confusables.py` downloads Unicode's actual security data and filters it programmatically, so the table is both more complete and trivially regenerable when Unicode ships a new version (see `03-IMPLEMENTATION.md` for what that filtering does and does not include).

**One log at a time by default.** Watching every usable log simultaneously means running one process per log; `stream` intentionally keeps a single-log model simple rather than building a multi-log scheduler nobody asked for yet. See the "Honest positioning" section of the project README for what this tradeoff means in practice.

## Security and performance considerations

- Every certificate parsed comes from an untrusted source (anyone can request a certificate for a domain they control, including a domain built specifically to attack this tool). `leaf_to_domains()` catches all parsing exceptions and returns `[]` rather than propagating them, so one malformed or adversarial leaf cannot crash a long-running `stream` process.
- The dashboard escapes every attacker-influenced string before rendering it as HTML (`server.py`, see the module docstring there), since certificate domain names are exactly the kind of input that might contain `<script>` if someone tries it.
- `get-entries` responses can be large (a batch of a few hundred certificates easily runs a few MB of base64 JSON). `--batch-size` defaults to 256 entries per request as a balance between request count and memory use; raising it trades more memory per request for fewer round trips.
