<!-- ©AngelaMos | 2026 -->
<!-- README.md -->

```json
 █████╗ ███████╗███╗   ██╗███████╗██████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝████╗  ██║██╔════╝██╔══██╗██╔══██╗██║██╔════╝
███████║█████╗  ██╔██╗ ██║█████╗  ██████╔╝██████╔╝██║███████╗
██╔══██║██╔══╝  ██║╚██╗██║██╔══╝  ██╔══██╗██╔══██╗██║╚════██║
██║  ██║███████╗██║ ╚████║███████╗██████╔╝██║  ██║██║███████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2343-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/haskell-reverse-proxy)
[![Haskell](https://img.shields.io/badge/Haskell-GHC%209.10.3-5D4F85?style=flat&logo=haskell&logoColor=white)](https://www.haskell.org)
[![Inference](https://img.shields.io/badge/inference-pure%20Haskell-4B7BEC?style=flat)](#the-bot-detector)
[![Model](https://img.shields.io/badge/model-LightGBM%20v4%20text-6D4AFF?style=flat)](https://lightgbm.readthedocs.io)
[![Deps](https://img.shields.io/badge/FFI-none-8B5CF6?style=flat)](#what-it-refuses-to-do)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

> Ᾰenebris is a security-first reverse proxy written in pure Haskell. It terminates TLS 1.2 and 1.3 with SNI, load balances across a health-checked backend pool, tunnels WebSockets and server-sent events without buffering them, and then does the part most proxies hand to a vendor: it scores every request against a gradient-boosted bot model it evaluates itself, in-process, with no FFI, no Python sidecar, no API call and no model server. The ensemble is a LightGBM text-format file you drop on disk. The tree walk, the sigmoid, the probability calibration and the Isolation Forest escalation gate are all Haskell. A request's verdict is a value of type `Decision`, and the type checker will not let a code path forget to handle one.

## Why a proxy, and why Haskell

Every reverse proxy is a parser sitting in front of something valuable, which is exactly the shape of software that keeps producing critical CVEs. HTTP/2 Rapid Reset (CVE-2023-44487) turned a protocol feature into a DDoS primitive against the entire edge of the internet in October 2023. Request smuggling keeps resurfacing because two parsers disagree about where a message ends. These are not exotic failures. They are what happens when a hot path written in C has to be both fast and exactly right about untrusted bytes.

Haskell is an unusual answer and a defensible one. The request path is built from total functions over immutable data, concurrency is STM rather than hand-rolled locking, and the places where state genuinely has to be mutable are small and named. More to the point, the bot-detection verdict is a sum type. There is no "unknown" branch that silently falls through to allow, because an incomplete case match is a compile error. The 28-feature vector is a struct-of-arrays laid out once and never reallocated per request.

The second reason is the bot detector itself. Commodity bot management is a subscription and an opaque score. Aenebris reads a model you trained, tells you which features moved the number, and refuses to pretend it knows things it does not.

## The request path

```
client -> TLS 1.3 / SNI -> early-data gate -> conn limit -> IP jail
       -> geo / ASN -> rate limit -> WAF -> JA4H -> Web Bot Auth
       -> feature extract -> GBDT -> calibrate -> IForest gate
       -> Decision -> route | challenge | block | honeypot
```

Everything left of `Decision` is cheap and ordered cheapest-first: a connection that trips the conn limiter never reaches the WAF, and a crawler with a valid RFC 9421 signature never reaches the model at all. The expensive stage runs last and on the smallest remaining slice of traffic.

## Quick Start

```bash
curl -fsSL https://angelamos.com/aenebris/install.sh | bash
```

One command, zero further steps: it installs GHC 9.10.3 and Stack through ghcup if they are missing, builds the proxy, drops `aenebris` on your `PATH`, generates self-signed certs for a local test, and leaves you a working config.

```sh
aenebris examples/config.yaml
```

A minimal config is a listener, an upstream and a route:

```yaml
version: 1

listen:
  - port: 38443
    tls:
      cert: ./certs/default.crt
      key: ./certs/default.key

upstreams:
  - name: web
    servers:
      - host: "127.0.0.1:41080"
        weight: 1
    health_check:
      path: /health
      interval: 10s

routes:
  - host: "example.com"
    paths:
      - path: /
        upstream: web
        rate_limit: 100/minute
```

Host ports are deliberately high and arbitrary. Nothing in this project assumes 80, 443 or 8080 is free.

## What it does

**Proxying and transport**
- TLS 1.2 and 1.3 with SNI-selected credentials, strong cipher suites only, built on `crypton-x509`
- Virtual-host and path routing to named upstreams
- Weighted round-robin load balancing over an STM backend pool, with active health checks that eject and readmit servers on their own interval
- WebSocket and HTTP Upgrade handled as a raw socket tunnel, zero-copy via `splice`, so the proxy never buffers a stream it cannot bound
- Server-sent events and chunked responses detected and relayed without accumulation
- HTTP/2 with tuned connection and stream windows, and the `RST_STREAM` flood ceiling that Rapid Reset made mandatory
- Keep-alive upstream connection pool with per-backend response timeouts

**Defense**
- Token-bucket rate limiting, per route and per path class
- A DDoS suite in four independent layers: TLS early-data rejection with a 425, a memory shed that drops new work before the heap does it for you, an IP jail with decay, and a hard concurrent-connection limit
- A from-scratch WAF: a rule ADT, an OWASP-shaped pattern set, and an engine that evaluates them in a declared order with per-rule block accounting
- JA4H request fingerprinting, used as a lookup key into per-fingerprint statistics rather than fed to the model as raw bytes
- GeoIP and ASN concentration over a rolling window, so a sudden single-ASN burst is visible as one signal rather than ten thousand IPs
- A honeypot upstream that suspicious traffic can be routed to instead of refused, which costs the attacker time and tells you more

**The bot detector**
- 28 stateless request features in a struct-of-arrays `FeatureVector`: header order canonicalization, path and query shape, body characteristics, method and version, UA structure, and the derived per-fingerprint rates
- A pure-Haskell parser for the LightGBM v4 text format, correct down to the `decision_type` byte, categorical split bitmaps, negative child-index leaf encoding and the sigmoid parameter that lives inside the `objective=` line
- A tree walk that mirrors LightGBM's C++ `NumericalDecision` exactly, including default-left and missing-type handling, validated against the reference implementation on a frozen fixture
- Probability calibration as a first-class choice: Platt scaling for small calibration sets, isotonic regression by pool-adjacent-violators once you have enough samples
- An Isolation Forest (Liu et al. 2008) used as an escalation gate, not a weighted blend. Traffic in the ambiguous band gets a second opinion; anomalous escalates to block, otherwise it gets challenged
- RFC 9421 HTTP Message Signatures and Web Bot Auth, Ed25519 primary and ECDSA P-256 secondary, so signed crawlers are whitelisted before any scoring happens
- A `Decision` of `Human`, `Bot` or `Challenge`, with operator-overridable responses and an optional `X-Aenebris-ML-Decision` header for debugging

**Operations**
- Non-blocking JSON access logging through `fast-logger`, structured events through `katip`
- A Prometheus endpoint exposing request histograms, GC pause and heap series, plus `aenebris_backend_healthy`, `aenebris_rate_limit_hits`, `aenebris_waf_blocks`, `aenebris_ja4h_total` and the ML score buckets
- OpenTelemetry spans per connection: handshake, WAF, inference, backend dial, upstream roundtrip
- Hot reload on config and rule files via `hinotify`, validated before the swap, draining in-flight streams rather than cutting them
- An admin API bound to a Unix domain socket and authenticated by `SO_PEERCRED`: drain a backend, read stats, reload, health
- ACME certificate issuance and renewal that is ARI-aware per RFC 9773, HTTP-01 and DNS-01, with hot credential swap and an advisory lock so replicas do not race

## What it refuses to do

These are deliberate, and they are why the rest of the output is worth trusting.

- **It will not fingerprint HTTP/2 in the Akamai format.** Warp does not surface the frame-level settings that format depends on. This is a documented architectural gap, not a backlog item.
- **It will not blend the Isolation Forest score into the GBDT score.** The 0.8/0.2 weighting everyone repeats is folk wisdom with no published basis. The forest is a gate on the ambiguous band or it is nothing.
- **It will not report a model it cannot fully parse.** A multi-class ensemble, an unknown decision type or a malformed tree is a `ParseError` at load, refused loudly at startup, never silently degraded into a classifier that always says human.
- **It will not stand up a cleartext listener you did not ask for.** HTTPS redirect is a middleware you enable, not a port it opens.
- **It does not speak HTTP/3.** QUIC is out of scope here and this README will not imply otherwise.
- **It does not staple OCSP.** The responder ecosystem is dead; browser-side CRLite is the live mechanism.

## Performance

Measured on an Intel Core i7-14700KF, 8 cores allocated to the RTS, nonmoving concurrent GC enabled, upstream on loopback. Reproduce with `just bench`.

| Measurement | Result |
|---|---|
| Proxied throughput, `wrk -c 1000 -t 8 -d 60s` | 118k req/s |
| p99 latency at that load | 3.8 ms |
| Tunnel throughput, loopback WebSocket | 2.4 GB/s |
| Feature extraction, 28 features | 1.9 us |
| GBDT inference, 200 trees | 168 us |
| Isolation Forest score, 100 trees | 41 us |
| Worst-case GC pause under load | 150 ms |

The inference number is the honest cost of keeping the model evaluation in-process and in pure Haskell. It is paid only by traffic that reaches the last stage, which is why the pipeline is ordered the way it is.

## Commands

```sh
just setup         # deps, test certs, first build
just run           # start on the default config
just https         # TLS listener
just sni           # multi-cert SNI
just lb            # weighted load balancing across backends
just ws-sse        # WebSocket + SSE demo with live backends
just backends      # the test upstreams
just test          # the full HSpec suite
just bench         # the throughput and hot-path numbers
just ci            # build + test
```

`just` with no argument lists every recipe grouped by area.

## Learn

The `learn/` folder is the long version.

| Doc | What it covers |
|-----|----------------|
| [`learn/00-OVERVIEW.md`](learn/00-OVERVIEW.md) | What a reverse proxy is, what this one adds, and a ten-minute demo |
| [`learn/01-CONCEPTS.md`](learn/01-CONCEPTS.md) | TLS termination, JA4+, WAF paranoia levels, HTTP/2 Rapid Reset, and the real incidents behind each |
| [`learn/02-ARCHITECTURE.md`](learn/02-ARCHITECTURE.md) | The module graph, the request path, the WAF pipeline and the hot-reload path, with diagrams |
| [`learn/03-IMPLEMENTATION.md`](learn/03-IMPLEMENTATION.md) | A walkthrough of Proxy, Tunnel, LoadBalancer, WAF and the ML stack |
| [`learn/04-CHALLENGES.md`](learn/04-CHALLENGES.md) | Extensions: HTTP/3, io_uring, eBPF/XDP, post-quantum TLS |

## Project Structure

```
haskell-reverse-proxy/
├── aenebris.cabal            # library / exe / test stanzas
├── stack.yaml                # GHC 9.10.3, Stackage LTS
├── install.sh                # one-shot curl|bash to `aenebris` on PATH
├── app/Main.hs               # load config, validate, start
├── src/Aenebris/
│   ├── Proxy.hs              # the request path
│   ├── Tunnel.hs             # raw-socket upgrade tunnel, splice zero-copy
│   ├── Config.hs             # YAML schema, parse + validate
│   ├── Backend.hs            # STM backend pool
│   ├── LoadBalancer.hs       # weighted round-robin selection
│   ├── HealthCheck.hs        # active probes, eject and readmit
│   ├── TLS.hs                # TLS 1.2/1.3, SNI credentials
│   ├── Connection.hs         # timeouts and connection accounting
│   ├── Acme.hs               # ARI-aware issuance and renewal
│   ├── Middleware/           # security headers, HTTPS redirect
│   ├── RateLimit.hs          # token bucket
│   ├── DDoS/                 # EarlyData, MemoryShed, IPJail, ConnLimit
│   ├── Fingerprint/JA4H.hs   # request fingerprint
│   ├── WAF/                  # Rule, Patterns, Engine
│   ├── Honeypot.hs           # divert instead of refuse
│   ├── Geo.hs                # GeoIP + rolling ASN concentration
│   ├── Net/IP.hs             # address handling
│   ├── Observe/              # fast-logger, katip, Prometheus, OTEL
│   ├── Admin.hs              # Unix-socket admin API, SO_PEERCRED
│   └── ML/
│       ├── Features.hs       # 28 features, struct-of-arrays
│       ├── Model.hs          # LightGBM-shaped ADT
│       ├── Loader.hs         # v4 text-format parser
│       ├── Inference.hs      # tree walk + sigmoid
│       ├── Calibration.hs    # Platt + isotonic
│       ├── IForest.hs        # Liu 2008 anomaly scorer
│       ├── WebBotAuth.hs     # RFC 9421 signed-bot whitelist
│       ├── Engine.hs         # the decision pipeline
│       └── Middleware.hs     # the WAI integration
├── test/Spec.hs              # 721 examples, 0 failures
├── examples/                 # configs, test backends, cert generation
└── learn/                    # the teaching track
```

## Requirements

Linux, GHC 9.10.3 and Stack. The installer handles all of it. A GeoIP database is optional and only needed for the geo and ASN signals. A trained model is optional: with no model configured, the ML middleware is simply not in the chain, and every other defense works unchanged.

## License

[AGPL 3.0](LICENSE).
