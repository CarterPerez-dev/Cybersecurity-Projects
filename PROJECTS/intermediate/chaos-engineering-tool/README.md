<!-- ©AngelaMos | 2026 -->
<!-- README.md -->

```json
 ██ ▄█▀ ██░ ██  ▄▄▄       ▒█████    ██████ 
 ██▄█▒ ▓██░ ██▒▒████▄    ▒██▒  ██▒▒██    ▒ 
▓███▄░ ▒██▀▀██░▒██  ▀█▄  ▒██░  ██▒░ ▓██▄   
▓██ █▄ ░▓█ ░██ ░██▄▄▄▄██ ▒██   ██░  ▒   ██▒
▒██▒ █▄░▓█▒░██▓ ▓█   ▓██▒░ ████▓▒░▒██████▒▒
▒ ▒▒ ▓▒ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░
░ ░▒ ▒░ ▒ ░▒░ ░  ▒   ▒▒ ░  ░ ▒ ▒░ ░ ░▒  ░ ░
░ ░░ ░  ░  ░░ ░  ░   ▒   ░ ░ ░ ▒  ░  ░  ░  
░  ░    ░  ░  ░      ░  ░    ░ ░        ░
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Intermediate-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/chaos-engineering-tool)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![Linux](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-333333?style=flat&logo=linux&logoColor=white)](https://github.com/CarterPerez-dev/khaos/releases)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](LICENSE)

> Inject security failures into a Docker stack and measure whether its controls still enforce their decisions. Khaos tests legitimate and invalid credentials before, during, and after each fault, then records what changed and whether recovery succeeded.

Security concepts, architecture, and walkthroughs are in the [learn modules](#learn).

## What It Does

- 90 experiments across network, identity, TLS, DNS, credential, and security-control failures
- A bundled Docker range with correct and deliberately defective gateways, plus an optional PostgreSQL, MySQL, MariaDB, and Redis tier
- Terminal reports, canonical JSON records, JUnit XML, and Prometheus textfile metrics
- Saved run history, YAML experiment files, replay with target identity checks, and an optional health stop
- Consent labels, mutation journals, renewable leases, bounded rollback, and recovery after an interrupted run
- An interactive console with completion, alongside ordinary commands for scripts and CI

| Family | Examples |
|--------|----------|
| `network` | Dependency outages, resets, latency, incomplete responses, and stalled connections |
| `identity` | Revoked tokens, key rotation, unavailable key sets, malformed introspection, and JWT verification defects |
| `tls` | Expired certificates, trust-chain errors, revoked identities, weak keys, and session resumption |
| `dns` | Failed resolution, forged answers, truncated responses, and changes hidden by connection reuse |
| `credential` | Database password rotation, account locking, session termination, missing secrets, and authorization denials |
| `control` | Unavailable rate-limit counters, policy stores, and rule backends |

## Install

```bash
curl -fsSL https://angelamos.com/khaos/install.sh | bash
```

The installer verifies the release checksum, installs `khaos` onto PATH, and sets up Docker Engine and Compose when needed. If a release is unavailable, it builds a static binary from source and downloads a verified Go toolchain when necessary. Run it again to update.

Linux AMD64 and ARM64 are supported. The bundled range requires a local Docker Engine with host access to its bridge network. Use a Linux VM on macOS or Windows. Docker setup may require sudo.

To install only the executable:

```bash
curl -fsSL https://angelamos.com/khaos/install.sh | bash -s -- --no-docker
```

Or use Go 1.26+:

```bash
CGO_ENABLED=0 go install github.com/CarterPerez-dev/khaos/cmd/khaos@latest
```

Go installs into `GOBIN`, or `$(go env GOPATH)/bin` when unset. That directory must be on PATH. `CGO_ENABLED=0` is required because Khaos uses its own executable inside resolver and secret-file helper containers. Range build files are embedded, so a source checkout is unnecessary.

## Quick Start

Start the range with its authentication gateway configured to refuse requests when the identity provider is unavailable:

```bash
khaos range up --fail-mode closed
khaos doctor
khaos plan network.dependency_outage
khaos run network.dependency_outage
```

Now run the same experiment against a gateway that permits requests when that dependency fails:

```bash
khaos range up --fail-mode open
khaos run network.dependency_outage
khaos range down
```

The second run should report `PERMITTED` and exit with code `2`: the gateway accepted an invalid credential during the fault. A closed gateway may also deny legitimate traffic during an outage; that availability deviation has its own exit code.

Run `khaos` without arguments to open the interactive console. Use `khaos catalog` to list experiments and `khaos plan <experiment>` to inspect one before applying it.

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` in a checkout to see its recipes.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Commands

| Command | Purpose |
|---------|---------|
| `khaos doctor` | Check Docker access, consenting targets, and helper-binary compatibility |
| `khaos targets` | List eligible Docker targets |
| `khaos catalog` | List the experiment catalog |
| `khaos plan <experiment>` | Describe an experiment without injecting its fault |
| `khaos run <experiment>` | Measure baseline, fault, and recovery |
| `khaos run-file experiment.yaml` | Run a saved experiment configuration |
| `khaos runs` | List saved runs |
| `khaos show <run-id>` | Read a run and verify its event hashes |
| `khaos replay path/to/run.json` | Repeat a recorded configuration after checking target identity |
| `khaos reclaim` | Retry outstanding recovery obligations |
| `khaos reap` | Watch leases and recover abandoned mutations |
| `khaos range up --with-db` | Start the range with its database tier |
| `khaos range status` | Show range endpoints and status |
| `khaos range down` | Remove the disposable range and its volumes |

Each command has `--help`. The range automatically supplies targets, addresses, and test credentials. For your own stack, add `khaos.target: "true"` to consenting services and provide the parameters shown by the experiment's plan.

## Reports and CI

```bash
khaos run network.dependency_outage \
  --record ./results/outage \
  --output json \
  --junit ./results/outage.xml \
  --metrics-out ./results/outage.prom
```

`run.json` is the canonical result. `events.jsonl` contains the individual observations and is referenced by its SHA-256 hash. Terminal output, JUnit, and metrics derive from that record. Saved configurations use environment-variable references for supplied secrets.

| Exit code | Meaning |
|-----------|---------|
| `0` | Accepted outcome under the selected failure policy |
| `1` | Usage, configuration, or artifact-publication error |
| `2` | Measured security defect |
| `3` | Measured deviation outside the experiment's defect direction |
| `4` | Inconclusive evidence |
| `5` | Probe failure |
| `6` | Rollback failed |
| `7` | Experiment validity checks failed |
| `8` | Baseline requirements were not met |
| `9` | Experiment unsupported for this target |
| `10` | Interrupted |
| `70` | Internal error |

The default preserves nonzero outcomes. `--fail-on` selects which measured outcomes fail a CI job; usage, rollback, and internal errors cannot be suppressed. `--abort-after N` stops after consecutive unhealthy primary probe pairs and reverts the fault while preserving any bypass already measured.

Run history and recovery state live in `${XDG_STATE_HOME:-~/.local/state}/khaos`. Set `KHAOS_STATE_DIR` to override that location. Bundled range sources are cached under `${XDG_CACHE_HOME:-~/.cache}/khaos/range`, with their contents verified before reuse.

## Scope and Recovery

Use Khaos in disposable development, test, and CI environments. Docker access is powerful enough to affect the host; consent checks and recovery controls bound the operations Khaos performs.

Mutations require the exact label `khaos.target=true`. Khaos refuses unsafe target configurations and unresolved recovery obligations. Keep `khaos reap` running when automatic recovery after a killed process is required, and use `khaos reclaim` to inspect and retry abandoned work.

Network-disconnect recovery verifies endpoint settings and addresses. Docker 28 may allocate a new MAC when an endpoint is recreated, which the fault description discloses before injection. A target requiring an unchanged MAC should use another fault mechanism.

## Build and Test

```bash
just build
just check
just race
just gate
```

`just build` produces a static binary. `just check` runs the configured linters, module checks, unit tests, and terminal-color checks. `just gate` also runs the Docker integration suites sequentially; they create and remove the disposable range. Additional ownership and restart tests require `KHAOS_DOCKER_TESTS=1`.

The standalone repository at [CarterPerez-dev/khaos](https://github.com/CarterPerez-dev/khaos) provides Go installation and release binaries. The project also lives in the [Cybersecurity Projects collection](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/chaos-engineering-tool).

## Learn

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Prerequisites, installation, and a first experiment |
| [01 - Concepts](learn/01-CONCEPTS.md) | Security chaos engineering, failure direction, and evidence |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | Injection tiers, probes, journaling, and recovery |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Walkthrough from experiment selection to a verified report |
| [04 - Challenges](learn/04-CHALLENGES.md) | Extension ideas and exercises |

## License

[AGPL 3.0](LICENSE).
