```regex
██████╗  ██████╗ ██████╗ ████████╗██╗ █████╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██║██╔══██╗
██████╔╝██║   ██║██████╔╝   ██║   ██║███████║
██╔═══╝ ██║   ██║██╔══██╗   ██║   ██║██╔══██║
██║     ╚██████╔╝██║  ██║   ██║   ██║██║  ██║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2316%20intermediate-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/secrets-scanner)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![HIBP](https://img.shields.io/badge/HIBP-integrated-2A6DB2?style=flat)](https://haveibeenpwned.com/API/v3)

> Secrets scanner for codebases and git repositories, written in Go.

*This is a quick overview. Security theory, architecture, and full walkthroughs are in the [learn modules](#learn).*

## What It Does

- 150 detection rules covering AWS, GitHub, GitLab, GCP, Azure, Slack, Stripe, Twilio, SendGrid, SSH/PGP keys, passwords, connection strings, JWTs, and 100+ more
- Shannon entropy analysis for detecting high-randomness strings
- HIBP breach verification via k-anonymity protocol (your secrets never leave your machine)
- Directory scanning and full git history scanning (branches, depth, date ranges)
- Output as colored terminal tables, JSON, or SARIF v2.1.0
- 5-layer false positive defense: keyword pre-filter, structural validation, stopwords, allowlists, entropy
- Concurrent pipeline with bounded worker pools
- TOML configuration via `.portia.toml` or `pyproject.toml`

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/CarterPerez-dev/portia/main/install.sh | bash
```

Or with Go:

```bash
go install github.com/CarterPerez-dev/portia/cmd/portia@latest
```

## Quick Start

```bash
portia scan .
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Commands

| Command | Description |
|---------|-------------|
| `portia scan [path]` | Scan a directory for secrets |
| `portia git [repo]` | Scan git history for secrets |
| `portia init` | Initialize `.portia.toml` configuration |
| `portia pyproject` | Create `pyproject.toml` with `[tool.portia]` config |
| `portia config rules` | List all 150 detection rules |
| `portia config show` | Show active configuration |

**Flags:** `--format` (terminal/json/sarif), `--verbose`, `--no-color`, `--exclude`, `--max-size`, `--hibp`, `--config`

**Git flags:** `--branch`, `--since`, `--depth`, `--staged`

## Learn

This project includes step-by-step learning materials covering security theory, architecture, and implementation.

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Prerequisites and quick start |
| [01 - Concepts](learn/01-CONCEPTS.md) | Secret sprawl, entropy, and breach databases |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | System design and data flow |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Code walkthrough |
| [04 - Challenges](learn/04-CHALLENGES.md) | Extension ideas and exercises |

## License

AGPL 3.0
