```ruby
 ██████╗██████╗ ███████╗██████╗ ███████╗███╗   ██╗██╗   ██╗███╗   ███╗
██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝████╗  ██║██║   ██║████╗ ████║
██║     ██████╔╝█████╗  ██║  ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
██║     ██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
╚██████╗██║  ██║███████╗██████╔╝███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
 ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2321%20intermediate-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/credential-enumeration)
[![Nim](https://img.shields.io/badge/Nim-2.2+-FFE953?style=flat&logo=nim&logoColor=black)](https://nim-lang.org)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-T1552-orange?style=flat)](https://attack.mitre.org/techniques/T1552/)

> Post-access credential exposure detection for Linux systems, written in Nim.

*This is a quick overview. Security theory, architecture, and full walkthroughs are in the [learn modules](#learn).*

## What It Does

- Scans Linux home directories for exposed credentials across 7 categories
- Detects unprotected SSH keys, plaintext cloud credentials, browser credential stores, shell history secrets, keyrings, Git tokens, and application credentials
- Classifies findings by severity based on file permissions and exposure risk
- Reports in terminal with color-coded output or structured JSON for automation
- Compiles to a single static binary with zero runtime dependencies

## Quick Start

```bash
bash install.sh
credenum
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Stack

**Language:** Nim 2.2+ (ORC memory management)

**Build:** Just, Nimble, musl (static linking), UPX (compression), zigcc (cross-compilation)

**Testing:** Nim unittest, Docker (integration tests with planted credentials)

## Learn

This project includes step-by-step learning materials covering security theory, architecture, and implementation.

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Prerequisites and quick start |
| [01 - Concepts](learn/01-CONCEPTS.md) | Security theory and real-world breaches |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | System design and data flow |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Code walkthrough |
| [04 - Challenges](learn/04-CHALLENGES.md) | Extension ideas and exercises |

## License

AGPL 3.0
