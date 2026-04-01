```json
 █████╗ ██╗  ██╗██╗   ██╗███╗   ███╗ ██████╗ ██████╗ ████████╗███████╗███╗   ███╗
██╔══██╗╚██╗██╔╝██║   ██║████╗ ████║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝████╗ ████║
███████║ ╚███╔╝ ██║   ██║██╔████╔██║██║   ██║██████╔╝   ██║   █████╗  ██╔████╔██║
██╔══██║ ██╔██╗ ██║   ██║██║╚██╔╝██║██║   ██║██╔══██╗   ██║   ██╔══╝  ██║╚██╔╝██║
██║  ██║██╔╝ ██╗╚██████╔╝██║ ╚═╝ ██║╚██████╔╝██║  ██║   ██║   ███████╗██║ ╚═╝ ██║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝     ╚═╝
```
#### >>> [Live Demo](axumortem.carterperez-dev.com)

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2320-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/binary-analysis-tool)
[![Rust](https://img.shields.io/badge/Rust-stable-000000?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker)](https://www.docker.com)

> Static binary analysis engine with multi-format parsing, YARA scanning, x86 disassembly, and MITRE ATT&CK threat scoring.

*This is a quick overview — security theory, architecture, and full walkthroughs are in the [learn modules](#learn).*

## What It Does

- Multi-format binary parsing (ELF, PE, Mach-O) with section analysis and import table extraction
- YARA rule scanning with 14 built-in detection rules for malware, packers, and crypto patterns
- x86/x86_64 disassembly with control flow graph generation from entry points and symbol tables
- Shannon entropy analysis for detecting packed or encrypted sections
- 8-category threat scoring system (max 100 points) with MITRE ATT&CK technique mapping
- Pass-based analysis pipeline with topological ordering and dependency resolution

## Quick Start

```bash
docker compose up -d
```

Visit `http://localhost:22784`

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Stack

**Backend:** Rust, Axum, goblin, iced-x86, yara-x, SQLx, PostgreSQL

**Frontend:** React 19, TypeScript, Vite, TanStack Query, Zustand, Zod, SCSS Modules

**Infra:** Docker Compose, Nginx, PostgreSQL 18

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
