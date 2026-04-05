# Credential Enumeration Tool — Design Spec

## Overview

A post-access credential enumeration tool written in Nim that scans Linux systems for exposed secrets across 7 categories. Compiles to a single static binary with zero dependencies — drop on target, run, get a structured report of every credential file, its exposure level, and severity rating.

**Language:** Nim 2.2.x
**Binary name:** `credenum`
**Architecture:** Modular collector pattern — one module per credential category, common interface, central runner

---

## Core Types (`src/types.nim`)

- **Severity** — enum: `info`, `low`, `medium`, `high`, `critical`
- **Category** — enum: `browser`, `ssh`, `cloud`, `history`, `keyring`, `git`, `apptoken`
- **Credential** — discovered credential data (source, credential type, value or redacted preview, metadata)
- **Finding** — a single discovery (path, category, severity, description, optional Credential, file permissions, timestamps)
- **CollectorResult** — `seq[Finding]` + collector metadata (name, duration, errors encountered)
- **HarvestConfig** — runtime configuration (target home dir, enabled modules, exclude patterns, output format, flags)
- **Report** — all collector results + summary stats + timestamp + target info

**Severity assignment rules:**
- Critical: plaintext credentials in world-readable files
- High: unprotected private keys, plaintext credential stores
- Medium: overly permissive file permissions on credential files
- Low: credential files exist but properly permissioned
- Info: enumeration data (host lists, profile counts, existence checks)

---

## Collector Modules

Each module exports `proc collect(config: HarvestConfig): CollectorResult`. The runner calls each in sequence. No inheritance needed — just a common return type and a seq of collector procs populated at init.

### 1. Browser Credential Store Scanner (`src/collectors/browser.nim`)
- Firefox: locate profiles via `profiles.ini`, check `logins.json`, `cookies.sqlite`, `key4.db`
- Chromium: locate `Login Data`, `Cookies`, `Web Data` SQLite databases
- Report: file locations, permissions, entry counts, last-modified timestamps
- Flag world-readable/group-readable databases as critical
- Detection + metadata level (no decryption)

### 2. SSH Key & Config Auditor (`src/collectors/ssh.nim`)
- Scan `~/.ssh/` for private keys (RSA, Ed25519, ECDSA, non-standard filenames)
- Read key headers to determine passphrase protection (encrypted PEM vs unencrypted)
- Flag unprotected keys as high severity
- Check permissions (keys=600, directory=700)
- Parse `~/.ssh/config` — enumerate hosts, identify weak settings
- Read `authorized_keys` and `known_hosts` for enumeration

### 3. Cloud Provider Config Scanner (`src/collectors/cloud.nim`)
- AWS: `~/.aws/credentials`, `~/.aws/config` — count profiles, identify static vs session keys
- GCP: `~/.config/gcloud/` — application default credentials, service account keys
- Azure: `~/.azure/` — access tokens, profile info
- Kubernetes: `~/.kube/config` — enumerate contexts, clusters, auth methods
- Permission checks, flag anything broader than owner-only

### 4. Shell History & Environment Scanner (`src/collectors/history.nim`)
- Read `.bash_history`, `.zsh_history`, `.fish_history`
- Pattern match for inline secrets: KEY=, SECRET=, TOKEN=, PASSWORD= exports, DB connection strings, curl/wget with auth headers
- Scan for `.env` files in home directory tree
- Report: file, line region, redacted preview

### 5. Keyring & Password Store Scanner (`src/collectors/keyring.nim`)
- GNOME Keyring: `~/.local/share/keyrings/`
- KDE Wallet: `~/.local/share/kwalletd/`
- KeePass/KeePassXC: search for `.kdbx` files
- pass (password-store): `~/.password-store/`
- Bitwarden: `~/.config/Bitwarden/` local vault data
- Report locations, file sizes, permissions, last modified

### 6. Git Credential Store Scanner (`src/collectors/git.nim`)
- `~/.git-credentials` — plaintext storage (high severity)
- `~/.gitconfig` — check `credential.helper` setting
- Search for credential cache socket files
- Check for GitHub/GitLab PATs in config files

### 7. Application Token Scanner (`src/collectors/apptoken.nim`)
- Slack: `~/.config/Slack/` session/cookie storage
- Discord: `~/.config/discord/` token storage
- VS Code: `~/.config/Code/` stored secrets
- Database configs: `~/.pgpass`, `~/.my.cnf`, Redis configs
- MQTT broker configs, common application credential files

---

## CLI Interface

```
credenum [flags]

Flags:
  --target <user>      Target user home directory (default: current user)
  --modules <list>     Comma-separated module list (default: all)
  --exclude <patterns> Glob patterns for paths to skip
  --format <fmt>       Output format: terminal, json, both (default: terminal)
  --output <path>      Write JSON output to file
  --dry-run            List paths that would be scanned without reading
  --quiet              Suppress banner and progress, output findings only
  --verbose            Show all scanned paths, not just findings
```

**CLI parsing:** `std/parseopt` (stdlib, no dependencies)

---

## Terminal Output Design

Hacker-aesthetic terminal output:
- ASCII art banner with tool name and version
- Box-drawing characters for section borders
- Color-coded severity badges (critical=red, high=magenta, medium=yellow, low=cyan, info=dim)
- Clean table formatting for findings
- Summary footer with totals by severity, modules scanned, duration
- Progress indicators showing which module is currently scanning

---

## Output Formats

### Terminal (ANSI)
Colored, formatted output designed for interactive use. Banner, per-module sections, severity badges, summary.

### JSON
Structured report:
```json
{
  "metadata": { "timestamp": "...", "target": "...", "version": "...", "duration_ms": 0 },
  "modules": [
    {
      "name": "ssh",
      "findings": [
        {
          "category": "ssh",
          "severity": "high",
          "path": "/home/user/.ssh/id_rsa",
          "description": "Unprotected private key (no passphrase)",
          "permissions": "0644",
          "modified": "2026-01-15T10:30:00Z"
        }
      ],
      "duration_ms": 12,
      "errors": []
    }
  ],
  "summary": { "critical": 2, "high": 5, "medium": 8, "low": 3, "info": 12 }
}
```

---

## Build & Distribution

### Static binary via musl
- `config.nims` configures musl-gcc for fully static Linux binaries
- Zero runtime dependencies

### Cross-compilation
- x86_64-linux (primary)
- aarch64-linux (ARM64)
- Uses zig cc for cross-compilation
- Justfile tasks: `just build-x86`, `just build-arm64`

### Build modes
- `just build` — debug build with all checks
- `just release` — optimized static binary (`-d:release -d:lto --opt:size`)
- `just release-small` — stripped + UPX compressed

### Justfile tasks
- `just build` / `just release` / `just release-small`
- `just test` — run unit tests
- `just docker-test` — build + run in Docker test environment
- `just fmt` — format with nph
- `just clean`

---

## Docker Test Environment

**`tests/docker/Dockerfile`** — Ubuntu-based container planting fake credentials across all 7 categories:

- SSH: test key pairs (some protected, some not), various permissions
- Browser: mock Firefox profile with dummy `logins.json`, mock Chromium dirs
- Cloud: fake AWS credentials, dummy GCP service account JSON, mock kubeconfig
- History: seeded `.bash_history`/`.zsh_history` with fake tokens
- Keyrings: mock `.kdbx`, mock `pass` store
- Git: `.git-credentials` with dummy entries
- App tokens: mock Slack/Discord/VS Code configs, `.pgpass`, `.my.cnf`

All values are obviously fake (`AKIA_FAKE_ACCESS_KEY_12345`).

`just docker-test` builds, runs credenum inside, validates all findings discovered with correct severity.

---

## Project Structure

```
credential-enumeration/
├── src/
│   ├── harvester.nim              # Entry point, CLI parsing
│   ├── config.nim                 # Constants, paths, patterns, severities
│   ├── types.nim                  # Core types
│   ├── runner.nim                 # Execute collectors, aggregate results
│   ├── output/
│   │   ├── terminal.nim           # ANSI terminal output with hacker aesthetic
│   │   └── json.nim               # JSON serialization
│   └── collectors/
│       ├── base.nim               # Collector registration
│       ├── browser.nim
│       ├── ssh.nim
│       ├── cloud.nim
│       ├── history.nim
│       ├── keyring.nim
│       ├── git.nim
│       └── apptoken.nim
├── tests/
│   └── docker/
│       ├── Dockerfile
│       └── planted/               # Mock credential files
├── learn/
│   ├── 00-OVERVIEW.md
│   ├── 01-CONCEPTS.md
│   ├── 02-ARCHITECTURE.md
│   ├── 03-IMPLEMENTATION.md
│   └── 04-CHALLENGES.md
├── config.nims                    # Build config (static linking, cross-compile)
├── credential-enumeration.nimble  # Package manifest
├── Justfile
├── install.sh
├── README.md
├── LICENSE
└── .gitignore
```

---

## Learn Folder

- **00-OVERVIEW.md** — What credential enumeration is, why it matters, prerequisites, quick start
- **01-CONCEPTS.md** — Linux credential storage locations, file permission model, where apps store secrets and why defaults are insecure. Real-world breach references.
- **02-ARCHITECTURE.md** — Modular collector design, data flow, why Nim for security tooling
- **03-IMPLEMENTATION.md** — Code walkthrough: core types, collector pattern, CLI parsing, output formatting, Nim type system and modules
- **04-CHALLENGES.md** — Extensions: new collectors, encrypted output, network enumeration, framework integration

---

## What This Project Teaches

- Linux credential storage locations across browsers, SSH, cloud tools, shells, keyrings, Git, and applications
- File permission models and their security implications
- Nim programming: static compilation, module system, type system, FFI potential
- Why Nim is adopted in the security assessment community (small static binaries, C-level performance)
- Modular tool architecture with common interfaces
- Building visually polished CLI tools
- Docker-based testing for security tools
- Cross-compilation and static linking for portable binaries
