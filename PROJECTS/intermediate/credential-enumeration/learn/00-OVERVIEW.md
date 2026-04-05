# 00-OVERVIEW.md

# Credential Enumeration

## What This Is

A command-line tool that scans Linux home directories for exposed credentials after gaining access to a system. It checks 7 categories of credential storage: SSH keys, browser data, cloud provider configs (AWS/GCP/Azure/Kubernetes), shell history, keyrings, Git credential stores, and application tokens. Each finding is classified by severity based on file permissions and exposure risk. Written in Nim and compiled to a single static binary.

## Why This Matters

Credentials left in home directories are one of the most reliable footholds attackers find after initial access. The LastPass breach in 2022-2023 traced back to a DevOps engineer's home machine where an attacker found SSH keys and cloud credentials that gave access to production vaults. In the CircleCI incident (January 2023), an engineer's laptop was compromised and session tokens were stolen from browser storage, which gave the attacker access to customer secrets across the platform. The Uber breach in September 2022 started with social engineering but escalated because hardcoded credentials were sitting in PowerShell scripts on internal network shares.

These aren't exotic attack techniques. MITRE ATT&CK catalogs them as T1552 (Unsecured Credentials) with sub-techniques for credentials in files (T1552.001), bash history (T1552.003), and private keys (T1552.004). Separately, T1555 covers credentials from password stores (T1555.001 for keychains, T1555.003 for web browsers). These techniques appear in nearly every post-access kill chain because they work so often and so reliably.

This project teaches you what attackers look for, where they look, and how to detect that exposure before it gets exploited.

**Real world scenarios where this applies:**
- Red team operators mapping available credentials after landing on a Linux workstation
- Blue team defenders auditing developer machines for credential hygiene
- Security engineers building credential exposure into CI/CD compliance checks
- System administrators verifying SSH key permissions across fleet machines
- Incident responders determining what credentials an attacker could have accessed

## What You'll Learn

**Security Concepts:**
- MITRE ATT&CK credential access techniques (T1552, T1555) and how they map to real file system locations
- Linux file permission model and why 0644 on an SSH private key is a finding but 0600 is not
- How browsers store credentials (Firefox's logins.json + key4.db, Chromium's Login Data SQLite database)
- Cloud credential storage patterns across AWS, GCP, Azure, and Kubernetes
- Shell history as an intelligence source: leaked secrets in exports, credential-bearing commands, .env files

**Technical Skills:**
- Building a modular scanner architecture with pluggable collectors in Nim
- Unix file permission inspection using POSIX stat syscalls
- Pattern matching for secret detection across shell history and config files
- Structured severity classification based on permission analysis
- Dual output rendering: colored terminal with box drawing and structured JSON

**Tools and Techniques:**
- Nim systems programming with ORC memory management and zero-exception guarantees (`{.push raises: [].}`)
- Static binary compilation with musl for deployment without runtime dependencies
- Cross-compilation targeting x86_64 and aarch64 via zigcc
- Docker-based integration testing with planted credential fixtures
- Just as a task runner for build, test, and release workflows

## Prerequisites

**Required knowledge:**
- Linux fundamentals: navigating the file system, understanding home directory layout, reading file permissions with `ls -la`
- Basic programming concepts: functions, loops, conditionals, data structures. Nim reads like Python with type annotations, so Python experience transfers well
- Security basics: what credentials are, why unprotected credentials are dangerous, what SSH keys do

**Tools you'll need:**
- Nim 2.2.0+ with nimble package manager
- Docker (for integration tests)
- Just task runner (optional but recommended)
- A Linux system (the tool targets Linux credential stores specifically)

**Helpful but not required:**
- Familiarity with Nim syntax. If you know Python, you can read Nim. The significant differences are compile-time types and manual memory layout
- Experience with penetration testing or red team operations provides context for why these credential locations matter
- Understanding of cloud provider authentication (AWS IAM, GCP service accounts, Kubernetes RBAC)

## Quick Start

```bash
cd PROJECTS/intermediate/credential-enumeration

bash install.sh

credenum
```

Expected output: A colored terminal report showing findings grouped by module (SSH, browser, cloud, history, keyring, git, apptoken). Each finding shows a severity badge, file path, permissions, and modification timestamp. The summary at the bottom shows total findings by severity.

To run with JSON output:

```bash
credenum --format json
```

To scan specific modules only:

```bash
credenum --modules ssh,git,cloud
```

To run the integration test suite:

```bash
just docker-test
```

This builds a Docker container with planted credential fixtures across all 7 categories and validates that the scanner detects each one.

## Project Structure

```
credential-enumeration/
├── src/
│   ├── harvester.nim              # Entry point, CLI parser, main orchestration
│   ├── runner.nim                 # Routes categories to collectors, aggregates results
│   ├── types.nim                  # Core data structures (Finding, Report, Severity, etc)
│   ├── config.nim                 # All constants: paths, patterns, thresholds, colors
│   ├── collectors/
│   │   ├── base.nim               # Shared utilities: file ops, permissions, finding factories
│   │   ├── browser.nim            # Firefox profiles + Chromium variants
│   │   ├── ssh.nim                # Private keys, config, authorized_keys, known_hosts
│   │   ├── git.nim                # .git-credentials, config helpers, GitHub/GitLab tokens
│   │   ├── cloud.nim              # AWS, GCP, Azure, Kubernetes credential files
│   │   ├── history.nim            # Shell history secrets, command patterns, .env files
│   │   ├── keyring.nim            # GNOME Keyring, KDE Wallet, KeePass, pass, Bitwarden
│   │   └── apptoken.nim           # Database creds, dev tokens, infra tokens, Docker auth
│   └── output/
│       ├── terminal.nim           # Box-drawn colored terminal renderer
│       └── json.nim               # Structured JSON output with metadata
├── tests/
│   ├── test_all.nim               # Unit tests (30+ cases)
│   └── docker/
│       ├── Dockerfile             # Multi-stage: nim builder + ubuntu test runtime
│       ├── validate.sh            # Integration test: runs scanner, checks all 7 categories
│       └── planted/               # Credential fixtures (SSH keys, AWS creds, tokens, etc)
├── config.nims                    # Nim compiler switches (ORC, musl, zigcc, cross-compile)
├── credential-enumeration.nimble  # Package manifest
├── Justfile                       # Build, test, release, format commands
└── install.sh                     # One-step install: compile + PATH setup
```

## Next Steps

1. **Understand the concepts** - Read [01-CONCEPTS.md](./01-CONCEPTS.md) to learn about credential exposure vectors, Linux file permissions, how browsers and cloud providers store secrets, and real breaches driven by unsecured credentials
2. **Study the architecture** - Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) to see the collector-based design, how severity classification works, and why the type system is structured the way it is
3. **Walk through the code** - Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for detailed breakdowns of the CLI parser, each collector module, the permission analysis logic, and the output renderers
4. **Extend the project** - Read [04-CHALLENGES.md](./04-CHALLENGES.md) for ideas ranging from adding new collectors to building a remediation engine

## Common Issues

**Nim version too old**
```
Error: Nim 2.2+ required (found 1.6.x)
```
Solution: Update via `choosenim stable` or install from https://nim-lang.org/install.html

**Static build fails (musl not found)**
```
Error: musl-gcc not found
```
Solution: Install musl tools. On Debian/Ubuntu: `apt install musl-tools`. On Arch: `pacman -S musl`. The install script falls back to dynamic linking if musl is unavailable.

**Docker test shows 0 findings**
```
Results: 0 passed, 30 failed
```
Solution: The planted credential fixtures may not have been copied. Check that `tests/docker/planted/` contains the test files and rebuild with `just docker-build`.

**Binary too large**
The debug build produces a ~2MB binary. For a smaller binary: `just release-small` compiles with optimizations, strips symbols, and compresses with UPX, producing a binary under 200KB.

## Related Projects

If you found this interesting, check out:
- **[secrets-scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/secrets-scanner)** - Scans codebases and git history for leaked secrets using entropy analysis and pattern matching. Complements this project by covering the repository side rather than the file system side
- **[docker-security-audit](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/docker-security-audit)** - CIS Docker Benchmark scanner. Focuses on container security, where misconfigured containers can expose the same credential files this tool detects
- **[api-rate-limiter](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/api-rate-limiter)** - Enterprise rate limiting for FastAPI. Shows how stolen API credentials (the kind this tool finds) get used to abuse API endpoints
