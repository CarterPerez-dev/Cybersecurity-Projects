```ruby
██╗  ██╗ █████╗ ███████╗██╗  ██╗    ██╗██████╗
██║  ██║██╔══██╗██╔════╝██║  ██║    ██║██╔══██╗
███████║███████║███████╗███████║    ██║██║  ██║
██╔══██║██╔══██║╚════██║██╔══██║    ██║██║  ██║
██║  ██║██║  ██║███████║██║  ██║    ██║██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝╚═════╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Foundations-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/foundations/hash-identifier)
[![Tier: Foundations](https://img.shields.io/badge/Tier-Foundations-00C9A7?style=flat&logo=bookstack&logoColor=white)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/foundations)
[![Python 3.13+](https://img.shields.io/badge/Python-3.13+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Tests](https://img.shields.io/badge/tests-pytest-0A9EDC?style=flat&logo=pytest&logoColor=white)](https://pytest.org)
[![Lint](https://img.shields.io/badge/lint-ruff%20%2B%20mypy%20%2B%20pylint-D7FF64?style=flat)](https://github.com/astral-sh/ruff)

> Identify the algorithm behind a hash string by its prefix, length, and character set — the first move in any password-cracking workflow.

*This is a quick overview — security theory, architecture, and full walkthroughs are in the [learn modules](#learn).*

> [!NOTE]
> **Foundations tier** — this project is built for someone who has never written Python before. The source code is heavily commented as a teaching aid, the `learn/` folder explains every concept from zero, and the whole tool is one readable file. If you already know Python, jump straight to [`PROJECTS/beginner/hash-cracker`](../../beginner/hash-cracker) — the natural cracking companion to this identifier.

## What It Does

- Identify ~30 hash formats by prefix (`$2b$`, `$argon2id$`, `$apr1$`, `pbkdf2_sha256$`, `{SSHA}`, and more)
- Identify common hex hashes by length (MD5, SHA-1, SHA-256, SHA-512, NTLM, MD4, RIPEMD, BLAKE2, SHA-3)
- Recognize MySQL5, NetNTLMv1/v2, and traditional 13-char DES crypt by shape
- Detect non-hash inputs (JWTs, base64 blobs) and tell the user what they actually pasted
- Return ranked candidates with `high` / `medium` / `low` confidence and a one-line *reason* for every guess
- Pure-function core — no network, no filesystem, no global state, instant runtime
- Rich-rendered colored output table; clean exit codes for shell scripting

## Quick Start

```bash
./install.sh
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
# ✔ MD5 (medium) — 32 hex chars, most likely candidate at this length
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Demo Hashes

Try these — each demonstrates a different identification path:

| Hash | Detected as | Why |
|------|-------------|-----|
| `5f4dcc3b5aa765d61d8327deb882cf99` | MD5 | 32 hex chars — most likely candidate at this length |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | SHA-256 | 64 hex chars — most likely candidate at this length |
| `$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK` | bcrypt | prefix `$2b$` — bcrypt PHC string, 2b variant (current) |
| `$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG` | Argon2id | prefix `$argon2id$` — modern PHC string, the current standard |
| `$apr1$JlOdSlVe$ipa1mTAv3LFRBHHzqaIaH/` | Apache MD5-crypt | prefix `$apr1$` — Apache htpasswd MD5 variant (`htpasswd -m`) |
| `*A4B6157319038724E3560894F7F932C8886EBFCF` | MySQL5 | starts with `*` followed by 40 uppercase hex chars |
| `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN...` | JWT (not a hash) | leading `eyJ` is base64 of `{"` — JWT, not a hash |

```bash
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
just run -- '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK'
just run -- '*A4B6157319038724E3560894F7F932C8886EBFCF'
just run -- e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

> [!IMPORTANT]
> Always wrap hashes that begin with `$` in **single quotes**. Without quotes your shell will try to expand `$2`, `$P$`, `$1$` etc. as shell variables and silently mangle the input.

## Tooling

```bash
just            # list available recipes
just test       # run pytest (30+ tests, runs in under a second)
just lint       # ruff + mypy --strict + pylint
just format     # yapf
just run -- <h> # identify a hash
```

## Requirements

- **Python 3.13+** — the install script will check.
- [`uv`](https://github.com/astral-sh/uv) — modern Python package manager (auto-installed by `./install.sh`).
- [`just`](https://github.com/casey/just) — command runner (auto-installed by `./install.sh`).

No compilers, no system libraries, no network access required. The project is one Python file plus tests.

## Learn

This project includes step-by-step learning materials covering security theory, architecture, and implementation — written for someone who has never touched Python before.

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Quick start, prerequisites, common problems |
| [01 - Concepts](learn/01-CONCEPTS.md) | What hashes are, real-world breaches, the three identification signals |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | Three-layer architecture, six-step decision pipeline, data-driven design |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Line-by-line walkthrough — every Python feature explained when first encountered |
| [04 - Challenges](learn/04-CHALLENGES.md) | Five tiers of extension ideas, from adding a prefix rule to building an ML classifier |

## See Also

- [`PROJECTS/beginner/hash-cracker`](../../beginner/hash-cracker) — the natural sibling. Once this tool tells you *what* a hash is, that one teaches you how to crack it.
- [`PROJECTS/foundations/http-headers-scanner`](../http-headers-scanner) — another foundations-tier Python project, slightly more involved I/O.
- [`PROJECTS/foundations/password-manager`](../password-manager) — the hardest foundations-tier project; covers Argon2id, AES-GCM, and on-disk vaults.

## License

AGPL 3.0
