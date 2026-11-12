```ruby
██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗
██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗
██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║
██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Foundations-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/foundations/http-headers-scanner)
[![Tier: Foundations](https://img.shields.io/badge/Tier-Foundations-00C9A7?style=flat&logo=bookstack&logoColor=white)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/foundations)
[![Python 3.13](https://img.shields.io/badge/Python-3.13-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Tests](https://img.shields.io/badge/tests-pytest-0A9EDC?style=flat&logo=pytest&logoColor=white)](https://pytest.org)
[![Lint](https://img.shields.io/badge/lint-ruff%20%2B%20mypy%20%2B%20pylint-D7FF64?style=flat)](https://github.com/astral-sh/ruff)
[![HTTP Client](https://img.shields.io/badge/httpx-0.28+-1f5582?style=flat)](https://www.python-httpx.org/)

> Fetch a URL once and grade its HTTP security headers A through F using the same weighted-rubric model as Mozilla Observatory.

*This is a quick overview, security theory, architecture, and full walkthroughs are in the [learn modules](#learn).*

> [!NOTE]
> **Foundations tier**, this project is built for someone who has never written Python before. The source code is heavily commented as a teaching aid, the `learn/` folder explains every concept from zero, and the whole tool is one readable file. If you already know Python, the natural next step is [`PROJECTS/foundations/password-manager`](../password-manager), the hardest foundations project, which adds Argon2id, AES-GCM, and on-disk state.

## What It Does

- Performs one polite HTTPS request to the URL you provide and inspects the response headers
- Grades six security-critical headers against a weighted rubric (high = 30 pts, medium = 15 pts, low = 5 pts)
- Reports each finding as `ok`, `weak`, or `missing` with a one-line explanation of why
- Computes a 0 to 100 score and maps it to an A through F letter grade (90+ = A, 80+ = B, etc.)
- Catches subtly broken values like `Strict-Transport-Security: max-age=0` (header present, actively disabled) and flags them as `weak`, not `ok`
- Follows redirects and grades the **final** URL, the one your browser would actually land on
- Prints a colored Rich table plus a grade panel plus a recommendation list for every non-`ok` finding
- Returns meaningful exit codes: `0` for A/B, `1` for C/D, `2` for F or network error, useful in CI pipelines

## The Headers It Grades

| Header | Severity | What it stops |
|---|---|---|
| `Strict-Transport-Security` | high | SSL stripping on coffee-shop wifi |
| `Content-Security-Policy` | high | XSS via injected `<script>` tags |
| `X-Content-Type-Options` | medium | MIME-sniffing of uploaded files |
| `X-Frame-Options` | medium | Clickjacking via hidden iframes |
| `Referrer-Policy` | low | Leaking secret tokens via the Referer header |
| `Permissions-Policy` | low | Compromised third-party scripts abusing camera/mic/etc. |

Every header maps to a real attack class with a real history. The [`01-CONCEPTS.md`](learn/01-CONCEPTS.md) module walks through each one with concrete attack examples.

## Quick Start

```bash
./install.sh
just run -- https://example.com
# Grade: B, Score: 85 / 100  (example.com is missing CSP and Permissions-Policy)
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Demo URLs

Try these, each demonstrates a different grading path:

| URL | Expected grade | Why |
|---|---|---|
| `https://github.com` | A | Comprehensive CSP, HSTS with `includeSubDomains`, almost every header set |
| `https://web.dev` | A | Google's own developer-docs site, full modern header set |
| `https://mozilla.org` | A | Mozilla practices what Observatory preaches |
| `https://example.com` | B / C | Has HSTS, but missing CSP, Permissions-Policy, and others |
| `http://neverssl.com` | F | Intentionally serves plain HTTP, no security headers at all |

```bash
just run -- https://github.com
just run -- https://example.com
just run -- https://web.dev --timeout 5
just run -- http://neverssl.com
```

> [!IMPORTANT]
> Always include the `http://` or `https://` scheme. The scanner refuses bare hostnames like `github.com` because it cannot guess which scheme you meant, and guessing wrong is exactly the SSL-stripping problem HSTS exists to prevent.

## Sample Output

```
                  Headers for https://github.com/ (HTTP 200)
┌─────────────────────────────┬─────────┬──────────┬─────────────────────────┐
│ header                      │ status  │ severity │ note                    │
├─────────────────────────────┼─────────┼──────────┼─────────────────────────┤
│ Strict-Transport-Security   │ ok      │ high     │ Present and contains... │
│ Content-Security-Policy     │ ok      │ high     │ Present                 │
│ X-Content-Type-Options      │ ok      │ medium   │ Present and contains... │
│ X-Frame-Options             │ ok      │ medium   │ Present                 │
│ Referrer-Policy             │ ok      │ low      │ Present                 │
│ Permissions-Policy          │ missing │ low      │ Header ... is not set   │
└─────────────────────────────┴─────────┴──────────┴─────────────────────────┘
╭─ Result ───────────────────╮
│ Grade: A                   │
│ Score: 95 / 100            │
╰────────────────────────────╯
```

Followed by a `Recommendations:` block for every non-`ok` finding, with the exact header value to add.

## Exit Codes

The scanner returns shell-friendly exit codes so you can wire it into CI:

| Grade | Exit code | Meaning |
|---|---|---|
| A, B | `0` | Green light, no action needed |
| C, D | `1` | Worth investigating, often acceptable depending on context |
| F or network error | `2` | Hard fail, must fix |

```bash
just run -- https://my-deployed-site.com
if [ $? -gt 1 ]; then exit 1; fi   # fail the build only on F or error
```

## Tooling

```bash
just            # list available recipes
just test       # run pytest (11 tests, runs in under a second, network-mocked with respx)
just lint       # ruff + mypy --strict + pylint
just format     # yang
just run -- <url>  # scan a URL
```

## Requirements

- **Python 3.13+**, the install script will check.
- [`uv`](https://github.com/astral-sh/uv), modern Python package manager (auto-installed by `./install.sh`).
- [`just`](https://github.com/casey/just), command runner (auto-installed by `./install.sh`).
- A working internet connection at runtime (the scanner makes one real HTTPS request per scan, but the test suite mocks the network with `respx` and runs fully offline).

No compilers, no system libraries. The project is one Python file plus tests.

## Learn

This project includes step-by-step learning materials covering security theory, architecture, and implementation, written for someone who has never touched Python before.

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Quick start, prerequisites, expected output, common first-run problems |
| [01 - Concepts](learn/01-CONCEPTS.md) | What HTTP is, what a header is, each security header with the real attack it stops (SSL stripping, clickjacking, MIME sniffing, XSS, referer leakage) |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | The four-stage pipeline, dataclasses as value objects, the I/O fence pattern (functional core / imperative shell) |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Function-by-function walkthrough, every Python feature explained when first encountered, plus test patterns and tooling |
| [04 - Challenges](learn/04-CHALLENGES.md) | Twelve extension ideas, from "add a seventh header rule" up through "wrap it in a FastAPI service with rate limiting" |

## Real-World Context

This scanner is a teaching-scale version of tools that do the same job at production scale:

- **[Mozilla Observatory](https://observatory.mozilla.org/)**, the canonical version. Same weighted-rubric approach, deeper CSP analysis, cookie checks, TLS configuration grading.
- **[securityheaders.com](https://securityheaders.com)**, simpler UI, same idea.
- **[nmap http-security-headers script](https://nmap.org/nsedoc/scripts/http-security-headers.html)**, for command-line workflows.

Once you understand how this scanner makes decisions, those tools become readable instead of magical. The [04-CHALLENGES.md](learn/04-CHALLENGES.md) module includes ideas for growing this project toward what Observatory does.

## See Also

- [`PROJECTS/foundations/hash-identifier`](../hash-identifier), the easier foundations project, pure logic and no network at all.
- [`PROJECTS/foundations/password-manager`](../password-manager), the hardest foundations project, covers Argon2id, AES-GCM, and on-disk vaults.
- [`PROJECTS/advanced/bug-bounty-platform`](../../advanced/bug-bounty-platform), what a serious web-security tool looks like once it grows up.

## License

AGPL 3.0
