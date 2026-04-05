# 04-CHALLENGES.md

# Challenges

Extension ideas organized by difficulty. Each challenge builds on the existing codebase and teaches specific security or engineering concepts.

## Easy Challenges

### 1. Add a Container Credentials Collector

**What to build:** A new collector module that scans for container runtime credentials beyond what the apptoken collector already checks for Docker.

**Why it's useful:** Container runtimes like Podman, containerd, and container orchestration tools store authentication and configuration data in the home directory. Podman uses `~/.config/containers/auth.json` for registry authentication. Buildah and Skopeo share the same credential store. Container-specific kubeconfig overrides may exist at `~/.config/containers/containers.conf`.

**Skills you'll practice:**
- Adding a new collector to the modular architecture
- Working with the Category enum and compiler-enforced exhaustive matching
- Understanding container runtime credential storage

**Hints:**
- Follow the pattern: add Category value, add to config arrays, create collector file, wire up in runner
- Check `~/.config/containers/` for auth.json, registries.conf, and containers.conf
- Check for `~/.config/podman/` if it exists
- The Docker auth scanning logic in apptoken.nim is a good reference for registry auth parsing

**How to test:** Add Podman/container fixture files to `tests/docker/planted/.config/containers/` and add checks to `validate.sh`.

### 2. Add CSV Output Format

**What to build:** A new output renderer that produces CSV with one row per finding.

**Why it's useful:** CSV output integrates with spreadsheets, SIEM imports, and data analysis tools. Security teams often need to aggregate findings across multiple hosts into a single dataset.

**Skills you'll practice:**
- Adding a new output format to the type system
- Working with the Report data structure
- Proper CSV escaping (fields containing commas, quotes, or newlines)

**Hints:**
- Add `fmtCsv` to the `OutputFormat` enum
- Create `output/csv.nim` with columns: severity, category, path, permissions, modified, description
- Handle CSV escaping: wrap fields in quotes, double any internal quotes
- The JSON renderer is a good structural reference

**How to test:** Run with `--format csv` and import into a spreadsheet. Verify all findings appear and special characters in descriptions don't break parsing.

### 3. Add Severity Filtering

**What to build:** A `--min-severity` flag that filters output to only show findings at or above a given severity level.

**Why it's useful:** In CI pipelines, you might want to fail only on CRITICAL findings. In audit mode, you might want to see everything including INFO. The current tool shows all findings and only uses HIGH/CRITICAL for exit codes.

**Skills you'll practice:**
- CLI argument parsing in Nim
- Filtering data after collection
- Working with ordered enums (Severity values have a natural ordering)

**Hints:**
- Add a `minSeverity` field to `HarvestConfig`
- Parse `--min-severity critical|high|medium|low|info` in the CLI parser
- Filter findings in the runner after collection: `res.findings = res.findings.filterIt(it.severity >= config.minSeverity)`
- Update the summary calculation to only count filtered findings
- Also update the exit code logic to respect the filter

### 4. Add Timestamp-Based Alerting

**What to build:** A `--recent <days>` flag that highlights findings for files modified within the last N days.

**Why it's useful:** During incident response, you care most about credentials that were recently accessed or modified. A `.git-credentials` file modified yesterday is more suspicious than one unchanged for two years.

**Skills you'll practice:**
- Date arithmetic in Nim
- Adding visual indicators to the terminal renderer
- Contextual severity adjustment

**Hints:**
- Parse `--recent 7` in the CLI parser
- In the terminal renderer, add a visual indicator (different color, prefix marker) for findings where the modification time is within the recent window
- Don't change the severity itself, just the visual presentation
- The `modified` field in Finding is already an ISO 8601 timestamp string

## Intermediate Challenges

### 5. Add SARIF Output Format

**What to build:** Output in SARIF (Static Analysis Results Interchange Format), the standard format used by GitHub Code Scanning, Azure DevOps, and other security platforms.

**Why it's useful:** SARIF is the industry standard for security tool output. Adding SARIF support means credenum results can be uploaded to GitHub Code Scanning, displayed in pull request annotations, and imported into security dashboards.

**Skills you'll practice:**
- Implementing an industry-standard output format
- Mapping domain-specific data (severity, category) to a standardized schema
- Working with nested JSON structures (SARIF is deeply nested)

**Implementation approach:**
1. Study the SARIF 2.1.0 schema at https://docs.oasis-open.org/sarif/sarif/v2.1.0/
2. Create `output/sarif.nim`
3. Map credenum concepts to SARIF: Finding → Result, Category → Rule, Severity → Level
4. SARIF severity levels are: error, warning, note, none. Map CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note
5. Each collector category becomes a "rule" with its own ID and description
6. The `physicalLocation` field uses the file path from each finding

**How to test:** Upload the output to GitHub Code Scanning using `gh api` or validate against the SARIF schema using a JSON Schema validator.

### 6. Add Remediation Suggestions

**What to build:** For each finding, generate a specific remediation command or instruction.

**Why it's useful:** Finding credentials is half the job. Telling the user exactly how to fix each issue makes the tool actionable rather than just informational.

**Skills you'll practice:**
- Pattern matching on finding types to generate context-specific advice
- String templating with actual file paths and values
- Understanding proper credential hygiene practices

**Implementation approach:**
1. Add a `remediation` field to the `Finding` type (or a parallel data structure)
2. After findings are collected, run a remediation pass that matches on category + description patterns
3. Generate specific commands:
   - SSH key with bad permissions → `chmod 0600 /home/user/.ssh/id_rsa`
   - Unencrypted SSH key → `ssh-keygen -p -f /home/user/.ssh/id_rsa` (adds passphrase)
   - World-readable AWS credentials → `chmod 0600 /home/user/.aws/credentials`
   - Secret in shell history → `sed -i 'Nd' /home/user/.bash_history` (line N)
   - Plaintext .git-credentials → `git config --global credential.helper cache` (switch to cache)
4. Add remediation output to both terminal and JSON renderers
5. Consider a `--fix` flag that applies permission fixes automatically (with confirmation)

**Extra credit:** Generate a shell script (`--remediate-script fix.sh`) that the user can review and execute.

### 7. macOS Support

**What to build:** Platform-specific collectors for macOS credential storage locations.

**Why it's useful:** macOS stores credentials in different locations than Linux. Browser paths differ (`~/Library/Application Support/`), the Keychain replaces desktop keyrings, and cloud CLI tools may use different config directories.

**Skills you'll practice:**
- Cross-platform filesystem handling
- Conditional compilation in Nim (`when defined(macosx)`)
- Understanding macOS security model (Keychain, TCC)

**Implementation approach:**
1. Add platform detection (`when defined(linux)` vs `when defined(macosx)`)
2. Create platform-specific path constants in config.nim
3. For macOS browsers:
   - Firefox: `~/Library/Application Support/Firefox/`
   - Chrome: `~/Library/Application Support/Google/Chrome/`
   - Safari: `~/Library/Cookies/`, `~/Library/Keychains/`
4. For macOS keychains: `~/Library/Keychains/login.keychain-db`
5. Cloud credentials use the same paths on both platforms
6. SSH directory is the same (`~/.ssh/`)
7. History files are the same (`~/.bash_history`, `~/.zsh_history`)
8. macOS-specific: `~/Library/Preferences/` plist files may contain tokens

**Gotcha:** macOS Transparency, Consent, and Control (TCC) may block access to some directories (e.g., Safari data) unless the terminal has Full Disk Access.

### 8. Watch Mode

**What to build:** A `--watch` flag that re-scans at a configurable interval and reports new or changed findings.

**Why it's useful:** Continuous monitoring catches credentials that appear after the initial scan. A developer pulls a `.env` file, creates a new SSH key, or configures a new cloud provider while the scanner is running in the background.

**Skills you'll practice:**
- Event loops and periodic execution in Nim
- Diffing structured data (comparing finding sets between runs)
- Terminal refresh without flooding output

**Implementation approach:**
1. Store the previous scan's findings as a set (keyed by path + category + description)
2. On each re-scan, compare new findings against the previous set
3. Report only new findings, removed findings, and changed severities
4. Use `--watch 30` for scan interval in seconds (default 60)
5. Clear and redraw the summary on each scan, append only new findings

## Advanced Challenges

### 9. Network Credential Scanning

**What to build:** Extend the tool to scan for credentials exposed over network protocols: mounted network shares, NFS exports, SSHFS mounts, and SMB shares.

**Why it's useful:** In enterprise environments, home directories are often NFS-mounted. Credentials on one machine may be accessible from any machine in the cluster. Network-mounted directories have different permission semantics (the NFS server may ignore local permission checks with `no_root_squash`).

**Skills you'll practice:**
- Detecting mount points and their types (`/proc/mounts` on Linux)
- Understanding NFS permission models vs local filesystem permissions
- Network-aware scanning and timeout handling

**Implementation approach:**
1. Parse `/proc/mounts` to identify NFS, CIFS, SSHFS, and other network mounts within the scan target
2. For network mounts, adjust severity: even `0600` permissions may be bypassed by the file server
3. Scan common network credential locations: `/etc/fstab` for stored mount credentials, `~/.smbcredentials`
4. Add a `--network` flag to enable this (disabled by default since it adds latency)
5. Add timeout handling for network paths that may be slow or unreachable

### 10. Credential Age Analysis

**What to build:** Track credential file age and flag credentials that haven't been rotated within a policy window.

**Why it's useful:** A properly permissioned AWS credential file that hasn't been rotated in 18 months is still a risk. Many compliance frameworks (SOC 2, PCI DSS) require credential rotation. This extends the tool from "is it exposed?" to "is it stale?"

**Skills you'll practice:**
- Date and time analysis against policy thresholds
- Configurable policy definitions
- Compliance mapping (SOC 2, PCI DSS rotation requirements)

**Implementation approach:**
1. Add a `--max-age <days>` flag with a default of 90 days
2. For each finding with a modification timestamp, calculate the file age
3. If the credential file is older than the threshold, add a secondary finding or flag
4. Severity for stale credentials: modification time should not change severity, but add a `stale` indicator to the output
5. Consider reading Git history of files like `~/.aws/credentials` to determine when the content (not just metadata) last changed

### 11. Agent Mode with Remote Reporting

**What to build:** A daemon mode that runs credenum on a schedule, compares results against a baseline, and sends alerts to a remote endpoint when new findings appear.

**Why it's useful:** Security teams managing fleets of developer machines need continuous visibility. Rather than running ad-hoc scans, agent mode provides ongoing monitoring with alerting.

**Skills you'll practice:**
- Building a long-running daemon in Nim
- Baseline management (storing and comparing scan results)
- HTTP client for pushing results to a webhook endpoint
- Systemd service file creation

**Implementation approach:**
1. Add a `--agent` flag with `--interval <seconds>` and `--webhook <url>`
2. On first run, save the report as a baseline JSON file
3. On subsequent runs, diff the new report against the baseline
4. If new findings appear or existing findings change severity, POST the diff to the webhook
5. Support multiple webhook formats: generic JSON, Slack incoming webhook, PagerDuty events API
6. Write a systemd unit file for deployment as a system service
7. Add `--baseline <path>` for explicit baseline management

**Testing strategy:**
- Unit test the diff logic (finding addition, removal, severity change)
- Integration test with a mock HTTP server that receives webhook payloads
- Test the daemon lifecycle (start, scan, sleep, re-scan, shutdown)

## Expert Challenge

### 12. Full Credential Lifecycle Platform

**What to build:** A web dashboard that aggregates credenum results from multiple hosts, tracks credential exposure over time, provides fleet-wide visibility, and integrates with remediation workflows.

**Prerequisites:** Familiarity with a web framework (FastAPI, Go's net/http, or similar), database design, and frontend basics.

**What you'll learn:**
- Security operations platform design
- Fleet-wide credential visibility
- Remediation workflow management
- Dashboard design for security operations

**High-level architecture:**

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Host A     │  │  Host B     │  │  Host C     │
│  credenum   │  │  credenum   │  │  credenum   │
│  --agent    │  │  --agent    │  │  --agent    │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │ HTTPS/webhook
                        ▼
              ┌─────────────────┐
              │  Aggregation    │
              │  API Server     │
              ├─────────────────┤
              │  PostgreSQL     │
              │  (findings,     │
              │   baselines,    │
              │   hosts)        │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Dashboard      │
              │  - Fleet view   │
              │  - Host detail  │
              │  - Trend charts │
              │  - Remediation  │
              │    tracking     │
              └─────────────────┘
```

**Phased implementation:**

Phase 1 - Foundation:
- Define the database schema (hosts, scans, findings, baselines)
- Build the API endpoint that receives scan results
- Store and deduplicate findings

Phase 2 - Core features:
- Fleet overview page: hosts by risk score, worst offenders, recent changes
- Host detail page: full finding list, history, severity trend
- Comparison view: diff between scans
- Search and filter across all findings

Phase 3 - Integration:
- Remediation workflow: assign findings to owners, track resolution, verify fixes
- Alert rules: new CRITICAL finding triggers PagerDuty/Slack/email
- Compliance view: map findings to SOC 2 / PCI DSS controls
- Export: generate compliance reports in PDF/CSV

Phase 4 - Polish:
- Host grouping (by team, environment, role)
- SLA tracking (time from detection to remediation)
- API tokens for automation
- Role-based access control

**Success criteria:**
- [ ] Agents on 3+ test hosts successfully push results to the API
- [ ] Dashboard shows fleet-level risk summary
- [ ] Finding diffs correctly detect new, removed, and changed findings
- [ ] Remediation workflow tracks at least one finding from detection to resolution
- [ ] Trend charts show exposure changes over time

## Mix and Match

Combine challenges for larger projects:

- **Challenges 3 + 6:** Severity filtering with remediation suggestions. Filter to HIGH+, generate a remediation script for just the urgent findings.
- **Challenges 5 + 10:** SARIF output with credential age annotations. Upload to GitHub and flag stale credentials as code scanning alerts.
- **Challenges 8 + 11:** Watch mode that feeds into agent mode. Local real-time monitoring with remote alerting.
- **Challenges 7 + 9:** macOS support plus network credential scanning. Cover both local and network-mounted credentials on both platforms.

## Performance Challenges

### Benchmark the Collectors

Profile each collector's execution time across different home directory sizes. The current timing data per module is a start, but deeper profiling reveals bottlenecks.

**What to measure:**
- Time per file system call (stat, readFile, walkDir)
- Memory allocation per finding
- Scaling behavior: how does scan time change with 10 vs 100 vs 1000 files in .ssh/?
- Impact of depth limits on history and keyring scanning

**Tools:** Nim's `--profiler:on` flag, `nimprof`, or custom timing with `getMonoTime()`.

### Optimize for Large Home Directories

Developer home directories on shared servers can be massive (100GB+, millions of files). The recursive .env scanner and KeePass scanner will be the bottleneck.

**Ideas:**
- Use `inotify` to watch for file changes instead of periodic full scans
- Build a file index on first scan and use modification times to skip unchanged files
- Parallelize the recursive walks across different top-level directories

## Security Challenges

### Add False Positive Suppression

Build a `.credenum-ignore` file format that lets users mark known-safe findings (e.g., a test SSH key that's intentionally world-readable).

**Requirements:**
- Support path-based ignores (`~/.ssh/test_key`)
- Support pattern-based ignores (`*.test.kdbx`)
- Support category-based ignores (`[ssh] id_rsa_test`)
- The ignore file itself should be checked for proper permissions

### Add Integrity Checking

Hash credential files and compare against a known-good baseline. If a credential file's content hash changes without an expected rotation event, flag it as potentially tampered.

### Compliance Mapping

Map each finding type to specific compliance framework controls:
- SOC 2 CC6.1 (Logical and Physical Access Controls)
- PCI DSS 8.2 (Authentication Policies)
- CIS Controls 5.2 (Use Unique Passwords)
- NIST 800-53 IA-5 (Authenticator Management)

Output a compliance-focused report that shows which controls have findings.

## Getting Help

**Debugging the scanner:** Run with `--verbose` to see all scanned paths including modules with zero findings. This helps identify if a module is looking in the wrong directory or if the target path is incorrect.

**Debugging a collector:** Add temporary `echo` statements before submitting the finding. Nim's stdlib `echo` works in `{.push raises: [].}` files without wrapping in try/except because `echo` is treated specially by the compiler.

**Debugging the test suite:** Run `just test` for unit tests. If a specific test fails, the test output shows which `check` assertion failed and the expected vs actual values. For integration tests, `docker run --rm -it credenum-test bash` gives you a shell in the test container where you can run credenum manually.

**Understanding Nim:** If you're new to Nim, the key concepts that appear in this codebase are:
- Procedures (`proc`) are functions
- `result` is an implicit return variable (equivalent to assigning to the function name)
- `{.push raises: [].}` is a compiler pragma that enforces no-exception contracts
- `{.cast(raises: []).}` overrides the raises check for a specific block
- `seq[T]` is a dynamic array, `array[N, T]` is fixed-size
- `Option[T]` is Nim's Maybe/Optional type (from `std/options`)
- `Table[K, V]` is a hash map (from `std/tables`)
