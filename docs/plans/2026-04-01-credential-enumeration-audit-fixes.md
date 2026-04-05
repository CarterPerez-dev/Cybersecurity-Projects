# Credential Enumeration Audit

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> to implement this plan task-by-task.

**Goal:** Address all gaps identified in the audit.

**Architecture:** All changes are modifications to existing files unless noted.

**Tech Stack:** Nim 2.2+, Docker, Bash (Justfile)

---

## Impression

Solid architecture for a Nim CLI tool — clean type hierarchy, consistent
`{.push raises: [].}` discipline, well-structured collector pattern. The
bones are genuinely good. But two of the command-detection patterns silently
match nothing, the terminal box renderer computes stats it never prints,
and the only test mechanism (Docker) can't actually build because the
Justfile passes the wrong build context. The tool scans 7 credential
categories competently but misses several high-value targets (.netrc,
npm/pip tokens, Terraform, Vault) that a real post-access operator would
check first.

## Project Assessment

**Type:** Rule-based credential detection CLI tool (post-access)
**Primary Axis:** Completeness — weighted 65/35 over code quality
**Why:** A scanner's value is directly proportional to what it catches.
Missing a credential category is a harder failure than a rendering bug.

## Findings

### Finding 1: Docker test build context is wrong — entire test pipeline broken
**Severity:** CRITICAL
**Axis:** Code Quality
**Files:** Justfile:88-89, tests/docker/Dockerfile:1-12

**Issue:** The Justfile recipe `docker-build` runs
`docker build -t credenum-test tests/docker`, setting the build context to
`tests/docker/`. But the Dockerfile's first stage copies `src/`, `config.nims`,
and `credential-enumeration.nimble` from the build context root — none of which
exist under `tests/docker/`. The build fails immediately with
"COPY failed: file not found in build context."

**Proof:** The Dockerfile contains:
```dockerfile
COPY src/ src/
COPY config.nims .
COPY credential-enumeration.nimble .
```
With context `tests/docker/`, Docker looks for `tests/docker/src/`,
`tests/docker/config.nims`, `tests/docker/credential-enumeration.nimble`.
None exist — `find tests/docker/ -name "config.nims"` returns nothing.
The only test mechanism for this project has never run successfully with
this Justfile recipe.

**Proof Check:** Confidence: HIGH — Docker build context semantics are deterministic;
this is not a maybe.

**Fix:**
`Justfile:88-89` — change the docker-build recipe to use the project root as context:
```just
[group('test')]
docker-build:
    docker build -t credenum-test -f tests/docker/Dockerfile .
```
And update `docker-test` accordingly (it depends on docker-build, so no change needed
there since it just `docker run`s the image).

**Test:**
```bash
just docker-build
```

---

### Finding 2: matchesCommandPattern has case mismatch — 2/7 patterns are dead code
**Severity:** CRITICAL
**Axis:** Code Quality
**Files:** src/collectors/history.nim:38-54, src/config.nim:120-128

**Issue:** `matchesCommandPattern` lowercases the input line (`line.toLowerAscii()`)
then searches for pattern fragments that contain uppercase characters. Two patterns
are affected:

- `"curl.*-H.*[Aa]uthoriz"` splits into `["curl", "-H", "[Aa]uthoriz"]` —
  `-H` (uppercase) will never be found in a lowercased string, and
  `[Aa]uthoriz` is treated as a literal (not a character class)
- `"wget.*--header.*[Aa]uthoriz"` splits into `["wget", "--header", "[Aa]uthoriz"]` —
  `[Aa]uthoriz` is literal and will never appear in real history

This means `curl -H "Authorization: Bearer ..."` commands in shell history
are silently missed — one of the most common credential-leaking patterns.

**Proof:** Trace through `matchesCommandPattern` with input
`curl -H "Authorization: Bearer token" https://api.example.com`:
1. `lower` = `curl -h "authorization: bearer token" https://api.example.com`
2. Pattern `"curl.*-H.*[Aa]uthoriz"` → parts = `["curl", "-H", "[Aa]uthoriz"]`
3. `lower.find("curl")` → found at 0
4. `lower.find("-H")` → NOT FOUND (lowercase string has `-h`, not `-H`)
5. `allFound = false` → returns false

The pattern never matches. The planted test data in `.bash_history` line 4
has `curl -H "Authorization: ..."` which should trigger this pattern but
the validate.sh check labeled "Sensitive command" passes only because
OTHER patterns (like `sshpass`, `mysql.*-p`) produce matches.

**Proof Check:** Confidence: HIGH — Nim's `find` is case-sensitive by default;
this is deterministic.

**Fix:**
`src/config.nim:120-128` — lowercase all pattern fragments:
```nim
HistoryCommandPatterns* = [
  "curl.*-h.*authoriz",
  "curl.*-u ",
  "wget.*--header.*authoriz",
  "wget.*--password",
  "mysql.*-p",
  "psql.*password",
  "sshpass"
]
```

**Test:**
Add a Docker test assertion that specifically validates curl -H Authorization
detection. After fix, run `just docker-test`.

---

### Finding 3: Module header stats computed but never rendered
**Severity:** MAJOR
**Axis:** Code Quality
**Files:** src/output/terminal.nim:40-57

**Issue:** `renderModuleHeader` computes a `stats` string containing
the finding count and duration, but the padding calculation
`padLen - stats.len + stats.len` simplifies to just `padLen` — then
writes padding spaces without ever writing `stats` to stdout.
The finding count and per-module duration are silently dropped from output.

**Proof:** The arithmetic:
```nim
let stats = $findingCount & " findings" & ColorDim & " (" & $durationMs & "ms)" & ColorReset
let padLen = 76 - name.len - desc.len - 5
if padLen > 0:
  stdout.write " ".repeat(padLen - stats.len + stats.len)  # = " ".repeat(padLen)
stdout.writeLine " " & BoxVertical
```
`stats` is never passed to `stdout.write`. The line is equivalent to
`stdout.write " ".repeat(padLen)` followed by the box border — no stats
anywhere.

**Proof Check:** Confidence: HIGH — the variable is computed and never
appears in any write call in the function.

**Fix:**
`src/output/terminal.nim:51-55` — compute visual width (excluding ANSI codes),
pad to fill the box, then write stats:
```nim
proc visualLen(s: string): int =
  var i = 0
  while i < s.len:
    if s[i] == '\e':
      while i < s.len and s[i] != 'm':
        inc i
      inc i
    else:
      inc result
      inc i

proc renderModuleHeader(name: string, desc: string, findingCount: int, durationMs: int64) =
  try:
    stdout.writeLine boxLine(78)
    stdout.write BoxVertical & " "
    stdout.write ColorBold & ColorCyan
    stdout.write name.toUpperAscii()
    stdout.write ColorReset
    stdout.write ColorDim
    stdout.write " " & Arrow & " " & desc
    stdout.write ColorReset

    let stats = $findingCount & " findings" & ColorDim & " (" & $durationMs & "ms)" & ColorReset
    let usedWidth = 2 + name.len + 3 + desc.len
    let statsVisual = visualLen(stats)
    let padLen = 78 - usedWidth - statsVisual - 2
    if padLen > 0:
      stdout.write " ".repeat(padLen)
    stdout.write stats
    stdout.writeLine " " & BoxVertical
    stdout.writeLine boxMid(78)
  except CatchableError:
    discard
```

**Test:**
```bash
just run --target /tmp | head -20
```
Verify module headers show "N findings (Xms)" right-aligned.

---

### Finding 4: Terminal box right-border alignment broken for variable content
**Severity:** MAJOR
**Axis:** Code Quality
**Files:** src/output/terminal.nim:60-84, 98-126

**Issue:** `renderFinding` writes descriptions and paths of arbitrary length
then appends `" " & BoxVertical` with no padding to reach column 78. Long
descriptions push past the box. Short ones leave the right border floating
at different positions. Same issue in `renderSummary` — hardcoded
`" ".repeat(69)` and `" ".repeat(20)` assume fixed content widths that
vary with finding counts, module counts, and durations.

**Proof:** A finding with path `/home/user/.config/google-chrome/Default/Login Data`
(49 chars) plus permissions `[0644]` plus modified timestamp is ~90+ chars of
content in a 78-char box. The right `BoxVertical` gets pushed to column ~95.
A finding with path `/home/user/.pgpass` (18 chars) leaves the right border
at ~column 50.

**Proof Check:** Confidence: HIGH — the code has zero width calculation before
writing the trailing BoxVertical.

**Fix:**
Create a `padWrite` helper that calculates visual width of content written so
far and pads to fill the 78-char box before writing the closing border.
Apply it to `renderFinding`, `renderSummary`, and `renderModuleErrors`.
Truncate content that would exceed box width.

In `src/output/terminal.nim`, add the `visualLen` proc from Finding 3
(shared), then refactor each line that writes content + BoxVertical:
```nim
proc padToBox(content: string, boxWidth: int = 78) =
  let vLen = visualLen(content)
  let pad = boxWidth - vLen - 1
  if pad > 0:
    stdout.write " ".repeat(pad)
  stdout.writeLine BoxVertical
```

Then each finding line becomes:
```nim
var line = BoxVertical & " " & sevBadge(f.severity) & " " & f.description
stdout.write line
padToBox(line)
```

Apply this pattern consistently to all content rows in the terminal renderer.

**Test:**
```bash
just docker-test
```
Visual inspection of terminal output — all right borders should align at column 78.

---

### Finding 5: scanGitCredentials reports svHigh for empty credential files
**Severity:** MAJOR
**Axis:** Code Quality
**Files:** src/collectors/git.nim:11-39

**Issue:** If `.git-credentials` exists but is empty or contains no valid URLs,
`credCount` stays at 0 but the function still creates a finding with
"Plaintext Git credential store with 0 entries" at severity svHigh
(or svCritical if world-readable). An empty file is not a high-severity
credential exposure.

**Proof:** Trace through `scanGitCredentials` with an empty `.git-credentials`:
1. `safeFileExists` returns true
2. `readFileLines` returns `@[]`
3. Loop runs zero iterations, `credCount = 0`
4. Code falls through to create credential and finding with `svHigh`
5. Report shows "Plaintext Git credential store with 0 entries" as HIGH

**Proof Check:** Confidence: HIGH — there is no guard checking `credCount > 0`
before creating the finding.

**Fix:**
`src/collectors/git.nim` — add early return after counting:
```nim
if credCount == 0:
  return
```
Insert after the for-loop that counts credentials (after line 22), before
the credential/finding construction.

**Test:**
Create an empty `.git-credentials` file, run scanner, verify no git finding
appears.

---

### Finding 6: `just test` references non-existent test_all.nim
**Severity:** MAJOR
**Axis:** Code Quality
**Files:** Justfile:84-85

**Issue:** The Justfile `test` recipe runs `nim c -r tests/test_all.nim`,
but this file does not exist. There are no unit tests in the project.
The only testing is Docker-based integration testing (validate.sh), which
itself is broken (Finding 1).

**Proof:** `test -f tests/test_all.nim` returns non-zero. The `tests/`
directory contains only `docker/`.

**Proof Check:** Confidence: HIGH — file does not exist.

**Fix:**
Create `tests/test_all.nim` with unit tests for each collector's core logic.
At minimum, test:
- `isPrivateKey` with various key headers
- `isEncrypted` with encrypted/unencrypted markers
- `matchesSecretPattern` with positive and negative cases
- `matchesCommandPattern` (after fixing Finding 2) with all 7 patterns
- `redactValue` edge cases
- `permissionSeverity` logic
- `parseModules` from CLI parsing

These should be fast, in-process tests that don't require Docker or
real credential files.

**Test:**
```bash
just test
```

---

### Finding 7: Missing credential categories — .netrc, npm/pip tokens, Terraform, Vault, GitHub CLI
**Severity:** MAJOR
**Axis:** Completeness
**Files:** src/config.nim, src/collectors/apptoken.nim

**Issue:** The tool covers 7 categories but misses several high-value
credential stores that a post-access operator would check:

| Missing Target | Path | Why It Matters |
|---|---|---|
| `.netrc` | `~/.netrc` | Universal HTTP auth store; Heroku, Artifactory, many tools |
| `.npmrc` | `~/.npmrc` | npm registry auth tokens (`_authToken=`) |
| `.pypirc` | `~/.pypirc` | PyPI upload tokens |
| GitHub CLI | `~/.config/gh/hosts.yml` | GitHub OAuth tokens |
| Terraform | `~/.terraform.d/credentials.tfrc.json` | Terraform Cloud API tokens |
| Vault | `~/.vault-token` | HashiCorp Vault root/user tokens |
| `~/.config/helm/repositories.yaml` | Helm chart repo credentials |
| `~/.config/rclone/rclone.conf` | Cloud storage credentials (S3, GCS, etc.) |

Industry comparison: LaZagne (closest post-access tool) covers 20+
credential categories on Linux alone. `truffleHog` detects 700+ secret
patterns. This tool's 7 categories leave real coverage gaps.

**Proof:** `grep -r "netrc\|npmrc\|pypirc\|vault-token\|terraform\|gh/hosts" src/`
returns zero matches.

**Proof Check:** Confidence: HIGH — the files are either scanned or they're not.

**Fix:**
Add constants to `src/config.nim`:
```nim
const
  NetrcFile* = ".netrc"
  NpmrcFile* = ".npmrc"
  PypircFile* = ".pypirc"
  GhCliHosts* = ".config/gh/hosts.yml"
  TerraformCreds* = ".terraform.d/credentials.tfrc.json"
  VaultTokenFile* = ".vault-token"
  HelmRepos* = ".config/helm/repositories.yaml"
  RcloneConf* = ".config/rclone/rclone.conf"
```

Add scanning logic to `src/collectors/apptoken.nim` — each is a simple
file-exists-and-check-contents pattern, consistent with existing
`scanDbCredFiles` approach. `.netrc` deserves content parsing (look for
`password` or `login` tokens). `.npmrc` should check for `_authToken=`.
`.pypirc` should check for `password` under `[pypi]` section.

**Test:**
Add planted files to `tests/docker/planted/` and assertions to `validate.sh`.

---

### Finding 8: matchesExclude uses substring matching, not glob patterns
**Severity:** MINOR
**Axis:** Code Quality
**Files:** src/collectors/base.nim:90-94

**Issue:** `matchesExclude` checks `if pattern in path` — plain substring.
An exclude pattern of `"env"` would exclude `/home/user/.venv/something`,
`/home/user/environment/data`, and the intended `.env` file. The CLI help
says `--exclude <patterns>` suggesting glob behavior, but the implementation
is substring containment.

**Proof:** `matchesExclude("/home/user/.venv/lib/site.py", @["env"])`
returns `true`, excluding a Python virtualenv file that has nothing to do
with environment secrets.

**Proof Check:** Confidence: HIGH — `in` is Nim's substring containment
operator for strings.

**Fix:**
`src/collectors/base.nim:90-94` — use `std/os.extractFilename` and simple
glob matching, or at minimum document that patterns are substrings. Better
fix: use Nim's `std/strutils.contains` with path-segment awareness:
```nim
proc matchesExclude*(path: string, patterns: seq[string]): bool =
  let name = path.extractFilename()
  for pattern in patterns:
    if pattern in name or pattern in path.splitPath().head:
      return true
```

Or implement basic glob support with `*` matching.

**Test:**
Unit test that `.venv/lib/site.py` is NOT excluded by pattern `".env"`.

---

### Finding 9: JSON renderJson silently discards file-write errors
**Severity:** MINOR
**Axis:** Code Quality
**Files:** src/output/json.nim:72-85

**Issue:** When `--output <path>` specifies an invalid path (read-only dir,
nonexistent parent), `writeFile` throws, the exception is caught and
discarded. The JSON is then also written to stdout, but if stdout is
redirected and also fails, both errors are silently swallowed. The user
gets zero indication that their requested output file was not created.

**Proof:** Run `credenum --format json --output /root/nope.json` as
non-root — the file write fails silently, output goes only to stdout.
If stdout is piped to a broken pipe, both writes fail and the user
sees nothing.

**Proof Check:** Confidence: MEDIUM — the stdout fallback usually works,
so the practical impact is limited to the file path case.

**Fix:**
`src/output/json.nim:77-80` — write a warning to stderr on file write failure:
```nim
except CatchableError as e:
  try:
    stderr.writeLine "Warning: could not write to " & outputPath & ": " & e.msg
  except CatchableError:
    discard
```

**Test:**
```bash
just run --format json --output /dev/full 2>&1 | grep "Warning"
```

---

### Finding 10: redactLine strips leading quote but keeps trailing quote
**Severity:** MINOR
**Axis:** Code Quality
**Files:** src/collectors/history.nim:15-28

**Issue:** `redactLine` strips a leading `"` or `'` from the value via
`value[1 .. ^1]`, but `^1` is the last index in Nim (inclusive), so
this removes only the first character. Input `"secret"` becomes
`secret"` — the trailing quote survives into the redacted preview.

**Proof:** Input line `export API_KEY="mysecret"`:
1. `eqIdx` = 14 (position of `=`)
2. `value` = `"mysecret"` (after strip)
3. `value.startsWith("\"")` → true
4. `cleanValue` = `value[1 .. ^1]` = `mysecret"` (trailing quote kept)
5. `redactValue("mysecret\"", 4)` = `myse****"`

**Proof Check:** Confidence: HIGH — `^1` is the last character in Nim slice
notation; this is deterministic.

**Fix:**
`src/collectors/history.nim:24-26`:
```nim
let cleanValue = if (value.startsWith("\"") and value.endsWith("\"")) or
                    (value.startsWith("'") and value.endsWith("'")):
  value[1 ..< ^1]
else:
  value
```

Note: `^1` in `[1 ..< ^1]` excludes the last character (half-open range).

**Test:**
Unit test: `redactLine("export KEY=\"secret\"")` should produce `KEY=secr**`
with no trailing quote.

---

### Finding 11: isRelative computed but unused in Firefox profile parsing
**Severity:** MINOR
**Axis:** Code Quality
**Files:** src/collectors/browser.nim:11-48

**Issue:** The `scanFirefox` proc parses `IsRelative=0` from profiles.ini
and stores it in `isRelative`, but this variable is never read. Profile
path resolution uses `profile.startsWith("/")` instead. The variable is
dead code from an abandoned design path.

**Proof:** `isRelative` is set on lines 23 and 37, but never appears in
any conditional or expression after the parsing loop.

**Proof Check:** Confidence: HIGH — grep for `isRelative` in browser.nim
shows only assignments, zero reads.

**Fix:**
`src/collectors/browser.nim` — remove the `isRelative` variable entirely
(lines 23, 37). The `startsWith("/")` check on line 43 is sufficient for
Linux path detection.

**Test:**
```bash
just check
```
Verify compilation succeeds with no warnings about unused variable.

---

### Finding 12: Azure scanner adds directory finding unconditionally
**Severity:** MINOR
**Axis:** Code Quality
**Files:** src/collectors/cloud.nim:140-144

**Issue:** `scanAzure` always adds an svInfo finding for the Azure CLI
directory after checking for specific token files. If token cache findings
were already added, this creates redundant noise. If no tokens were found,
a bare directory finding at svInfo adds very little value.

**Proof:** If `~/.azure/` exists with `accessTokens.json`, the output shows:
1. "Azure token cache" at svMedium — useful
2. "Azure CLI configuration directory" at svInfo — noise, adds nothing

**Proof Check:** Confidence: MEDIUM — it's noise, not incorrect data. Could
argue the directory finding is useful as a "this user has Azure CLI installed"
signal, but only if no token files were found.

**Fix:**
`src/collectors/cloud.nim:140-144` — only add the directory finding if no
token files were found:
```nim
if result.findings.len == 0 or
   result.findings[^1].category != catCloud:
  result.findings.add(makeFinding(
    azDir,
    "Azure CLI configuration directory",
    catCloud, svInfo
  ))
```

Better: track whether any Azure-specific findings were added and only emit
the directory finding as a fallback.

**Test:**
Docker test — verify Azure directory finding only appears when no token
findings exist.

---

## Self-Interrogation

Looking at these 12 findings as a whole:

- **Did I miss a dimension?** The tool has no rate-limiting or size-limiting on
  file reads. `readFileContent` reads entire files into memory. A malicious
  (or just large) `.bash_history` of several GB would cause OOM. But the
  history scanner has `MaxHistoryLines = 50000` via `readFileLines`, which
  mitigates this for its use case. Other collectors reading full files
  (git config, kubeconfig) are typically small. Not worth a finding.

- **Are any findings weak?** Finding 12 (Azure directory) is the weakest —
  it's a UX preference, not a bug. Keeping it as MINOR is appropriate.
  Finding 11 (dead variable) is real but trivial. Everything MAJOR and above
  is solid.

- **Completeness check:** The tool has 7 modules covering the major
  categories but Finding 7 lists 8 specific credential stores that any
  practitioner would expect. The `.netrc` omission alone is notable since
  it's been the standard Unix credential store since the 1980s.

## Summary

**Total Findings:** 12 (2 critical, 5 major, 5 minor)
**Code Quality Findings:** 11
**Completeness Findings:** 1
