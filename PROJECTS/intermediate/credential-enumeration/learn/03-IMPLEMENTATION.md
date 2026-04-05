# 03-IMPLEMENTATION.md

# Implementation

This document walks through the actual code: how each component works, why it's structured the way it is, and what patterns to look for when reading or extending the codebase.

## File Structure

```
src/
├── harvester.nim          # Entry point — CLI parsing, main orchestration
├── runner.nim             # Collector dispatch — maps categories to collectors
├── types.nim              # Type definitions — Finding, Report, Severity, etc
├── config.nim             # Constants — every path, pattern, threshold, color
├── collectors/
│   ├── base.nim           # Shared utils — file ops, permissions, factories
│   ├── browser.nim        # Firefox + Chromium credential stores
│   ├── ssh.nim            # SSH keys, config, authorized_keys
│   ├── git.nim            # .git-credentials, tokens, config helpers
│   ├── cloud.nim          # AWS, GCP, Azure, Kubernetes
│   ├── history.nim        # Shell history, command patterns, .env files
│   ├── keyring.nim        # GNOME, KDE, KeePass, pass, Bitwarden
│   └── apptoken.nim       # DB creds, dev tokens, infra tokens, Docker
└── output/
    ├── terminal.nim       # Color terminal with box drawing
    └── json.nim           # Structured JSON output
```

## The Zero-Exception Foundation

Every source file opens with:

```nim
{.push raises: [].}
```

This Nim pragma tells the compiler: no procedure in this file may propagate an exception. Any call to a function that might raise (file I/O, string parsing, etc.) must be wrapped in try/except within this file. The compiler enforces this at compile time and will reject code that could propagate an uncaught exception.

This matters for a security tool because crashing mid-scan means partial results, missed findings, and unreliable output. The `{.push raises: [].}` guarantee means that if the tool compiles, it will not crash from unhandled exceptions during a scan.

Where an operation genuinely can't avoid exceptions (like calling `readFile`), the pattern is:

```nim
proc readFileContent*(path: string): string =
  try:
    result = readFile(path)
  except CatchableError:
    result = ""
```

The exception is caught immediately and converted to a safe default. This pattern repeats throughout `base.nim` for every filesystem operation.

## Entry Point: harvester.nim

### CLI Parsing

The `parseCli` function builds a `HarvestConfig` from command-line arguments using Nim's stdlib `parseopt`:

```nim
proc parseCli(): HarvestConfig =
  result = defaultConfig()

  var parser = initOptParser(
    commandLineParams(),
    shortNoVal = {'d', 'q', 'v', 'h'},
    longNoVal = @["dry-run", "quiet", "verbose", "help", "version"]
  )
```

The `shortNoVal` and `longNoVal` parameters tell the parser which flags don't take values. Without this, `--quiet --format json` would try to parse `--format` as the value of `--quiet`.

The parser loop uses `case parser.key.toLowerAscii()` for case-insensitive matching, so `--Target`, `--target`, and `--TARGET` all work. Each recognized flag updates the result config. Unrecognized flags are silently discarded (`else: discard`).

### Module Parsing

The `parseModules` function converts comma-separated module names to a sequence of `Category` values:

```nim
proc parseModules*(input: string): seq[Category] =
  result = @[]
  let parts = input.split(",")
  for part in parts:
    let name = part.strip().toLowerAscii()
    for cat in Category:
      if ModuleNames[cat] == name:
        result.add(cat)
        break
```

This iterates through every `Category` enum value and checks if the module name matches. Unknown module names are silently skipped. The `ModuleNames` array in config.nim maps each Category to its string name, so the mapping is defined in one place.

### Main Orchestration

The `main` function is the control flow hub:

```nim
proc main() =
  let conf = parseCli()

  if conf.dryRun:
    renderDryRun(conf)
    quit(0)

  var report = runCollectors(conf)
  report.metadata.timestamp = now().utc.format("yyyy-MM-dd'T'HH:mm:ss'Z'")

  case conf.outputFormat
  of fmtTerminal: renderTerminal(report, conf.quiet, conf.verbose)
  of fmtJson: renderJson(report, conf.outputPath)
  of fmtBoth:
    renderTerminal(report, conf.quiet, conf.verbose)
    renderJson(report, conf.outputPath)

  var hasHighSeverity = false
  for sev in [svCritical, svHigh]:
    if report.summary[sev] > 0:
      hasHighSeverity = true
      break

  if hasHighSeverity: quit(1) else: quit(0)
```

The timestamp is set after the scan completes (not before) so it reflects when results were produced. The `{.cast(raises: []).}` pragma is used around the time formatting because `now()` and `format()` could technically raise, but in practice never do with valid format strings. The cast tells the compiler "I know what I'm doing here."

The exit code check only looks at CRITICAL and HIGH. MEDIUM, LOW, and INFO findings don't trigger a non-zero exit. This keeps the tool useful in CI pipelines where you want to fail on genuine exposures but not on informational notes.

## Runner: runner.nim

### Collector Dispatch

The `getCollector` function is the routing table:

```nim
proc getCollector(cat: Category): CollectorProc =
  case cat
  of catBrowser: browser.collect
  of catSsh: ssh.collect
  of catCloud: cloud.collect
  of catHistory: history.collect
  of catKeyring: keyring.collect
  of catGit: git.collect
  of catApptoken: apptoken.collect
```

Nim's case statement on an enum is exhaustive: if you add a new `Category` value without adding a case branch, the compiler will reject the code. This compile-time guarantee prevents the "forgot to wire up the new module" class of bug.

The return type `CollectorProc` is a function pointer type defined in types.nim:

```nim
CollectorProc = proc(config: HarvestConfig): CollectorResult {.nimcall, raises: [].}
```

The `{.nimcall, raises: [].}` calling convention means the function uses Nim's native calling convention and cannot raise exceptions. This contract is enforced at the type level.

### Result Aggregation

The `runCollectors` function iterates enabled modules, calls each collector, and builds the report:

```nim
proc runCollectors*(config: HarvestConfig): Report =
  let start = getMonoTime()
  var results: seq[CollectorResult] = @[]
  var moduleNames: seq[string] = @[]

  for cat in config.enabledModules:
    moduleNames.add(ModuleNames[cat])
    let collector = getCollector(cat)
    let res = collector(config)
    results.add(res)

  let elapsed = getMonoTime() - start

  var summary: array[Severity, int]
  for res in results:
    for finding in res.findings:
      inc summary[finding.severity]
```

The use of `getMonoTime()` (monotonic clock) instead of `now()` for timing is important. Monotonic time is immune to clock adjustments and NTP corrections. If the system clock changes during a scan, `getMonoTime()` still gives an accurate duration.

The summary array uses `Severity` as the index type, so `summary[svCritical]` directly gives the count of critical findings. The `inc` proc increments in-place without allocation.

## Base Utilities: collectors/base.nim

### Permission Inspection

The permission checking functions use POSIX `stat` directly:

```nim
proc getPermsString*(path: string): string =
  var statBuf: Stat
  try:
    if stat(path.cstring, statBuf) == 0:
      let mode = statBuf.st_mode and 0o7777
      result = "0" & toOct(mode.int, 3)
    else:
      result = "unknown"
  except CatchableError:
    result = "unknown"
```

The `stat` syscall retrieves file metadata from the kernel. The mode field contains the permission bits in the lower 12 bits (mask `0o7777`). The `toOct` function converts to octal representation. The string "0" prefix produces the familiar format: "0600", "0644", etc.

The world-readable and group-readable checks extract specific bits:

```nim
proc isWorldReadable*(path: string): bool =
  var statBuf: Stat
  try:
    if stat(path.cstring, statBuf) == 0:
      result = (statBuf.st_mode.int and WorldReadBit) != 0
  except CatchableError:
    discard
```

`WorldReadBit` is the constant `0o004` from config.nim. The bitwise AND isolates just the "others read" bit. If it's non-zero, the file is world-readable.

### Severity from Permissions

The `permissionSeverity` function encapsulates the permission-to-severity logic:

```nim
proc permissionSeverity*(path: string, isDir: bool = false): Severity =
  let perms = getNumericPerms(path)
  if perms < 0:
    return svInfo
  if (perms and WorldReadBit) != 0:
    return svCritical
  if (perms and GroupReadBit) != 0:
    return svMedium
  let expected = if isDir: OwnerOnlyDirPerms else: OwnerOnlyFilePerms
  if perms > expected:
    return svLow
  result = svInfo
```

Negative perms means the stat call failed (file doesn't exist or we can't read metadata). World-readable is always CRITICAL. Group-readable is MEDIUM. Anything looser than the expected permissions (0600 for files, 0700 for directories) is LOW. Correct permissions are INFO.

### Finding Factories

The two factory functions construct `Finding` objects with consistent metadata:

```nim
proc makeFinding*(
  path: string,
  description: string,
  category: Category,
  severity: Severity
): Finding =
  Finding(
    path: path,
    category: category,
    severity: severity,
    description: description,
    credential: none(Credential),
    permissions: getPermsString(path),
    modified: getModifiedTime(path),
    size: getFileSizeBytes(path)
  )
```

Every finding automatically gets the current permissions, modification time, and file size of the target path. Collectors don't need to remember to look these up. The `makeFindingWithCred` variant takes an additional `Credential` parameter wrapped in `some()`.

### Value Redaction

The `redactValue` function shows the first N characters and replaces the rest:

```nim
proc redactValue*(value: string, showChars: int = 4): string =
  if value.len <= showChars:
    result = "*".repeat(value.len)
  else:
    result = value[0 ..< showChars] & "*".repeat(value.len - showChars)
```

For values shorter than or equal to `showChars`, the entire value is masked. For longer values, the first 4 characters are shown. This gives enough context to identify the credential type (e.g., "ghp_" for GitHub tokens, "AKIA" for AWS keys) without exposing the full secret.

## Collector Implementations

### SSH Collector: ssh.nim

The SSH collector has four sub-scanners: `scanKeys`, `scanConfig`, `scanAuthorizedKeys`, and `scanKnownHosts`.

**Key scanning** is the most complex sub-scanner. It walks the `~/.ssh/` directory, reads each file, and checks if it starts with a PEM header:

```nim
proc isPrivateKey*(content: string): bool =
  for header in SshKeyHeaders:
    if content.startsWith(header):
      return true
```

`SshKeyHeaders` in config.nim contains all five PEM header formats. The check uses `startsWith` rather than `contains` because PEM headers must be at the start of the file.

Once a private key is found, encryption detection checks for known markers:

```nim
proc isEncrypted*(content: string): bool =
  for marker in SshEncryptedMarkers:
    if marker in content:
      return true
```

The severity calculation combines encryption status and permissions:

```nim
if not encrypted:
  sev = svHigh
else:
  sev = svInfo

if perms >= 0 and (perms and WorldReadBit) != 0:
  sev = svCritical
elif perms >= 0 and (perms and GroupReadBit) != 0:
  if sev < svHigh:
    sev = svHigh
```

An unencrypted key starts at HIGH. An encrypted key starts at INFO. Then permissions override upward: world-readable forces CRITICAL regardless of encryption. Group-readable escalates to at least HIGH.

**Config scanning** looks for weak settings:

```nim
if stripped.toLowerAscii().startsWith("passwordauthentication yes"):
  weakSettings.add("PasswordAuthentication enabled")

if stripped.toLowerAscii().startsWith("stricthostkeychecking no"):
  weakSettings.add("StrictHostKeyChecking disabled")
```

These are MEDIUM findings because they weaken the SSH connection security but don't directly expose credentials.

### Browser Collector: browser.nim

**Firefox scanning** starts by reading `profiles.ini` to find profile directories:

```nim
let lines = readFileLines(profilesIniPath)
var profiles: seq[string] = @[]
var currentPath = ""

for line in lines:
  let stripped = line.strip()
  if stripped.startsWith("[Profile"):
    if currentPath.len > 0:
      profiles.add(currentPath)
    currentPath = ""

  if stripped.toLowerAscii().startsWith("path="):
    currentPath = stripped.split("=", maxsplit = 1)[1]
```

This is a minimal INI parser that extracts the `Path=` value from each `[Profile*]` section. The `maxsplit = 1` is important because profile paths themselves might contain `=` characters.

For each profile, the scanner checks three credential files:

```nim
let credFiles = [
  (FirefoxLoginsFile, "Firefox stored logins database"),
  (FirefoxCookiesDb, "Firefox cookies database"),
  (FirefoxKeyDb, "Firefox key database")
]

for (fileName, desc) in credFiles:
  let filePath = profileDir / fileName
  if safeFileExists(filePath):
    let sev = if isWorldReadable(filePath): svCritical
              elif isGroupReadable(filePath): svHigh
              else: svMedium
```

Note that browser credential files are always at least MEDIUM severity even with correct permissions. This is because the files themselves contain sensitive data (encrypted passwords, session cookies) that could be exfiltrated and attacked offline.

**Chromium scanning** follows a similar pattern but handles multiple browser variants (Chrome, Brave, Vivaldi, Chromium) and numbered profiles (`Default`, `Profile 1`, `Profile 2`, etc.).

### Cloud Collector: cloud.nim

**AWS scanning** demonstrates the most detailed credential analysis. It reads the credentials file line by line, counting profiles and classifying key types:

```nim
if stripped.toLowerAscii().startsWith("aws_access_key_id"):
  let parts = stripped.split("=", maxsplit = 1)
  if parts.len == 2:
    let keyVal = parts[1].strip()
    if keyVal.startsWith(AwsStaticKeyPrefix):
      inc staticKeys
    elif keyVal.startsWith(AwsSessionKeyPrefix):
      inc sessionKeys
```

Static keys (prefix `AKIA`) are long-lived and escalate severity to HIGH. Session keys (prefix `ASIA`) are temporary and less dangerous. The distinction matters for remediation prioritization.

**Kubernetes scanning** parses the kubeconfig YAML to count contexts and users, and to detect authentication methods:

```nim
if "token:" in stripped:
  hasTokenAuth = true
if "client-certificate-data:" in stripped:
  hasCertAuth = true
```

Token authentication is HIGH severity because bearer tokens provide direct API access. Certificate authentication is noted but not escalated because certificates are harder to use in isolation.

### History Collector: history.nim

**Secret pattern matching** checks for known environment variable patterns:

```nim
proc matchesSecretPattern*(line: string): bool =
  let upper = line.toUpperAscii()
  for pattern in SecretPatterns:
    if pattern in upper:
      if "export " in line.toLowerAscii() or
         line.strip().startsWith(pattern.split("=")[0]):
        return true
```

The double check (pattern in upper AND either `export` or starts with key name) prevents false positives. `PATH=/usr/bin` contains `=` but doesn't match `KEY=`, `TOKEN=`, or `PASSWORD=`. The function requires both the pattern match and evidence that it's an actual variable assignment.

**Command pattern matching** uses a custom glob-like matcher:

```nim
proc matchesCommandPattern*(line: string): bool =
  let lower = line.toLowerAscii()
  for pattern in HistoryCommandPatterns:
    let parts = pattern.split(".*")
    if parts.len >= 2:
      var allFound = true
      var searchFrom = 0
      for part in parts:
        let idx = lower.find(part, start = searchFrom)
        if idx < 0:
          allFound = false
          break
        searchFrom = idx + part.len
      if allFound:
        return true
```

Patterns like `"curl.*-h.*authoriz"` are split on `".*"` and each segment is searched sequentially. The `searchFrom` index ensures segments match in order. This implements a basic regex-like matching without pulling in a regex library.

**History line limits** prevent resource exhaustion:

```nim
const MaxHistoryLines = 50000
```

A developer who's been using the same shell for years might have hundreds of thousands of history entries. Scanning all of them would be slow and memory-intensive. The 50,000 line cap covers the most recent history (where secrets are most likely still valid) while keeping resource usage bounded.

**Recursive .env scanning** uses depth-limited directory walking:

```nim
proc walkForEnv(
  dir: string,
  depth: int,
  excludePatterns: seq[string],
  result: var CollectorResult
) =
  if depth > MaxEnvDepth:
    return
```

The depth limit of 5 and directory exclusions (`node_modules`, `vendor`, `.git`, `__pycache__`, `.venv`, `.cache`) keep the recursive walk fast. Without these limits, scanning a directory with deeply nested `node_modules` would take minutes.

### Keyring Collector: keyring.nim

The keyring collector scans five different credential stores. The KeePass scanner is notable for its recursive file search:

```nim
proc walkForKdbx(
  dir: string,
  depth: int,
  excludePatterns: seq[string],
  result: var CollectorResult
) =
  if depth > 5:
    return
```

KeePass database files (`.kdbx`) can be stored anywhere in the home directory, not just in a standard location. The recursive walk finds them wherever they are, while the depth limit and directory exclusions prevent runaway scanning.

The pass (password-store) scanner counts GPG-encrypted entries:

```nim
for kind, path in walkDir(passDir, relative = false):
  if kind == pcFile and path.endsWith(".gpg"):
    inc entryCount
```

The count of entries tells the user (or attacker) how many credentials are stored, even though the entries themselves are GPG-encrypted and not directly readable.

### App Token Collector: apptoken.nim

The app token collector uses a generic `AppTarget` type to handle application data directories:

```nim
type
  AppTarget = object
    path: string
    name: string
    description: string
    isDir: bool
```

This lets the collector define scan targets as data rather than code:

```nim
let appTargets = [
  AppTarget(path: SlackDir, name: "Slack",
            description: "Slack desktop session data", isDir: true),
  AppTarget(path: DiscordDir, name: "Discord",
            description: "Discord desktop session data", isDir: true),
  ...
]
```

Each target is checked with the same logic: does it exist, and what are its permissions? The `isDir` flag determines whether to use file or directory permission checking.

The database credential scanning is more detailed. For PostgreSQL's `.pgpass`:

```nim
let lines = readFileLines(pgpassPath)
var entryCount = 0
for line in lines:
  if line.strip().len > 0 and not line.strip().startsWith("#"):
    inc entryCount
```

Non-comment, non-empty lines are counted as connection entries. The count goes into the credential metadata so the output can show "PostgreSQL password file with 3 entries" rather than just "PostgreSQL password file found."

## Output Rendering

### Terminal Renderer: terminal.nim

The terminal renderer handles the complexity of aligning text in box-drawn tables when strings contain invisible ANSI color codes and multi-byte UTF-8 characters.

**Visual length calculation** strips ANSI escape sequences and counts only visible characters:

```nim
proc visualLen(s: string): int =
  var i = 0
  while i < s.len:
    if s[i] == '\e':
      while i < s.len and s[i] != 'm':
        inc i
      if i < s.len:
        inc i
    elif (s[i].ord and 0xC0) == 0x80:
      inc i
    else:
      inc result
      inc i
```

ANSI escapes start with `\e` and end at `m`. UTF-8 continuation bytes have the pattern `10xxxxxx` (the `0xC0` mask checks the top two bits). Only non-escape, non-continuation bytes count as visible characters. This is necessary because a string like `"\e[31mERROR\e[0m"` is 5 visible characters ("ERROR") but 15 bytes long.

**Box line writing** uses this visual length to pad each line to exactly `BoxWidth` characters:

```nim
proc writeBoxLine(content: string) =
  try:
    stdout.write content
    let vLen = visualLen(content)
    let pad = BoxWidth - vLen - 1
    if pad > 0:
      stdout.write " ".repeat(pad)
    stdout.writeLine BoxVertical
  except CatchableError:
    discard
```

The `-1` accounts for the closing `BoxVertical` character. This produces perfectly aligned box borders regardless of how many color codes or Unicode characters are in the content.

**Severity badges** combine color and label:

```nim
proc sevBadge(sev: Severity): string =
  SeverityColors[sev] & ColorBold & " " & SeverityLabels[sev] & " " & ColorReset
```

The `SeverityColors` and `SeverityLabels` arrays are indexed by the `Severity` enum, so looking up the color for a severity is a direct array access.

### JSON Renderer: json.nim

The JSON renderer converts each type to a `JsonNode` with recursive functions:

```nim
proc findingToJson(f: Finding): JsonNode =
  result = newJObject()
  {.cast(raises: []).}:
    result["path"] = newJString(f.path)
    result["category"] = newJString($f.category)
    result["severity"] = newJString($f.severity)
    result["description"] = newJString(f.description)
    result["permissions"] = newJString(f.permissions)
    result["modified"] = newJString(f.modified)
    result["size"] = newJInt(f.size)
    if f.credential.isSome:
      result["credential"] = credentialToJson(f.credential.get())
```

The `{.cast(raises: []).}` block is needed because Nim's JSON operations technically can raise, but in practice won't when building objects from known-good data. The cast is scoped to just the JSON construction block.

The `$` operator on enum values produces the string representation ("browser", "critical", etc.) defined by the enum value assignments in types.nim.

## Testing Strategy

### Unit Tests: test_all.nim

The unit tests cover pure functions that don't require filesystem state:

**Redaction tests** verify boundary conditions:

```nim
suite "redactValue":
  test "short value fully redacted":
    check redactValue("abc", 4) == "***"

  test "value longer than showChars":
    check redactValue("mysecret", 4) == "myse****"
```

**Key detection tests** validate all five key formats plus negative cases:

```nim
suite "isPrivateKey":
  test "OpenSSH key":
    check isPrivateKey("-----BEGIN OPENSSH PRIVATE KEY-----\ndata")
  test "public key rejected":
    check isPrivateKey("-----BEGIN PUBLIC KEY-----\ndata") == false
```

**Pattern matching tests** cover both true positives and true negatives:

```nim
suite "matchesSecretPattern":
  test "export with KEY=":
    check matchesSecretPattern("export API_KEY=some_value")
  test "non-secret assignment":
    check matchesSecretPattern("export PATH=/usr/bin") == false
```

**Permission severity tests** use non-existent paths to test the error handling path:

```nim
suite "permissionSeverity":
  test "returns svInfo for unreadable path":
    check permissionSeverity("/nonexistent/path/abc123") == svInfo
```

**Module parsing tests** verify the CLI-to-Category conversion including edge cases:

```nim
suite "parseModules":
  test "single module":
    check parseModules("ssh") == @[catSsh]
  test "unknown module ignored":
    check parseModules("fake,nonexistent").len == 0
```

Running tests: `just test` compiles and runs the test suite.

### Integration Tests: Docker

The Docker-based integration test creates a controlled environment with known credential files and validates that the scanner detects all of them.

**The Dockerfile** uses a multi-stage build:

Stage 1 (builder): Compiles credenum from source using the official Nim Alpine image, producing a static binary.

Stage 2 (runtime): Ubuntu 24.04 with a `testuser` account. The `planted/` directory is copied into the test user's home directory, creating realistic credential files across all 7 categories. Permissions are explicitly set to create specific severity scenarios (e.g., `chmod 0644` on the unprotected SSH key to make it world-readable).

**The validation script** runs credenum against the test user's home directory and checks for expected findings:

```bash
OUTPUT=$(credenum --target /home/testuser --format json 2>&1) || true

check "SSH unprotected private key"    "no passphrase"
check "AWS credentials with static keys" "static keys"
check "Firefox stored logins"          "Firefox stored logins"
check "History secret pattern"         "Secret in shell history"
```

Each `check` function searches the JSON output for an expected string. The validation covers all 7 collector categories with 30+ individual checks.

Running integration tests: `just docker-test` builds the Docker image and runs the validation.

## Build System

### Nim Compiler Configuration: config.nims

The `config.nims` file configures the Nim compiler without command-line flags:

```nim
switch("mm", "orc")
```

ORC (Overflowing Reference Counting) is Nim's modern memory management. It combines reference counting with a cycle collector, providing deterministic cleanup without a traditional garbage collector pause.

**Musl static linking:**

```nim
when defined(musl):
  var muslGcc = findExe("musl-gcc")
  if muslGcc.len > 0:
    switch("gcc.exe", muslGcc)
    switch("gcc.linkerexe", muslGcc)
  switch("passL", "-static")
```

When `-d:musl` is passed, the compiler uses musl-gcc instead of the system gcc, producing a fully static binary with no glibc dependency. This binary runs on any Linux system regardless of glibc version.

**Cross-compilation:**

```nim
when defined(crossX86):
  switch("passC", "-target x86_64-linux-musl")
  switch("passL", "-target x86_64-linux-musl")
  switch("os", "linux")
  switch("cpu", "amd64")
```

The zigcc integration uses Zig's C compiler backend as a cross-compilation toolchain. Passing target triples through `-passC` and `-passL` produces binaries for different architectures without needing a full cross-compilation sysroot.

### Justfile Build Targets

The Justfile organizes commands by group:

**dev** group: `build` (debug), `run` (build + execute), `scan` (build + scan current user), `check` (type check without compilation)

**prod** group: `release` (optimized), `release-static` (musl), `release-small` (musl + UPX), `build-x86` (cross-compile x86_64), `build-arm64` (cross-compile ARM64)

**test** group: `test` (unit tests), `docker-build` (build test image), `docker-test` (full integration test)

**lint** group: `fmt` (format with nph), `fmt-check` (verify formatting)

The Justfile uses shell variables for DRY configuration:

```just
bin     := "bin/credenum"
src     := "src/harvester.nim"
```

All build targets reference these variables, so changing the binary name or entry point requires editing one line.

## Code Organization Principles

**One file per concern.** Each collector is its own file. Types are separate from config. Output renderers are separate from each other. This means you can understand the browser collector by reading `browser.nim` alone.

**Constants separate from logic.** All paths, patterns, thresholds, colors, and labels live in `config.nim`. Collectors import `config` to get their scan targets. This separation means you can audit every credential path the tool checks by reading one file.

**Shared utilities in base, not duplicated.** Permission checking, file reading, finding construction, and redaction are in `base.nim`. No collector reimplements file stat calls or finding construction.

**Types define the contract.** The `CollectorProc` type ensures every collector has the same signature. The `Report` type defines what output renderers receive. The `Severity` enum's ordering determines comparison behavior. These types are the architecture, enforced by the compiler.

## Extending the Code

### Adding a New Collector

1. Add a new `Category` value in `types.nim` (e.g., `catContainer = "container"`)
2. Add module name and description to arrays in `config.nim`
3. Create `collectors/container.nim`:
   - Start with `{.push raises: [].}`
   - Import `../types`, `../config`, `base`
   - Implement `proc collect*(config: HarvestConfig): CollectorResult`
   - Use `newCollectorResult`, `makeFinding`, `makeFindingWithCred` from base.nim
4. Import and route in `runner.nim`:
   - `import collectors/container`
   - Add `of catContainer: container.collect` to the case statement
5. Add test fixtures in `tests/docker/planted/` and checks in `validate.sh`

### Adding a New Scan Target to an Existing Collector

1. Add the path constant to `config.nim` (e.g., `PodmanConfig* = ".config/containers/auth.json"`)
2. Add scanning logic to the relevant collector (e.g., `apptoken.nim`)
3. Add a test fixture and validation check

### Adding a New Output Format

1. Add a value to `OutputFormat` in `types.nim`
2. Create `output/sarif.nim` with a render proc
3. Add the case branch and CLI flag handling in `harvester.nim`

## Dependencies

The project uses only Nim's standard library. No external packages are required.

| Import | Purpose |
|--------|---------|
| `std/parseopt` | CLI argument parsing |
| `std/os` | File operations, path manipulation, home directory |
| `std/posix` | POSIX stat for permission inspection |
| `std/strutils` | String operations (split, strip, find, contains) |
| `std/times` | Timestamp formatting |
| `std/monotimes` | Performance timing |
| `std/options` | Optional[Credential] for findings |
| `std/tables` | Credential metadata key-value pairs |
| `std/json` | JSON output construction |
| `std/unittest` | Test framework |

Zero external dependencies means no supply chain risk, no version conflicts, and no network access needed to build. The entire project compiles from a fresh Nim installation.

## Next Steps

- Read [04-CHALLENGES.md](./04-CHALLENGES.md) for extension ideas ranging from new collectors to remediation automation
- Try adding a new scan target to an existing collector. Start with something simple like adding Docker Compose credential detection to the apptoken collector
