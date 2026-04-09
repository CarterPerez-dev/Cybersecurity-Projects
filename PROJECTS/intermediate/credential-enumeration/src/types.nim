# ©AngelaMos | 2026
# types.nim
#
# Domain types for the credential enumeration tool
#
# Defines the core type hierarchy: Severity (info through critical) and
# Category (browser, ssh, cloud, history, keyring, git, apptoken) as
# string-backed enums. Finding captures a discovered credential exposure
# with path, severity, description, optional Credential detail,
# permissions, modification time, and file size. CollectorResult groups
# findings from a single module with timing and error tracking. Report
# aggregates all collector results with metadata (timestamp, target,
# version, duration, module list) and a severity summary array.
# HarvestConfig holds CLI-parsed runtime options. CollectorProc defines
# the nimcall signature all collector modules implement.
#
# Connects to:
#   config.nim           - constructs HarvestConfig via defaultConfig
#   collectors/base.nim  - makeFinding/makeFindingWithCred build Findings
#   output/json.nim      - serializes Report/Finding/Credential to JSON
#   output/terminal.nim  - renders Report/Finding with severity badges

{.push raises: [].}

import std/[options, tables]

type
  Severity* = enum
    svInfo = "info"
    svLow = "low"
    svMedium = "medium"
    svHigh = "high"
    svCritical = "critical"

  Category* = enum
    catBrowser = "browser"
    catSsh = "ssh"
    catCloud = "cloud"
    catHistory = "history"
    catKeyring = "keyring"
    catGit = "git"
    catApptoken = "apptoken"

  Credential* = object
    source*: string
    credType*: string
    preview*: string
    metadata*: Table[string, string]

  Finding* = object
    path*: string
    category*: Category
    severity*: Severity
    description*: string
    credential*: Option[Credential]
    permissions*: string
    modified*: string
    size*: int64

  CollectorResult* = object
    name*: string
    category*: Category
    findings*: seq[Finding]
    durationMs*: int64
    errors*: seq[string]

  ReportMetadata* = object
    timestamp*: string
    target*: string
    version*: string
    durationMs*: int64
    modules*: seq[string]

  Report* = object
    metadata*: ReportMetadata
    results*: seq[CollectorResult]
    summary*: array[Severity, int]

  OutputFormat* = enum
    fmtTerminal = "terminal"
    fmtJson = "json"
    fmtBoth = "both"

  HarvestConfig* = object
    targetDir*: string
    enabledModules*: seq[Category]
    excludePatterns*: seq[string]
    outputFormat*: OutputFormat
    outputPath*: string
    dryRun*: bool
    quiet*: bool
    verbose*: bool

  CollectorProc* = proc(config: HarvestConfig): CollectorResult {.nimcall, raises: [].}
