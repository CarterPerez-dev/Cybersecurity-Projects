# ©AngelaMos | 2026
# types.nim

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
