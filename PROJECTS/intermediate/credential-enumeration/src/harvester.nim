# ©AngelaMos | 2026
# harvester.nim
#
# CLI entry point and argument parser
#
# Parses command-line flags via std/parseopt (--target, --modules,
# --exclude, --format, --output, --dry-run, --quiet, --verbose,
# --help, --version) into a HarvestConfig. Dispatches to renderDryRun
# for --dry-run preview, otherwise calls runCollectors to execute all
# enabled modules, stamps the report with a UTC ISO 8601 timestamp,
# and routes output to renderTerminal, renderJson, or both. Exits
# with code 1 if any critical or high severity findings are detected,
# 0 otherwise.
#
# Connects to:
#   config.nim          - defaultConfig, AppVersion, ModuleNames/Descriptions
#   types.nim           - HarvestConfig, OutputFormat, Severity, Report
#   runner.nim          - runCollectors orchestrates module execution
#   output/terminal.nim - renderTerminal for ANSI output
#   output/json.nim     - renderJson for structured output

{.push raises: [].}

import std/[parseopt, strutils, os, times]
import types
import config
import runner
import output/terminal
import output/json

proc printHelp() =
  try:
    stdout.writeLine ColorBold & BinaryName & ColorReset & " v" & AppVersion
    stdout.writeLine ""
    stdout.writeLine "  Post-access credential exposure detection for Linux systems"
    stdout.writeLine ""
    stdout.writeLine ColorBold & "USAGE:" & ColorReset
    stdout.writeLine "  " & BinaryName & " [flags]"
    stdout.writeLine ""
    stdout.writeLine ColorBold & "FLAGS:" & ColorReset
    stdout.writeLine "  --target <path>       Target home directory (default: current user)"
    stdout.writeLine "  --modules <list>      Comma-separated modules: " &
      ModuleNames[catBrowser] & "," & ModuleNames[catSsh] & "," & ModuleNames[catCloud] &
      "," & ModuleNames[catHistory] & "," & ModuleNames[catKeyring] & "," &
      ModuleNames[catGit] & "," & ModuleNames[catApptoken]
    stdout.writeLine "  --exclude <patterns>  Comma-separated path patterns to skip"
    stdout.writeLine "  --format <fmt>        Output format: terminal, json, both (default: terminal)"
    stdout.writeLine "  --output <path>       Write JSON output to file"
    stdout.writeLine "  --dry-run             List scan targets without reading files"
    stdout.writeLine "  --quiet               Suppress banner, show findings only"
    stdout.writeLine "  --verbose             Show all scanned paths including empty modules"
    stdout.writeLine "  --help                Show this help"
    stdout.writeLine "  --version             Show version"
    stdout.writeLine ""
    stdout.writeLine ColorBold & "EXAMPLES:" & ColorReset
    stdout.writeLine "  " & BinaryName & "                           Scan current user"
    stdout.writeLine "  " & BinaryName & " --format json             JSON output"
    stdout.writeLine "  " & BinaryName &
      " --modules ssh,git,cloud   Scan specific modules"
    stdout.writeLine "  " & BinaryName & " --target /home/victim     Scan another user"
    stdout.writeLine "  " & BinaryName & " --dry-run                 Preview scan paths"
    stdout.writeLine ""
  except CatchableError:
    discard

proc printVersion() =
  try:
    stdout.writeLine BinaryName & " " & AppVersion
  except CatchableError:
    discard

proc parseModules*(input: string): seq[Category] =
  result = @[]
  let parts = input.split(",")
  for part in parts:
    let name = part.strip().toLowerAscii()
    for cat in Category:
      if ModuleNames[cat] == name:
        result.add(cat)
        break

proc parseCli(): HarvestConfig =
  result = defaultConfig()

  var parser = initOptParser(
    commandLineParams(),
    shortNoVal = {'d', 'q', 'v', 'h'},
    longNoVal = @["dry-run", "quiet", "verbose", "help", "version"],
  )

  while true:
    parser.next()
    case parser.kind
    of cmdEnd:
      break
    of cmdShortOption, cmdLongOption:
      case parser.key.toLowerAscii()
      of "target", "t":
        result.targetDir = parser.val
      of "modules", "m":
        result.enabledModules = parseModules(parser.val)
      of "exclude", "e":
        result.excludePatterns = parser.val.split(",")
      of "format", "f":
        case parser.val.toLowerAscii()
        of "json":
          result.outputFormat = fmtJson
        of "both":
          result.outputFormat = fmtBoth
        else:
          result.outputFormat = fmtTerminal
      of "output", "o":
        result.outputPath = parser.val
      of "dry-run", "dry", "d":
        result.dryRun = true
      of "quiet", "q":
        result.quiet = true
      of "verbose", "v":
        result.verbose = true
      of "help", "h":
        printHelp()
        quit(0)
      of "version":
        printVersion()
        quit(0)
      else:
        discard
    of cmdArgument:
      discard

proc renderDryRun(conf: HarvestConfig) =
  try:
    stdout.writeLine ColorBold & "Dry run — scan targets:" & ColorReset
    stdout.writeLine ""
    for cat in conf.enabledModules:
      stdout.writeLine "  " & ColorCyan & ModuleNames[cat] & ColorReset & ": " &
        ModuleDescriptions[cat]
    stdout.writeLine ""
    stdout.writeLine ColorDim & "  Target: " & conf.targetDir & ColorReset
    stdout.writeLine ""
  except CatchableError:
    discard

proc main() =
  let conf = parseCli()

  if conf.dryRun:
    renderDryRun(conf)
    quit(0)

  var report = runCollectors(conf)

  {.cast(raises: []).}:
    report.metadata.timestamp = now().utc.format("yyyy-MM-dd'T'HH:mm:ss'Z'")

  case conf.outputFormat
  of fmtTerminal:
    renderTerminal(report, conf.quiet, conf.verbose)
  of fmtJson:
    renderJson(report, conf.outputPath)
  of fmtBoth:
    renderTerminal(report, conf.quiet, conf.verbose)
    renderJson(report, conf.outputPath)

  var hasHighSeverity = false
  for sev in [svCritical, svHigh]:
    if report.summary[sev] > 0:
      hasHighSeverity = true
      break

  if hasHighSeverity:
    quit(1)
  else:
    quit(0)

when isMainModule:
  main()
