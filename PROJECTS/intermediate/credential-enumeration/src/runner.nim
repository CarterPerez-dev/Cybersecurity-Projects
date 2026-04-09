# ©AngelaMos | 2026
# runner.nim
#
# Module dispatcher and report assembler
#
# Maps each Category enum value to its collector proc via getCollector,
# then runCollectors iterates the enabled modules from HarvestConfig,
# invokes each collector, collects results with monotonic timing, and
# builds the final Report with aggregated severity counts across all
# findings. The metadata timestamp is left empty for the caller
# (harvester.nim) to fill with wall-clock time.
#
# Connects to:
#   types.nim             - HarvestConfig, Report, CollectorResult, Severity
#   config.nim            - AppVersion, ModuleNames
#   collectors/ssh.nim    - ssh.collect
#   collectors/git.nim    - git.collect
#   collectors/cloud.nim  - cloud.collect
#   collectors/browser.nim - browser.collect
#   collectors/history.nim - history.collect
#   collectors/keyring.nim - keyring.collect
#   collectors/apptoken.nim - apptoken.collect

{.push raises: [].}

import std/[monotimes, times]
import types
import config
import collectors/ssh
import collectors/git
import collectors/cloud
import collectors/browser
import collectors/history
import collectors/keyring
import collectors/apptoken

proc getCollector(cat: Category): CollectorProc =
  case cat
  of catBrowser: browser.collect
  of catSsh: ssh.collect
  of catCloud: cloud.collect
  of catHistory: history.collect
  of catKeyring: keyring.collect
  of catGit: git.collect
  of catApptoken: apptoken.collect

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

  result = Report(
    metadata: ReportMetadata(
      timestamp: "",
      target: config.targetDir,
      version: AppVersion,
      durationMs: elapsed.inMilliseconds,
      modules: moduleNames,
    ),
    results: results,
    summary: summary,
  )
