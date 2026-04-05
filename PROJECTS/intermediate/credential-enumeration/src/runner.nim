# ©AngelaMos | 2026
# runner.nim

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
      modules: moduleNames
    ),
    results: results,
    summary: summary
  )
