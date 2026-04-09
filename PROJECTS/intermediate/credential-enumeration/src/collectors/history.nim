# ©AngelaMos | 2026
# history.nim
#
# Shell history and environment file collector
#
# Scans for secrets leaked through shell history and .env files.
# scanHistoryFile reads up to 50000 lines from each history file
# (.bash_history, .zsh_history, .fish_history, .sh_history,
# .python_history) and matches lines against two pattern sets:
# secret assignments (KEY=, SECRET=, TOKEN=, PASSWORD=, etc. with
# export prefix detection) capped at 20 reported findings, and
# sensitive commands (curl with auth headers, wget with passwords,
# mysql -p, psql password, sshpass) capped at 10. Redacts matched
# values using redactLine to avoid exposing actual secrets.
# scanEnvFiles recursively walks subdirectories up to depth 5 looking
# for .env, .env.local, .env.production, and .env.staging files,
# skipping hidden dirs and common vendored paths.
#
# Connects to:
#   collectors/base.nim - expandHome, safeFileExists, readFileLines,
#                          isWorldReadable, isGroupReadable, makeFinding,
#                          makeFindingWithCred, matchesExclude, redactValue
#   config.nim          - HistoryFiles, SecretPatterns,
#                          HistoryCommandPatterns, EnvFilePatterns

{.push raises: [].}

import std/[os, strutils, tables, monotimes, times]
import ../types
import ../config
import base

const
  MaxHistoryLines = 50000
  MaxEnvDepth = 5

proc redactLine*(line: string): string =
  let eqIdx = line.find('=')
  if eqIdx < 0:
    return line
  let key = line[0 ..< eqIdx]
  let valStart = eqIdx + 1
  if valStart >= line.len:
    return line
  let value = line[valStart .. ^1].strip()
  let cleanValue =
    if (value.startsWith("\"") and value.endsWith("\"")) or
        (value.startsWith("'") and value.endsWith("'")):
      value[1 ..< ^1]
    else:
      value
  result = key & "=" & redactValue(cleanValue, 4)

proc matchesSecretPattern*(line: string): bool =
  let upper = line.toUpperAscii()
  for pattern in SecretPatterns:
    if pattern in upper:
      if "export " in line.toLowerAscii() or
          line.strip().startsWith(pattern.split("=")[0]):
        return true

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
    elif pattern in lower:
      return true

proc scanHistoryFile(
    config: HarvestConfig, fileName: string, result: var CollectorResult
) =
  let path = expandHome(config, fileName)
  if not safeFileExists(path):
    return

  let lines = readFileLines(path, MaxHistoryLines)
  var secretCount = 0
  var commandCount = 0

  for i, line in lines:
    let stripped = line.strip()
    if stripped.len == 0:
      continue

    if matchesSecretPattern(stripped):
      inc secretCount
      if secretCount <= 20:
        var cred = Credential(
          source: path,
          credType: "history_secret",
          preview: redactLine(stripped),
          metadata: initTable[string, string](),
        )
        cred.setMeta("line_region", $(i + 1))

        result.findings.add(
          makeFindingWithCred(
            path,
            "Secret in shell history (line ~" & $(i + 1) & ")",
            catHistory,
            svHigh,
            cred,
          )
        )
    elif matchesCommandPattern(stripped):
      inc commandCount
      if commandCount <= 10:
        let preview =
          if stripped.len > 60:
            stripped[0 ..< 60] & "..."
          else:
            stripped

        result.findings.add(
          makeFinding(
            path, "Sensitive command in history: " & preview, catHistory, svMedium
          )
        )

  if secretCount > 20:
    result.findings.add(
      makeFinding(
        path,
        $secretCount & " total secret patterns found (showing first 20)",
        catHistory,
        svInfo,
      )
    )

proc walkForEnv(
    dir: string, depth: int, excludePatterns: seq[string], result: var CollectorResult
) =
  if depth > MaxEnvDepth:
    return
  try:
    for kind, path in walkDir(dir):
      if matchesExclude(path, excludePatterns):
        continue
      case kind
      of pcFile:
        let name = path.extractFilename()
        for envPattern in EnvFilePatterns:
          if name == envPattern:
            let sev =
              if isWorldReadable(path):
                svCritical
              elif isGroupReadable(path):
                svHigh
              else:
                svMedium
            result.findings.add(
              makeFinding(path, "Environment file: " & name, catHistory, sev)
            )
            break
      of pcDir:
        let dirName = path.extractFilename()
        if dirName.startsWith(".") and dirName notin [".config", ".local"]:
          continue
        if dirName in
            ["node_modules", "vendor", ".git", "__pycache__", ".venv", "venv", ".cache"]:
          continue
        walkForEnv(path, depth + 1, excludePatterns, result)
      else:
        discard
  except CatchableError as e:
    result.errors.add("Error scanning for env files in " & dir & ": " & e.msg)

proc scanEnvFiles(config: HarvestConfig, result: var CollectorResult) =
  walkForEnv(config.targetDir, 0, config.excludePatterns, result)

proc collect*(config: HarvestConfig): CollectorResult =
  result = newCollectorResult("history", catHistory)
  let start = getMonoTime()

  for histFile in HistoryFiles:
    scanHistoryFile(config, histFile, result)

  scanEnvFiles(config, result)

  let elapsed = getMonoTime() - start
  result.durationMs = elapsed.inMilliseconds
