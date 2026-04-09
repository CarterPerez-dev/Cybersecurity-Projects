# ©AngelaMos | 2026
# git.nim
#
# Git credential store and token collector
#
# Scans for Git-related credential exposure in three areas.
# scanGitCredentials reads ~/.git-credentials for plaintext URL
# entries containing embedded passwords (severity high, critical if
# world-readable). scanGitConfig parses ~/.gitconfig and
# ~/.config/git/config for credential helper configuration, flagging
# the "store" helper as medium severity since it persists plaintext.
# scanTokenPatterns searches Git config files for GitHub personal
# access token prefixes (ghp_, gho_, ghu_, ghs_, ghr_) and GitLab
# token prefixes (glpat-), reporting detected tokens with redacted
# previews.
#
# Connects to:
#   collectors/base.nim - expandHome, safeFileExists, readFileContent,
#                          readFileLines, isWorldReadable, getPermsString,
#                          makeFinding, makeFindingWithCred, redactValue
#   config.nim          - GitCredentials, GitConfig, GitConfigLocal,
#                          GitHubTokenPatterns, GitLabTokenPatterns

{.push raises: [].}

import std/[strutils, tables, monotimes, times]
import ../types
import ../config
import base

proc scanGitCredentials(config: HarvestConfig, result: var CollectorResult) =
  let credPath = expandHome(config, GitCredentials)
  if not safeFileExists(credPath):
    return

  let lines = readFileLines(credPath)
  var credCount = 0

  for line in lines:
    let stripped = line.strip()
    if stripped.len > 0 and "://" in stripped:
      inc credCount

  if credCount == 0:
    return

  var cred = Credential(
    source: credPath,
    credType: "git_plaintext_credentials",
    preview: $credCount & " stored credentials",
    metadata: initTable[string, string](),
  )
  cred.setMeta("count", $credCount)
  cred.setMeta("permissions", getPermsString(credPath))

  let sev = if isWorldReadable(credPath): svCritical else: svHigh

  result.findings.add(
    makeFindingWithCred(
      credPath,
      "Plaintext Git credential store with " & $credCount & " entries",
      catGit,
      sev,
      cred,
    )
  )

proc scanGitConfig(config: HarvestConfig, result: var CollectorResult) =
  let paths = [expandHome(config, GitConfig), expandHome(config, GitConfigLocal)]

  for path in paths:
    if not safeFileExists(path):
      continue

    let content = readFileContent(path)
    if content.len == 0:
      continue

    let lines = content.splitLines()
    var inCredentialSection = false
    var helperValue = ""

    for line in lines:
      let stripped = line.strip()
      if stripped.startsWith("["):
        inCredentialSection = stripped.toLowerAscii().startsWith("[credential")

      if inCredentialSection and stripped.toLowerAscii().startsWith("helper"):
        let parts = stripped.split("=", maxsplit = 1)
        if parts.len == 2:
          helperValue = parts[1].strip()

    if helperValue.len > 0:
      let sev = if helperValue == "store": svMedium else: svInfo
      result.findings.add(
        makeFinding(
          path, "Git credential helper configured: " & helperValue, catGit, sev
        )
      )

proc scanTokenPatterns(config: HarvestConfig, result: var CollectorResult) =
  let configPaths = [expandHome(config, GitConfig), expandHome(config, GitConfigLocal)]

  for path in configPaths:
    if not safeFileExists(path):
      continue

    let content = readFileContent(path)
    if content.len == 0:
      continue

    for pattern in GitHubTokenPatterns:
      let idx = content.find(pattern)
      if idx >= 0:
        let tokenStart = content[idx ..< min(idx + 20, content.len)]
        var cred = Credential(
          source: path,
          credType: "github_token",
          preview: redactValue(tokenStart, 8),
          metadata: initTable[string, string](),
        )
        result.findings.add(
          makeFindingWithCred(
            path, "GitHub personal access token detected", catGit, svHigh, cred
          )
        )
        break

    for pattern in GitLabTokenPatterns:
      let idx = content.find(pattern)
      if idx >= 0:
        let tokenStart = content[idx ..< min(idx + 20, content.len)]
        var cred = Credential(
          source: path,
          credType: "gitlab_token",
          preview: redactValue(tokenStart, 8),
          metadata: initTable[string, string](),
        )
        result.findings.add(
          makeFindingWithCred(
            path, "GitLab personal access token detected", catGit, svHigh, cred
          )
        )
        break

proc collect*(config: HarvestConfig): CollectorResult =
  result = newCollectorResult("git", catGit)
  let start = getMonoTime()

  scanGitCredentials(config, result)
  scanGitConfig(config, result)
  scanTokenPatterns(config, result)

  let elapsed = getMonoTime() - start
  result.durationMs = elapsed.inMilliseconds
