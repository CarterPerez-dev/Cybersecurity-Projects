# ©AngelaMos | 2026
# apptoken.nim
#
# Application token and database credential collector
#
# Scans for credential exposure across desktop apps, databases,
# package registries, and infrastructure tools. Checks application
# data directories (Slack, Discord, VS Code). scanDbCredFiles
# inspects database credential files: .pgpass (PostgreSQL entry
# count), .my.cnf (MySQL password presence), .rediscli_auth (Redis),
# and .mongorc.js (MongoDB auth). scanDockerConfig checks
# .docker/config.json for registry authentication tokens. scanNetrc
# parses .netrc for machine entries with passwords. scanDevTokenFiles
# checks .npmrc for _authToken, .pypirc for passwords, and
# .config/gh/hosts.yml for GitHub CLI OAuth tokens.
# scanInfraTokenFiles checks Terraform Cloud credentials, Vault
# tokens, Helm repository passwords, and Rclone cloud storage
# configs. Severity escalates for world-readable files and files
# containing plaintext credentials.
#
# Connects to:
#   collectors/base.nim - expandHome, safeFileExists, safeDirExists,
#                          readFileContent, readFileLines, isWorldReadable,
#                          isGroupReadable, makeFinding, makeFindingWithCred,
#                          permissionSeverity
#   config.nim          - PgPass, MyCnf, RedisConf, MongoRc, DockerConfig,
#                          NetrcFile, NpmrcFile, PypircFile, GhCliHosts,
#                          TerraformCreds, VaultTokenFile, HelmRepos,
#                          RcloneConf, SlackDir, DiscordDir, VsCodeDir

{.push raises: [].}

import std/[strutils, tables, monotimes, times]
import ../types
import ../config
import base

type AppTarget = object
  path: string
  name: string
  description: string
  isDir: bool

proc scanAppDir(config: HarvestConfig, target: AppTarget, result: var CollectorResult) =
  let fullPath = expandHome(config, target.path)
  if target.isDir:
    if not safeDirExists(fullPath):
      return
    let sev = permissionSeverity(fullPath, isDir = true)
    result.findings.add(makeFinding(fullPath, target.description, catApptoken, sev))
  else:
    if not safeFileExists(fullPath):
      return
    let sev =
      if isWorldReadable(fullPath):
        svCritical
      elif isGroupReadable(fullPath):
        svHigh
      else:
        svMedium
    result.findings.add(makeFinding(fullPath, target.description, catApptoken, sev))

proc scanDbCredFiles(config: HarvestConfig, result: var CollectorResult) =
  let pgpassPath = expandHome(config, PgPass)
  if safeFileExists(pgpassPath):
    let lines = readFileLines(pgpassPath)
    var entryCount = 0
    for line in lines:
      if line.strip().len > 0 and not line.strip().startsWith("#"):
        inc entryCount

    let sev = if isWorldReadable(pgpassPath): svCritical else: svHigh

    var cred = Credential(
      source: pgpassPath,
      credType: "postgresql_credentials",
      preview: $entryCount & " database connection entries",
      metadata: initTable[string, string](),
    )
    cred.setMeta("entry_count", $entryCount)

    result.findings.add(
      makeFindingWithCred(
        pgpassPath,
        "PostgreSQL password file with " & $entryCount & " entries",
        catApptoken,
        sev,
        cred,
      )
    )

  let mycnfPath = expandHome(config, MyCnf)
  if safeFileExists(mycnfPath):
    let content = readFileContent(mycnfPath)
    let hasPassword = "password" in content.toLowerAscii()
    let sev =
      if isWorldReadable(mycnfPath):
        svCritical
      elif hasPassword:
        svHigh
      else:
        svMedium

    result.findings.add(
      makeFinding(
        mycnfPath,
        "MySQL configuration" & (if hasPassword: " (contains password)" else: ""),
        catApptoken,
        sev,
      )
    )

  let redisPath = expandHome(config, RedisConf)
  if safeFileExists(redisPath):
    let sev = if isWorldReadable(redisPath): svCritical else: svHigh
    result.findings.add(
      makeFinding(redisPath, "Redis CLI authentication file", catApptoken, sev)
    )

  let mongoPath = expandHome(config, MongoRc)
  if safeFileExists(mongoPath):
    let content = readFileContent(mongoPath)
    let hasCreds =
      "password" in content.toLowerAscii() or "auth" in content.toLowerAscii()
    let sev =
      if isWorldReadable(mongoPath):
        svCritical
      elif hasCreds:
        svHigh
      else:
        svMedium

    result.findings.add(
      makeFinding(
        mongoPath,
        "MongoDB RC file" & (if hasCreds: " (may contain credentials)" else: ""),
        catApptoken,
        sev,
      )
    )

proc scanNetrc(config: HarvestConfig, result: var CollectorResult) =
  let path = expandHome(config, NetrcFile)
  if not safeFileExists(path):
    return

  let content = readFileContent(path)
  let lines = content.splitLines()
  var machineCount = 0
  var hasPassword = false

  for line in lines:
    let stripped = line.strip()
    if stripped.toLowerAscii().startsWith("machine "):
      inc machineCount
    if "password " in stripped.toLowerAscii():
      hasPassword = true

  let sev =
    if isWorldReadable(path):
      svCritical
    elif hasPassword:
      svHigh
    else:
      svMedium

  var cred = Credential(
    source: path,
    credType: "netrc_credentials",
    preview: $machineCount & " machine entries",
    metadata: initTable[string, string](),
  )
  cred.setMeta("machines", $machineCount)
  cred.setMeta("has_password", $hasPassword)

  result.findings.add(
    makeFindingWithCred(
      path,
      "Netrc credential file with " & $machineCount & " entries",
      catApptoken,
      sev,
      cred,
    )
  )

proc scanDevTokenFiles(config: HarvestConfig, result: var CollectorResult) =
  let npmrcPath = expandHome(config, NpmrcFile)
  if safeFileExists(npmrcPath):
    let content = readFileContent(npmrcPath)
    let hasToken = "_authToken" in content or "_auth" in content
    let sev =
      if isWorldReadable(npmrcPath):
        svCritical
      elif hasToken:
        svHigh
      else:
        svInfo

    if hasToken:
      result.findings.add(
        makeFinding(npmrcPath, "npm registry authentication token", catApptoken, sev)
      )

  let pypircPath = expandHome(config, PypircFile)
  if safeFileExists(pypircPath):
    let content = readFileContent(pypircPath)
    let hasPassword = "password" in content.toLowerAscii()
    let sev =
      if isWorldReadable(pypircPath):
        svCritical
      elif hasPassword:
        svHigh
      else:
        svMedium

    result.findings.add(
      makeFinding(
        pypircPath,
        "PyPI configuration" & (if hasPassword: " (contains credentials)" else: ""),
        catApptoken,
        sev,
      )
    )

  let ghPath = expandHome(config, GhCliHosts)
  if safeFileExists(ghPath):
    let content = readFileContent(ghPath)
    let hasOauth = "oauth_token" in content.toLowerAscii()
    let sev =
      if isWorldReadable(ghPath):
        svCritical
      elif hasOauth:
        svHigh
      else:
        svMedium

    result.findings.add(makeFinding(ghPath, "GitHub CLI OAuth token", catApptoken, sev))

proc scanInfraTokenFiles(config: HarvestConfig, result: var CollectorResult) =
  let tfPath = expandHome(config, TerraformCreds)
  if safeFileExists(tfPath):
    let content = readFileContent(tfPath)
    let hasToken = "token" in content.toLowerAscii()
    let sev =
      if isWorldReadable(tfPath):
        svCritical
      elif hasToken:
        svHigh
      else:
        svMedium

    result.findings.add(
      makeFinding(tfPath, "Terraform Cloud API token", catApptoken, sev)
    )

  let vaultPath = expandHome(config, VaultTokenFile)
  if safeFileExists(vaultPath):
    let sev = if isWorldReadable(vaultPath): svCritical else: svHigh

    result.findings.add(
      makeFinding(vaultPath, "HashiCorp Vault token", catApptoken, sev)
    )

  let helmPath = expandHome(config, HelmRepos)
  if safeFileExists(helmPath):
    let content = readFileContent(helmPath)
    let hasPassword = "password" in content.toLowerAscii()
    let sev =
      if isWorldReadable(helmPath):
        svCritical
      elif hasPassword:
        svHigh
      else:
        svInfo

    if hasPassword:
      result.findings.add(
        makeFinding(helmPath, "Helm repository credentials", catApptoken, sev)
      )

  let rclonePath = expandHome(config, RcloneConf)
  if safeFileExists(rclonePath):
    let content = readFileContent(rclonePath)
    let hasCreds =
      "pass" in content.toLowerAscii() or "token" in content.toLowerAscii() or
      "key" in content.toLowerAscii()
    let sev =
      if isWorldReadable(rclonePath):
        svCritical
      elif hasCreds:
        svHigh
      else:
        svMedium

    result.findings.add(
      makeFinding(
        rclonePath,
        "Rclone cloud storage configuration" &
          (if hasCreds: " (contains credentials)" else: ""),
        catApptoken,
        sev,
      )
    )

proc scanDockerConfig(config: HarvestConfig, result: var CollectorResult) =
  let dockerPath = expandHome(config, DockerConfig)
  if not safeFileExists(dockerPath):
    return

  let content = readFileContent(dockerPath)
  let hasAuth = "\"auth\"" in content or "\"auths\"" in content
  let sev =
    if isWorldReadable(dockerPath):
      svCritical
    elif hasAuth:
      svHigh
    else:
      svMedium

  var cred = Credential(
    source: dockerPath,
    credType: "docker_registry_auth",
    preview: if hasAuth: "Registry authentication tokens present" else: "No auth data",
    metadata: initTable[string, string](),
  )

  result.findings.add(
    makeFindingWithCred(
      dockerPath,
      "Docker configuration" & (if hasAuth: " with registry auth tokens" else: ""),
      catApptoken,
      sev,
      cred,
    )
  )

proc collect*(config: HarvestConfig): CollectorResult =
  result = newCollectorResult("apptoken", catApptoken)
  let start = getMonoTime()

  let appTargets = [
    AppTarget(
      path: SlackDir,
      name: "Slack",
      description: "Slack desktop session data",
      isDir: true,
    ),
    AppTarget(
      path: DiscordDir,
      name: "Discord",
      description: "Discord desktop session data",
      isDir: true,
    ),
    AppTarget(
      path: VsCodeDir,
      name: "VS Code",
      description: "VS Code configuration directory",
      isDir: true,
    ),
    AppTarget(
      path: VsCodeUserSettings,
      name: "VS Code Settings",
      description: "VS Code user settings (may contain tokens)",
      isDir: false,
    ),
  ]

  for target in appTargets:
    scanAppDir(config, target, result)

  scanDbCredFiles(config, result)
  scanDockerConfig(config, result)
  scanNetrc(config, result)
  scanDevTokenFiles(config, result)
  scanInfraTokenFiles(config, result)

  let elapsed = getMonoTime() - start
  result.durationMs = elapsed.inMilliseconds
