# ©AngelaMos | 2026
# cloud.nim
#
# Cloud provider configuration collector
#
# Scans for credential exposure across four cloud platforms. scanAws
# parses ~/.aws/credentials for profile counts, static keys (AKIA
# prefix), and session keys (ASIA prefix), then checks ~/.aws/config
# for SSO and MFA configuration. scanGcp inspects application default
# credentials for service account vs user type and walks the gcloud
# config directory for additional service account key files. scanAzure
# checks for access token and MSAL token cache files. scanKubernetes
# parses ~/.kube/config to count contexts and users, detecting token-
# based and certificate-based authentication methods. Severity
# escalates for static keys, service accounts, token auth, and
# world-readable files.
#
# Connects to:
#   collectors/base.nim - expandHome, safeFileExists, safeDirExists,
#                          readFileContent, readFileLines, isWorldReadable,
#                          makeFinding, makeFindingWithCred, permissionSeverity
#   config.nim          - AwsCredentials, AwsConfig, AwsStaticKeyPrefix,
#                          GcpConfigDir, GcpAppDefaultCreds, AzureDir,
#                          AzureAccessTokens, KubeConfig, KubeContextMarker

{.push raises: [].}

import std/[os, strutils, tables, monotimes, times]
import ../types
import ../config
import base

proc scanAws(config: HarvestConfig, result: var CollectorResult) =
  let credPath = expandHome(config, AwsCredentials)
  let configPath = expandHome(config, AwsConfig)

  if safeFileExists(credPath):
    let content = readFileContent(credPath)
    let lines = content.splitLines()
    var profileCount = 0
    var staticKeys = 0
    var sessionKeys = 0

    for line in lines:
      let stripped = line.strip()
      if stripped.startsWith("["):
        inc profileCount
      if stripped.toLowerAscii().startsWith("aws_access_key_id"):
        let parts = stripped.split("=", maxsplit = 1)
        if parts.len == 2:
          let keyVal = parts[1].strip()
          if keyVal.startsWith(AwsStaticKeyPrefix):
            inc staticKeys
          elif keyVal.startsWith(AwsSessionKeyPrefix):
            inc sessionKeys

    var sev = svMedium
    if staticKeys > 0:
      sev = svHigh
    if isWorldReadable(credPath):
      sev = svCritical

    var cred = Credential(
      source: credPath,
      credType: "aws_credentials",
      preview: $profileCount & " profiles, " & $staticKeys & " static keys",
      metadata: initTable[string, string](),
    )
    cred.setMeta("profiles", $profileCount)
    cred.setMeta("static_keys", $staticKeys)
    cred.setMeta("session_keys", $sessionKeys)

    result.findings.add(
      makeFindingWithCred(
        credPath,
        "AWS credentials file: " & $profileCount & " profiles, " & $staticKeys &
          " static keys, " & $sessionKeys & " session keys",
        catCloud,
        sev,
        cred,
      )
    )

  if safeFileExists(configPath):
    let lines = readFileLines(configPath)
    var profileCount = 0
    var hasSso = false
    var hasMfa = false

    for line in lines:
      let stripped = line.strip()
      if stripped.startsWith("["):
        inc profileCount
      if "sso_" in stripped.toLowerAscii():
        hasSso = true
      if "mfa_serial" in stripped.toLowerAscii():
        hasMfa = true

    var desc = "AWS config: " & $profileCount & " profiles"
    if hasSso:
      desc &= ", SSO configured"
    if hasMfa:
      desc &= ", MFA configured"

    result.findings.add(makeFinding(configPath, desc, catCloud, svInfo))

proc scanGcp(config: HarvestConfig, result: var CollectorResult) =
  let gcpDir = expandHome(config, GcpConfigDir)
  let adcPath = expandHome(config, GcpAppDefaultCreds)

  if safeFileExists(adcPath):
    let content = readFileContent(adcPath)
    let isServiceAccount = GcpServiceAccountPattern in content.toLowerAscii()
    let sev = if isServiceAccount: svHigh else: svMedium

    var cred = Credential(
      source: adcPath,
      credType: "gcp_credentials",
      preview: if isServiceAccount: "Service account key" else: "User credentials",
      metadata: initTable[string, string](),
    )
    let credTypeStr = if isServiceAccount: "service_account" else: "authorized_user"
    cred.setMeta("type", credTypeStr)

    result.findings.add(
      makeFindingWithCred(
        adcPath,
        "GCP application default credentials (" & credTypeStr & ")",
        catCloud,
        sev,
        cred,
      )
    )

  if safeDirExists(gcpDir):
    try:
      for kind, path in walkDir(gcpDir):
        if kind != pcFile:
          continue
        if path.endsWith(".json") and path != adcPath:
          let content = readFileContent(path)
          if GcpServiceAccountPattern in content.toLowerAscii():
            result.findings.add(
              makeFinding(path, "GCP service account key file", catCloud, svHigh)
            )
    except CatchableError as e:
      result.errors.add("Error scanning GCP directory: " & e.msg)

proc scanAzure(config: HarvestConfig, result: var CollectorResult) =
  let azDir = expandHome(config, AzureDir)
  if not safeDirExists(azDir):
    return

  let tokenPaths =
    [expandHome(config, AzureAccessTokens), expandHome(config, AzureMsalTokenCache)]

  var foundTokens = false
  for path in tokenPaths:
    if safeFileExists(path):
      foundTokens = true
      let sev = if isWorldReadable(path): svCritical else: svMedium
      result.findings.add(makeFinding(path, "Azure token cache", catCloud, sev))

  if not foundTokens:
    result.findings.add(
      makeFinding(azDir, "Azure CLI configuration directory", catCloud, svInfo)
    )

proc scanKubernetes(config: HarvestConfig, result: var CollectorResult) =
  let kubePath = expandHome(config, KubeConfig)
  if not safeFileExists(kubePath):
    return

  let content = readFileContent(kubePath)
  let lines = content.splitLines()
  var contextCount = 0
  var userCount = 0
  var hasTokenAuth = false
  var hasCertAuth = false

  var inContexts = false
  var inUsers = false

  for line in lines:
    let stripped = line.strip()
    if stripped == KubeContextMarker:
      inContexts = true
      inUsers = false
    elif stripped == KubeUserMarker:
      inUsers = true
      inContexts = false
    elif stripped.len > 0 and not stripped.startsWith(" ") and
        not stripped.startsWith("-"):
      inContexts = false
      inUsers = false

    if inContexts and stripped.startsWith("- context:"):
      inc contextCount
    if inUsers and stripped.startsWith("- name:"):
      inc userCount
    if "token:" in stripped:
      hasTokenAuth = true
    if "client-certificate-data:" in stripped:
      hasCertAuth = true

  let sev =
    if isWorldReadable(kubePath):
      svCritical
    elif hasTokenAuth:
      svHigh
    else:
      svMedium

  var cred = Credential(
    source: kubePath,
    credType: "kubernetes_config",
    preview: $contextCount & " contexts, " & $userCount & " users",
    metadata: initTable[string, string](),
  )
  cred.setMeta("contexts", $contextCount)
  cred.setMeta("users", $userCount)
  cred.setMeta("token_auth", $hasTokenAuth)
  cred.setMeta("cert_auth", $hasCertAuth)

  result.findings.add(
    makeFindingWithCred(
      kubePath,
      "Kubernetes config: " & $contextCount & " contexts, " & $userCount & " users",
      catCloud,
      sev,
      cred,
    )
  )

proc collect*(config: HarvestConfig): CollectorResult =
  result = newCollectorResult("cloud", catCloud)
  let start = getMonoTime()

  scanAws(config, result)
  scanGcp(config, result)
  scanAzure(config, result)
  scanKubernetes(config, result)

  let elapsed = getMonoTime() - start
  result.durationMs = elapsed.inMilliseconds
