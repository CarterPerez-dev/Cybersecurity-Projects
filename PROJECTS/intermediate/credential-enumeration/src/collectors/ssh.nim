# ©AngelaMos | 2026
# ssh.nim
#
# SSH key and configuration collector
#
# Scans the target's ~/.ssh directory for credential exposure across
# four areas. scanKeys walks all files looking for PEM/OpenSSH private
# key headers, classifies each as encrypted or unencrypted by checking
# for passphrase markers (ENCRYPTED, bcrypt, aes256-ctr), and escalates
# severity based on encryption status and file permissions (world/group
# readable). scanConfig parses ssh_config for host entry counts and
# weak settings (PasswordAuthentication yes, StrictHostKeyChecking no).
# scanAuthorizedKeys counts non-comment public key entries.
# scanKnownHosts counts known host entries. Also validates .ssh
# directory permissions against the expected 0700.
#
# Connects to:
#   collectors/base.nim - expandHome, safeFileExists, safeDirExists,
#                          readFileContent, readFileLines, makeFinding,
#                          makeFindingWithCred, permissionSeverity
#   config.nim          - SshDir, SshKeyHeaders, SshEncryptedMarkers,
#                          SshSafeDirPerms, SshConfig, SshAuthorizedKeys,
#                          SshKnownHosts

{.push raises: [].}

import std/[os, strutils, tables, monotimes, times]
import ../types
import ../config
import base

proc isPrivateKey*(content: string): bool =
  for header in SshKeyHeaders:
    if content.startsWith(header):
      return true

proc isEncrypted*(content: string): bool =
  for marker in SshEncryptedMarkers:
    if marker in content:
      return true

proc scanKeys(config: HarvestConfig, result: var CollectorResult) =
  let sshPath = expandHome(config, SshDir)
  if not safeDirExists(sshPath):
    return

  let dirPerms = getNumericPerms(sshPath)
  if dirPerms >= 0 and dirPerms != OwnerOnlyDirPerms:
    let sev = permissionSeverity(sshPath, isDir = true)
    result.findings.add(
      makeFinding(
        sshPath,
        "SSH directory permissions " & getPermsString(sshPath) & " (expected " &
          SshSafeDirPerms & ")",
        catSsh,
        sev,
      )
    )

  try:
    for kind, path in walkDir(sshPath):
      if kind != pcFile:
        continue
      if matchesExclude(path, config.excludePatterns):
        continue

      let content = readFileContent(path)
      if content.len == 0:
        continue

      if not isPrivateKey(content):
        continue

      let encrypted = isEncrypted(content)
      let perms = getNumericPerms(path)
      var sev: Severity

      if not encrypted:
        sev = svHigh
      else:
        sev = svInfo

      if perms >= 0 and (perms and WorldReadBit) != 0:
        sev = svCritical
      elif perms >= 0 and (perms and GroupReadBit) != 0:
        if sev < svHigh:
          sev = svHigh

      let keyType =
        if content.startsWith(SshKeyHeaders[0]):
          "OpenSSH"
        elif content.startsWith(SshKeyHeaders[1]):
          "RSA"
        elif content.startsWith(SshKeyHeaders[2]):
          "ECDSA"
        elif content.startsWith(SshKeyHeaders[3]):
          "DSA"
        else:
          "Unknown"

      let desc =
        if encrypted:
          keyType & " private key (passphrase-protected)"
        else:
          keyType & " private key (no passphrase)"

      var cred = Credential(
        source: path,
        credType: "ssh_private_key",
        preview: keyType & " key",
        metadata: initTable[string, string](),
      )
      cred.setMeta("encrypted", $encrypted)
      cred.setMeta("permissions", getPermsString(path))

      result.findings.add(makeFindingWithCred(path, desc, catSsh, sev, cred))
  except CatchableError as e:
    result.errors.add("Error scanning SSH keys: " & e.msg)

proc scanConfig(config: HarvestConfig, result: var CollectorResult) =
  let configPath = expandHome(config, SshDir / SshConfig)
  if not safeFileExists(configPath):
    return

  let lines = readFileLines(configPath)
  var hostCount = 0
  var weakSettings: seq[string] = @[]

  for line in lines:
    let stripped = line.strip()
    if stripped.toLowerAscii().startsWith("host ") and
        not stripped.toLowerAscii().startsWith("host *"):
      inc hostCount

    if stripped.toLowerAscii().startsWith("passwordauthentication yes"):
      weakSettings.add("PasswordAuthentication enabled")

    if stripped.toLowerAscii().startsWith("stricthostkeychecking no"):
      weakSettings.add("StrictHostKeyChecking disabled")

  if hostCount > 0:
    result.findings.add(
      makeFinding(
        configPath, "SSH config with " & $hostCount & " host entries", catSsh, svInfo
      )
    )

  for setting in weakSettings:
    result.findings.add(
      makeFinding(configPath, "Weak SSH setting: " & setting, catSsh, svMedium)
    )

proc scanAuthorizedKeys(config: HarvestConfig, result: var CollectorResult) =
  let akPath = expandHome(config, SshDir / SshAuthorizedKeys)
  if not safeFileExists(akPath):
    return

  let lines = readFileLines(akPath)
  var keyCount = 0
  for line in lines:
    if line.strip().len > 0 and not line.strip().startsWith("#"):
      inc keyCount

  if keyCount > 0:
    result.findings.add(
      makeFinding(akPath, $keyCount & " authorized public keys", catSsh, svInfo)
    )

proc scanKnownHosts(config: HarvestConfig, result: var CollectorResult) =
  let khPath = expandHome(config, SshDir / SshKnownHosts)
  if not safeFileExists(khPath):
    return

  let lines = readFileLines(khPath)
  var hostCount = 0
  for line in lines:
    if line.strip().len > 0 and not line.strip().startsWith("#"):
      inc hostCount

  if hostCount > 0:
    result.findings.add(
      makeFinding(khPath, $hostCount & " known hosts", catSsh, svInfo)
    )

proc collect*(config: HarvestConfig): CollectorResult =
  result = newCollectorResult("ssh", catSsh)
  let start = getMonoTime()

  scanKeys(config, result)
  scanConfig(config, result)
  scanAuthorizedKeys(config, result)
  scanKnownHosts(config, result)

  let elapsed = getMonoTime() - start
  result.durationMs = elapsed.inMilliseconds
