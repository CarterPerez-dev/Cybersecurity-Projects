# ©AngelaMos | 2026
# keyring.nim
#
# Desktop keyring and password manager collector
#
# Detects credential stores from five sources. scanGnomeKeyring walks
# ~/.local/share/keyrings for .keyring database files. scanKdeWallet
# checks ~/.local/share/kwalletd for wallet files. scanKeePass
# recursively searches up to depth 5 for .kdbx database files,
# skipping hidden/vendored directories. scanPassStore checks
# ~/.password-store and counts GPG-encrypted entries. scanBitwarden
# checks for Bitwarden desktop and CLI local vault directories.
# Each finding's severity is based on file permissions (world-readable
# escalates to critical).
#
# Connects to:
#   collectors/base.nim - expandHome, safeDirExists, safeFileExists,
#                          isWorldReadable, isGroupReadable, makeFinding,
#                          makeFindingWithCred, matchesExclude,
#                          permissionSeverity
#   config.nim          - GnomeKeyringDir, KdeWalletDir, KeePassExtension,
#                          PassStoreDir, BitwardenDir, BitwardenCliDir

{.push raises: [].}

import std/[os, strutils, tables, monotimes, times]
import ../types
import ../config
import base

proc scanGnomeKeyring(config: HarvestConfig, result: var CollectorResult) =
  let keyringDir = expandHome(config, GnomeKeyringDir)
  if not safeDirExists(keyringDir):
    return

  try:
    var dbCount = 0
    for kind, path in walkDir(keyringDir):
      if kind != pcFile:
        continue
      if path.endsWith(".keyring"):
        inc dbCount
        let sev =
          if isWorldReadable(path):
            svCritical
          elif isGroupReadable(path):
            svHigh
          else:
            svMedium

        result.findings.add(
          makeFinding(path, "GNOME Keyring database", catKeyring, sev)
        )

    if dbCount == 0:
      result.findings.add(
        makeFinding(
          keyringDir, "GNOME Keyring directory exists (empty)", catKeyring, svInfo
        )
      )
  except CatchableError as e:
    result.errors.add("Error scanning GNOME Keyring: " & e.msg)

proc scanKdeWallet(config: HarvestConfig, result: var CollectorResult) =
  let walletDir = expandHome(config, KdeWalletDir)
  if not safeDirExists(walletDir):
    return

  try:
    for kind, path in walkDir(walletDir):
      if kind != pcFile:
        continue
      let sev =
        if isWorldReadable(path):
          svCritical
        elif isGroupReadable(path):
          svHigh
        else:
          svMedium

      result.findings.add(makeFinding(path, "KDE Wallet database", catKeyring, sev))
  except CatchableError as e:
    result.errors.add("Error scanning KDE Wallet: " & e.msg)

proc walkForKdbx(
    dir: string, depth: int, excludePatterns: seq[string], result: var CollectorResult
) =
  if depth > 5:
    return
  try:
    for kind, path in walkDir(dir):
      if matchesExclude(path, excludePatterns):
        continue
      case kind
      of pcFile:
        if path.endsWith(KeePassExtension):
          let sev =
            if isWorldReadable(path):
              svCritical
            elif isGroupReadable(path):
              svHigh
            else:
              svMedium

          result.findings.add(
            makeFinding(path, "KeePass database file", catKeyring, sev)
          )
      of pcDir:
        let dirName = path.extractFilename()
        if dirName.startsWith(".") and
            dirName notin [".config", ".local", ".keepass", ".keepassxc"]:
          continue
        if dirName in
            ["node_modules", "vendor", ".git", "__pycache__", ".venv", "venv", ".cache"]:
          continue
        walkForKdbx(path, depth + 1, excludePatterns, result)
      else:
        discard
  except CatchableError:
    discard

proc scanKeePass(config: HarvestConfig, result: var CollectorResult) =
  walkForKdbx(config.targetDir, 0, config.excludePatterns, result)

proc scanPassStore(config: HarvestConfig, result: var CollectorResult) =
  let passDir = expandHome(config, PassStoreDir)
  if not safeDirExists(passDir):
    return

  var entryCount = 0
  try:
    for kind, path in walkDir(passDir, relative = false):
      if kind == pcFile and path.endsWith(".gpg"):
        inc entryCount
  except CatchableError as e:
    result.errors.add("Error scanning pass store: " & e.msg)

  var cred = Credential(
    source: passDir,
    credType: "pass_store",
    preview: $entryCount & " encrypted entries",
    metadata: initTable[string, string](),
  )
  cred.setMeta("entry_count", $entryCount)

  result.findings.add(
    makeFindingWithCred(
      passDir,
      "pass (password-store) with " & $entryCount & " entries",
      catKeyring,
      svInfo,
      cred,
    )
  )

proc scanBitwarden(config: HarvestConfig, result: var CollectorResult) =
  let dirs = [expandHome(config, BitwardenDir), expandHome(config, BitwardenCliDir)]

  for dir in dirs:
    if safeDirExists(dir):
      let sev = permissionSeverity(dir, isDir = true)
      result.findings.add(
        makeFinding(dir, "Bitwarden local vault data", catKeyring, sev)
      )

proc collect*(config: HarvestConfig): CollectorResult =
  result = newCollectorResult("keyring", catKeyring)
  let start = getMonoTime()

  scanGnomeKeyring(config, result)
  scanKdeWallet(config, result)
  scanKeePass(config, result)
  scanPassStore(config, result)
  scanBitwarden(config, result)

  let elapsed = getMonoTime() - start
  result.durationMs = elapsed.inMilliseconds
