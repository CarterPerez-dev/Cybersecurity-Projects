# ©AngelaMos | 2026
# base.nim
#
# Shared collector utilities and Finding constructors
#
# Foundation layer used by all seven collector modules. Wraps POSIX
# stat for permission inspection (getPermsString, getNumericPerms,
# isWorldReadable, isGroupReadable), provides safe filesystem access
# (safeFileExists, safeDirExists, readFileContent, readFileLines with
# optional line cap), SYSROOT-aware path expansion via expandHome,
# and exclude-pattern matching. Constructs Finding objects through
# makeFinding and makeFindingWithCred (auto-populates permissions,
# modification time, and file size). permissionSeverity maps file
# modes to severity levels based on world/group read bits. Also
# provides redactValue for credential preview masking and setMeta
# for type-safe metadata insertion.
#
# Connects to:
#   types.nim   - Finding, Credential, Severity, Category, HarvestConfig
#   config.nim  - OwnerOnlyFilePerms, OwnerOnlyDirPerms, WorldReadBit,
#                  GroupReadBit

{.push raises: [].}

import std/[os, posix, strutils, times, options, tables]
import ../types
import ../config

proc getPermsString*(path: string): string =
  var statBuf: Stat
  try:
    if stat(path.cstring, statBuf) == 0:
      let mode = statBuf.st_mode and 0o7777
      result = "0" & toOct(mode.int, 3)
    else:
      result = "unknown"
  except CatchableError:
    result = "unknown"

proc getModifiedTime*(path: string): string =
  try:
    let info = getFileInfo(path)
    result = $info.lastWriteTime.utc.format("yyyy-MM-dd'T'HH:mm:ss'Z'")
  except CatchableError:
    result = "unknown"

proc getFileSizeBytes*(path: string): int64 =
  try:
    result = os.getFileSize(path)
  except CatchableError:
    result = -1

proc isWorldReadable*(path: string): bool =
  var statBuf: Stat
  try:
    if stat(path.cstring, statBuf) == 0:
      result = (statBuf.st_mode.int and WorldReadBit) != 0
  except CatchableError:
    discard

proc isGroupReadable*(path: string): bool =
  var statBuf: Stat
  try:
    if stat(path.cstring, statBuf) == 0:
      result = (statBuf.st_mode.int and GroupReadBit) != 0
  except CatchableError:
    discard

proc getNumericPerms*(path: string): int =
  var statBuf: Stat
  try:
    if stat(path.cstring, statBuf) == 0:
      result = statBuf.st_mode.int and 0o7777
  except CatchableError:
    result = -1

proc expandHome*(config: HarvestConfig, subpath: string): string =
  result = config.targetDir / subpath

proc safeFileExists*(path: string): bool =
  try:
    result = os.fileExists(path)
  except CatchableError:
    result = false

proc safeDirExists*(path: string): bool =
  try:
    result = os.dirExists(path)
  except CatchableError:
    result = false

proc readFileContent*(path: string): string =
  try:
    result = readFile(path)
  except CatchableError:
    result = ""

proc readFileLines*(path: string, maxLines: int = -1): seq[string] =
  try:
    let content = readFile(path)
    let lines = content.splitLines()
    if maxLines > 0 and lines.len > maxLines:
      result = lines[0 ..< maxLines]
    else:
      result = lines
  except CatchableError:
    result = @[]

proc matchesExclude*(path: string, patterns: seq[string]): bool =
  let name = path.extractFilename()
  for pattern in patterns:
    if pattern == name or ("/" & pattern & "/") in path:
      return true

proc makeFinding*(
    path: string, description: string, category: Category, severity: Severity
): Finding =
  Finding(
    path: path,
    category: category,
    severity: severity,
    description: description,
    credential: none(Credential),
    permissions: getPermsString(path),
    modified: getModifiedTime(path),
    size: getFileSizeBytes(path),
  )

proc makeFindingWithCred*(
    path: string,
    description: string,
    category: Category,
    severity: Severity,
    cred: Credential,
): Finding =
  Finding(
    path: path,
    category: category,
    severity: severity,
    description: description,
    credential: some(cred),
    permissions: getPermsString(path),
    modified: getModifiedTime(path),
    size: getFileSizeBytes(path),
  )

proc newCollectorResult*(name: string, category: Category): CollectorResult =
  CollectorResult(
    name: name, category: category, findings: @[], durationMs: 0, errors: @[]
  )

proc permissionSeverity*(path: string, isDir: bool = false): Severity =
  let perms = getNumericPerms(path)
  if perms < 0:
    return svInfo
  if (perms and WorldReadBit) != 0:
    return svCritical
  if (perms and GroupReadBit) != 0:
    return svMedium
  let expected = if isDir: OwnerOnlyDirPerms else: OwnerOnlyFilePerms
  if perms > expected:
    return svLow
  result = svInfo

proc setMeta*(cred: var Credential, key: string, val: string) =
  {.cast(raises: []).}:
    cred.metadata[key] = val

proc redactValue*(value: string, showChars: int = 4): string =
  if value.len <= showChars:
    result = "*".repeat(value.len)
  else:
    result = value[0 ..< showChars] & "*".repeat(value.len - showChars)
