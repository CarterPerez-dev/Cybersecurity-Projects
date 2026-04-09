# ©AngelaMos | 2026
# browser.nim
#
# Browser credential store collector
#
# Detects Firefox and Chromium-family browser credential databases.
# scanFirefox parses profiles.ini to discover profile directories,
# then checks each for logins.json (stored passwords), cookies.sqlite,
# and key4.db (master key database). scanChromium iterates four
# browser paths (Chrome, Chromium, Brave, Vivaldi) and their Default/
# Profile N subdirectories looking for Login Data, Cookies, and Web
# Data (autofill and payment methods) SQLite databases. Severity
# escalates based on file permissions (world-readable = critical,
# group-readable = high, owner-only = medium).
#
# Connects to:
#   collectors/base.nim - expandHome, safeFileExists, safeDirExists,
#                          isWorldReadable, isGroupReadable, makeFinding
#   config.nim          - FirefoxDir, FirefoxProfilesIni, FirefoxLoginsFile,
#                          FirefoxCookiesDb, FirefoxKeyDb, ChromiumDirs,
#                          ChromiumLoginData, ChromiumCookies, ChromiumWebData

{.push raises: [].}

import std/[os, strutils, monotimes, times]
import ../types
import ../config
import base

proc scanFirefox(config: HarvestConfig, result: var CollectorResult) =
  let firefoxPath = expandHome(config, FirefoxDir)
  if not safeDirExists(firefoxPath):
    return

  let profilesIniPath = firefoxPath / FirefoxProfilesIni
  if not safeFileExists(profilesIniPath):
    return

  let lines = readFileLines(profilesIniPath)
  var profiles: seq[string] = @[]
  var currentPath = ""

  for line in lines:
    let stripped = line.strip()
    if stripped.startsWith("[Profile"):
      if currentPath.len > 0:
        profiles.add(currentPath)
      currentPath = ""

    if stripped.toLowerAscii().startsWith("path="):
      currentPath = stripped.split("=", maxsplit = 1)[1]

  if currentPath.len > 0:
    profiles.add(currentPath)

  for profile in profiles:
    let profileDir =
      if profile.startsWith("/"):
        profile
      else:
        firefoxPath / profile

    if not safeDirExists(profileDir):
      continue

    let credFiles = [
      (FirefoxLoginsFile, "Firefox stored logins database"),
      (FirefoxCookiesDb, "Firefox cookies database"),
      (FirefoxKeyDb, "Firefox key database"),
    ]

    for (fileName, desc) in credFiles:
      let filePath = profileDir / fileName
      if safeFileExists(filePath):
        let sev =
          if isWorldReadable(filePath):
            svCritical
          elif isGroupReadable(filePath):
            svHigh
          else:
            svMedium

        result.findings.add(makeFinding(filePath, desc, catBrowser, sev))

proc scanChromium(config: HarvestConfig, result: var CollectorResult) =
  for chromiumDir in ChromiumDirs:
    let basePath = expandHome(config, chromiumDir)
    if not safeDirExists(basePath):
      continue

    let browserName = chromiumDir.split("/")[^1]

    let defaultProfile = basePath / "Default"
    var profileDirs: seq[string] = @[]

    if safeDirExists(defaultProfile):
      profileDirs.add(defaultProfile)

    try:
      for kind, path in walkDir(basePath):
        if kind == pcDir and path.extractFilename().startsWith("Profile "):
          profileDirs.add(path)
    except CatchableError as e:
      result.errors.add("Error walking " & browserName & " profiles: " & e.msg)

    for profileDir in profileDirs:
      let credFiles = [
        (ChromiumLoginData, browserName & " stored login database"),
        (ChromiumCookies, browserName & " cookies database"),
        (ChromiumWebData, browserName & " web data (autofill, payment methods)"),
      ]

      for (fileName, desc) in credFiles:
        let filePath = profileDir / fileName
        if safeFileExists(filePath):
          let sev =
            if isWorldReadable(filePath):
              svCritical
            elif isGroupReadable(filePath):
              svHigh
            else:
              svMedium

          result.findings.add(makeFinding(filePath, desc, catBrowser, sev))

proc collect*(config: HarvestConfig): CollectorResult =
  result = newCollectorResult("browser", catBrowser)
  let start = getMonoTime()

  scanFirefox(config, result)
  scanChromium(config, result)

  let elapsed = getMonoTime() - start
  result.durationMs = elapsed.inMilliseconds
