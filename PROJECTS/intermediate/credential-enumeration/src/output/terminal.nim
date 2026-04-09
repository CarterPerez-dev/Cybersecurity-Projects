# ©AngelaMos | 2026
# terminal.nim
#
# ANSI terminal renderer with box-drawing output
#
# Renders the full credential enumeration report to the terminal
# using Unicode box-drawing characters for bordered sections.
# visualLen computes display width by skipping ANSI escape
# sequences and UTF-8 continuation bytes so padding aligns
# correctly despite embedded color codes. truncateVisual truncates
# strings at a visual-width boundary without splitting escape
# sequences. sevBadge produces colored severity labels using the
# SeverityColors and SeverityLabels maps from config. Three box
# helpers (boxLine, boxBottom, boxMid) draw top, bottom, and
# mid-section borders at a fixed 78-column width.
# renderModuleHeader prints a bordered header with the module name,
# category description, finding count, and duration. renderFinding
# shows a severity badge, truncated description, file path with
# permissions and modification date, and an optional credential
# preview. renderSummary totals findings across all modules and
# displays a severity badge breakdown. renderTerminal orchestrates
# the full output sequence: banner, target and module metadata,
# per-module sections (skipping empty modules unless verbose), and
# the summary footer.
#
# Connects to:
#   types.nim   - Severity, Finding, Report, CollectorResult,
#                  Credential, ReportMetadata
#   config.nim  - BoxVertical, BoxTopLeft, BoxTopRight, BoxBottomLeft,
#                  BoxBottomRight, BoxHorizontal, BoxTeeRight, BoxTeeLeft,
#                  SeverityColors, SeverityLabels, ColorBold, ColorReset,
#                  ColorDim, ColorCyan, ColorBoldRed, Banner,
#                  BannerTagline, AppVersion, Arrow, CrossMark,
#                  ModuleDescriptions

{.push raises: [].}

import std/[strutils, options]
import ../types
import ../config

const
  BoxWidth = 78
  InnerWidth = BoxWidth - 2

proc visualLen(s: string): int =
  var i = 0
  while i < s.len:
    if s[i] == '\e':
      while i < s.len and s[i] != 'm':
        inc i
      if i < s.len:
        inc i
    elif (s[i].ord and 0xC0) == 0x80:
      inc i
    else:
      inc result
      inc i

proc truncateVisual(s: string, maxLen: int): string =
  var vLen = 0
  var i = 0
  while i < s.len:
    if s[i] == '\e':
      let start = i
      while i < s.len and s[i] != 'm':
        inc i
      if i < s.len:
        inc i
      result.add(s[start ..< i])
    elif (s[i].ord and 0xC0) == 0x80:
      result.add(s[i])
      inc i
    else:
      if vLen >= maxLen - 3:
        result.add("...")
        return
      result.add(s[i])
      inc vLen
      inc i

proc writeBoxLine(content: string) =
  try:
    stdout.write content
    let vLen = visualLen(content)
    let pad = BoxWidth - vLen - 1
    if pad > 0:
      stdout.write " ".repeat(pad)
    stdout.writeLine BoxVertical
  except CatchableError:
    discard

proc sevBadge(sev: Severity): string =
  SeverityColors[sev] & ColorBold & " " & SeverityLabels[sev] & " " & ColorReset

proc boxLine(width: int): string =
  BoxTopLeft & BoxHorizontal.repeat(width - 2) & BoxTopRight

proc boxBottom(width: int): string =
  BoxBottomLeft & BoxHorizontal.repeat(width - 2) & BoxBottomRight

proc boxMid(width: int): string =
  BoxTeeRight & BoxHorizontal.repeat(width - 2) & BoxTeeLeft

proc renderBanner*(quiet: bool) =
  if quiet:
    return
  try:
    stdout.write ColorBoldRed
    stdout.writeLine Banner
    stdout.write ColorReset
    stdout.writeLine ""
    stdout.write "  "
    stdout.write ColorDim
    stdout.write BannerTagline
    stdout.write " v"
    stdout.write AppVersion
    stdout.writeLine ColorReset
    stdout.writeLine ""
  except CatchableError:
    discard

proc renderModuleHeader(
    name: string, desc: string, findingCount: int, durationMs: int64
) =
  try:
    stdout.writeLine boxLine(BoxWidth)
    let label =
      BoxVertical & " " & ColorBold & ColorCyan & name.toUpperAscii() & ColorReset &
      ColorDim & " " & Arrow & " " & desc & ColorReset
    let stats =
      $findingCount & " findings" & ColorDim & " (" & $durationMs & "ms)" & ColorReset
    let usedWidth = 2 + name.len + 3 + desc.len
    let statsVisual = visualLen(stats)
    let gap = BoxWidth - usedWidth - statsVisual - 2
    stdout.write label
    if gap > 0:
      stdout.write " ".repeat(gap)
    else:
      stdout.write " "
    stdout.write stats
    stdout.writeLine " " & BoxVertical
    stdout.writeLine boxMid(BoxWidth)
  except CatchableError:
    discard

proc renderFinding(f: Finding) =
  let descLine =
    BoxVertical & " " & sevBadge(f.severity) & " " &
    truncateVisual(f.description, InnerWidth - 14)
  writeBoxLine(descLine)

  var detail = BoxVertical & "   " & ColorDim & f.path & "  [" & f.permissions & "]"
  if f.modified != "unknown":
    detail &= "  mod:" & f.modified
  detail &= ColorReset
  writeBoxLine(detail)

  if f.credential.isSome:
    let cred = f.credential.get()
    if cred.preview.len > 0:
      let previewLine =
        BoxVertical & "   " & ColorDim & Arrow & " " & cred.preview & ColorReset
      writeBoxLine(previewLine)

proc renderModuleErrors(errors: seq[string]) =
  if errors.len == 0:
    return
  for err in errors:
    let errLine =
      BoxVertical & " " & ColorBoldRed & CrossMark & ColorReset & " " & ColorDim & err &
      ColorReset
    writeBoxLine(errLine)

proc renderSummary(report: Report) =
  try:
    stdout.writeLine ""
    stdout.writeLine boxLine(BoxWidth)
    writeBoxLine(BoxVertical & " " & ColorBold & "SUMMARY" & ColorReset)
    stdout.writeLine boxMid(BoxWidth)

    var totalFindings = 0
    for sev in Severity:
      totalFindings += report.summary[sev]

    let countLine =
      BoxVertical & " " & ColorBold & $totalFindings & ColorReset & " findings across " &
      ColorBold & $report.results.len & ColorReset & " modules" & ColorDim & " (" &
      $report.metadata.durationMs & "ms)" & ColorReset
    writeBoxLine(countLine)

    var badgeLine = BoxVertical & " "
    for sev in countdown(svCritical, svInfo):
      let count = report.summary[sev]
      if count > 0:
        badgeLine &= sevBadge(sev) & " " & $count & "  "
    writeBoxLine(badgeLine)

    stdout.writeLine boxBottom(BoxWidth)
    stdout.writeLine ""
  except CatchableError:
    discard

proc renderTerminal*(report: Report, quiet: bool, verbose: bool) =
  renderBanner(quiet)

  try:
    if not quiet:
      stdout.write ColorDim & "  Target: " & ColorReset
      stdout.writeLine report.metadata.target
      stdout.write ColorDim & "  Modules: " & ColorReset
      stdout.writeLine report.metadata.modules.join(", ")
      stdout.writeLine ""
  except CatchableError:
    discard

  for res in report.results:
    if res.findings.len == 0 and res.errors.len == 0 and not verbose:
      continue

    renderModuleHeader(
      res.name, ModuleDescriptions[res.category], res.findings.len, res.durationMs
    )

    for finding in res.findings:
      renderFinding(finding)

    renderModuleErrors(res.errors)

    try:
      stdout.writeLine boxBottom(BoxWidth)
    except CatchableError:
      discard

  renderSummary(report)
