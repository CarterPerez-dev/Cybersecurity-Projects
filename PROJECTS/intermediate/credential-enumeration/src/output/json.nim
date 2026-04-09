# ©AngelaMos | 2026
# json.nim
#
# JSON report serializer
#
# Converts the Report object tree into a structured JSON document
# using std/json's JsonNode builders. credentialToJson serializes a
# Credential with source, type, preview, and a metadata key-value
# map. findingToJson serializes a Finding with path, category,
# severity, description, permissions, modified timestamp, file
# size, and an optional nested credential object.
# collectorResultToJson wraps a module's findings array alongside
# its name, category, duration, and error list.  reportToJson
# assembles the top-level structure: metadata block (timestamp,
# target directory, version, duration, module list), a modules
# array of collector results, and a summary object mapping each
# Severity level to its finding count. renderJson pretty-prints the
# JSON tree to stdout and optionally writes to a file path.
# All builder procs use {.cast(raises: []).} to suppress exception
# tracking within the JSON construction blocks.
#
# Connects to:
#   types.nim - Credential, Finding, CollectorResult, Report,
#                Severity, ReportMetadata

{.push raises: [].}

import std/[json, options, tables]
import ../types

proc credentialToJson(cred: Credential): JsonNode =
  result = newJObject()
  {.cast(raises: []).}:
    result["source"] = newJString(cred.source)
    result["type"] = newJString(cred.credType)
    result["preview"] = newJString(cred.preview)
    let meta = newJObject()
    for key, val in cred.metadata:
      meta[key] = newJString(val)
    result["metadata"] = meta

proc findingToJson(f: Finding): JsonNode =
  result = newJObject()
  {.cast(raises: []).}:
    result["path"] = newJString(f.path)
    result["category"] = newJString($f.category)
    result["severity"] = newJString($f.severity)
    result["description"] = newJString(f.description)
    result["permissions"] = newJString(f.permissions)
    result["modified"] = newJString(f.modified)
    result["size"] = newJInt(f.size)
    if f.credential.isSome:
      result["credential"] = credentialToJson(f.credential.get())

proc collectorResultToJson(res: CollectorResult): JsonNode =
  result = newJObject()
  {.cast(raises: []).}:
    result["name"] = newJString(res.name)
    result["category"] = newJString($res.category)
    let findings = newJArray()
    for f in res.findings:
      findings.add(findingToJson(f))
    result["findings"] = findings
    result["duration_ms"] = newJInt(res.durationMs)
    let errors = newJArray()
    for e in res.errors:
      errors.add(newJString(e))
    result["errors"] = errors

proc reportToJson*(report: Report): JsonNode =
  result = newJObject()
  {.cast(raises: []).}:
    let metadata = newJObject()
    metadata["timestamp"] = newJString(report.metadata.timestamp)
    metadata["target"] = newJString(report.metadata.target)
    metadata["version"] = newJString(report.metadata.version)
    metadata["duration_ms"] = newJInt(report.metadata.durationMs)
    let modules = newJArray()
    for m in report.metadata.modules:
      modules.add(newJString(m))
    metadata["modules"] = modules
    result["metadata"] = metadata

    let results = newJArray()
    for res in report.results:
      results.add(collectorResultToJson(res))
    result["modules"] = results

    let summary = newJObject()
    for sev in Severity:
      summary[$sev] = newJInt(report.summary[sev])
    result["summary"] = summary

proc renderJson*(report: Report, outputPath: string) =
  let root = reportToJson(report)
  let pretty = root.pretty(2)

  if outputPath.len > 0:
    try:
      writeFile(outputPath, pretty & "\n")
    except CatchableError as e:
      try:
        stderr.writeLine "Warning: could not write to " & outputPath & ": " & e.msg
      except CatchableError:
        discard

  try:
    stdout.writeLine pretty
  except CatchableError:
    discard
