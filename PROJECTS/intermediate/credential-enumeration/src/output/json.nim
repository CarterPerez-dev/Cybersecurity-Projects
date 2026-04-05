# ©AngelaMos | 2026
# json.nim

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
