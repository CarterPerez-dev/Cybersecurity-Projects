// ===================
// © AngelaMos | 2026
// tab-imports.tsx
//
// Imports tab with library-grouped import tables,
// suspicious combination alerts, and export listing
//
// Groups imports by library into collapsible Library
// Group sections (tracked via openLibs Set state),
// each showing function name, hex address, ordinal,
// and threat tags with suspicious row highlighting via
// ImportRow. Above the import groups, suspicious API
// combinations render as alert cards with name, MITRE
// ID pill, severity badge (styled per level), description,
// and matched API tags. Below, an exports section shows
// name, address, ordinal, and forward target in a
// standard data table. All addresses formatted via
// formatHex, with PAGE_SIZE-less full rendering since
// import counts are typically manageable
//
// Connects to:
//   api/types         - AnalysisResponse, ImportEntry
//   core/lib          - formatHex
//   analysis/index    - mounted in renderTab switch
//   analysis.module
//     .scss           - libraryGroup, alertCard,
//                        dataTable, severityBadge styles
// ===================

import { useState } from 'react'
import type { AnalysisResponse, ImportEntry } from '@/api'
import { formatHex } from '@/core/lib'
import styles from './analysis.module.scss'

function ImportRow({ entry }: { entry: ImportEntry }): React.ReactElement {
  return (
    <tr
      className={`${styles.tableRow} ${entry.is_suspicious ? styles.suspicious : ''}`}
    >
      <td className={styles.cellMono}>{entry.function}</td>
      <td className={styles.cellMono}>
        {entry.address !== null ? formatHex(entry.address) : '\u2014'}
      </td>
      <td className={styles.cellMono}>
        {entry.ordinal !== null ? `#${entry.ordinal}` : '\u2014'}
      </td>
      <td>
        {entry.threat_tags.length > 0 && (
          <div className={styles.tagRow}>
            {entry.threat_tags.map((tag) => (
              <span key={tag} className={styles.threatTag}>
                {tag}
              </span>
            ))}
          </div>
        )}
      </td>
    </tr>
  )
}

function LibraryGroup({
  library,
  imports,
  isOpen,
  onToggle,
}: {
  library: string
  imports: ImportEntry[]
  isOpen: boolean
  onToggle: () => void
}): React.ReactElement {
  const suspiciousCount = imports.filter((i) => i.is_suspicious).length
  return (
    <div className={styles.libraryGroup}>
      <button type="button" className={styles.libraryHeader} onClick={onToggle}>
        <span className={styles.libraryName}>{library}</span>
        <span className={styles.libraryMeta}>
          {imports.length} imports
          {suspiciousCount > 0 && (
            <span className={styles.suspiciousCount}>
              {suspiciousCount} suspicious
            </span>
          )}
        </span>
        <span className={styles.collapseIcon}>
          {isOpen ? '\u25B2' : '\u25BC'}
        </span>
      </button>
      {isOpen && (
        <div className={styles.tableWrap}>
          <table className={styles.dataTable}>
            <thead>
              <tr>
                <th>FUNCTION</th>
                <th>ADDRESS</th>
                <th>ORDINAL</th>
                <th>TAGS</th>
              </tr>
            </thead>
            <tbody>
              {imports.map((entry, i) => (
                <ImportRow
                  key={`${entry.function}-${i.toString()}`}
                  entry={entry}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export function TabImports({
  data,
}: {
  data: AnalysisResponse
}): React.ReactElement {
  const imp = data.passes.imports
  const [openLibs, setOpenLibs] = useState<Set<string>>(new Set())

  if (!imp) {
    return (
      <div className={styles.tabPanel}>
        <span className={styles.noData}>No import data available</span>
      </div>
    )
  }

  const toggleLib = (lib: string) => {
    setOpenLibs((prev) => {
      const next = new Set(prev)
      if (next.has(lib)) next.delete(lib)
      else next.add(lib)
      return next
    })
  }

  const importsByLib = new Map<string, ImportEntry[]>()
  for (const entry of imp.imports) {
    const list = importsByLib.get(entry.library) ?? []
    list.push(entry)
    importsByLib.set(entry.library, list)
  }

  return (
    <div className={styles.tabPanel}>
      {imp.suspicious_combinations.length > 0 && (
        <section className={styles.overviewSection}>
          <span className={styles.sectionLabel}>SUSPICIOUS COMBINATIONS</span>
          <div className={styles.alertCards}>
            {imp.suspicious_combinations.map((combo) => (
              <div key={combo.name} className={styles.alertCard}>
                <div className={styles.alertHeader}>
                  <span className={styles.alertName}>{combo.name}</span>
                  <span className={styles.mitrePill}>{combo.mitre_id}</span>
                  <span
                    className={`${styles.severityBadge} ${styles[`severity${combo.severity}`]}`}
                  >
                    {combo.severity}
                  </span>
                </div>
                <span className={styles.alertDesc}>{combo.description}</span>
                <div className={styles.alertApis}>
                  {combo.apis.map((api) => (
                    <span key={api} className={styles.apiTag}>
                      {api}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className={styles.overviewSection}>
        <span className={styles.sectionLabel}>
          IMPORTS ({imp.statistics.total_imports})
        </span>
        {Array.from(importsByLib.entries()).map(([lib, imports]) => (
          <LibraryGroup
            key={lib}
            library={lib}
            imports={imports}
            isOpen={openLibs.has(lib)}
            onToggle={() => toggleLib(lib)}
          />
        ))}
      </section>

      {imp.exports.length > 0 && (
        <section className={styles.overviewSection}>
          <span className={styles.sectionLabel}>
            EXPORTS ({imp.exports.length})
          </span>
          <div className={styles.tableWrap}>
            <table className={styles.dataTable}>
              <thead>
                <tr>
                  <th>NAME</th>
                  <th>ADDRESS</th>
                  <th>ORDINAL</th>
                  <th>FORWARD</th>
                </tr>
              </thead>
              <tbody>
                {imp.exports.map((exp, i) => (
                  <tr key={`exp-${i.toString()}`} className={styles.tableRow}>
                    <td className={styles.cellMono}>{exp.name ?? '\u2014'}</td>
                    <td className={styles.cellMono}>{formatHex(exp.address)}</td>
                    <td className={styles.cellMono}>
                      {exp.ordinal !== null ? `#${exp.ordinal}` : '\u2014'}
                    </td>
                    <td className={styles.cellMono}>
                      {exp.forward_target ?? '\u2014'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}
