// ===================
// © AngelaMos | 2026
// tab-overview.tsx
//
// Overview tab showing summary cards for all six
// analysis passes, anomalies list, and MITRE ATT&CK
// technique links
//
// Renders a six-card summary grid: format (type, bits,
// section/segment counts), imports (total across
// libraries, suspicious count), strings (total
// extracted, suspicious count), entropy (overall value,
// packing detection status), disassembly (function and
// instruction totals), and YARA (rule match count with
// summary text). Below the grid, displays format
// anomalies as string or key-value entries, and MITRE
// ATT&CK techniques as clickable pill links that open
// attack.mitre.org technique pages (with sub-technique
// slash formatting via formatMitreUrl)
//
// Connects to:
//   api/types         - AnalysisResponse
//   analysis/index    - mounted in renderTab switch
//   analysis.module
//     .scss           - summaryGrid, summaryCard,
//                        anomalyList, mitrePills styles
// ===================

import type { AnalysisResponse } from '@/api'
import styles from './analysis.module.scss'

const MITRE_BASE_URL = 'https://attack.mitre.org/techniques/'

function formatMitreUrl(id: string): string {
  return `${MITRE_BASE_URL}${id.replace('.', '/')}`
}

export function TabOverview({
  data,
}: {
  data: AnalysisResponse
}): React.ReactElement {
  const { passes } = data

  return (
    <div className={styles.tabPanel}>
      <div className={styles.summaryGrid}>
        {passes.format && (
          <div className={styles.summaryCard}>
            <span className={styles.summaryLabel}>FORMAT</span>
            <span className={styles.summaryValue}>
              {passes.format.format} / {passes.format.bits}-bit
            </span>
            <span className={styles.summaryDetail}>
              {passes.format.sections.length} sections,{' '}
              {passes.format.segments.length} segments
            </span>
          </div>
        )}

        {passes.imports && (
          <div className={styles.summaryCard}>
            <span className={styles.summaryLabel}>IMPORTS</span>
            <span className={styles.summaryValue}>
              {passes.imports.statistics.total_imports} across{' '}
              {passes.imports.statistics.library_count} libraries
            </span>
            <span className={styles.summaryDetail}>
              {passes.imports.statistics.suspicious_count} suspicious
            </span>
          </div>
        )}

        {passes.strings && (
          <div className={styles.summaryCard}>
            <span className={styles.summaryLabel}>STRINGS</span>
            <span className={styles.summaryValue}>
              {passes.strings.statistics.total} extracted
            </span>
            <span className={styles.summaryDetail}>
              {passes.strings.statistics.suspicious_count} suspicious
            </span>
          </div>
        )}

        {passes.entropy && (
          <div className={styles.summaryCard}>
            <span className={styles.summaryLabel}>ENTROPY</span>
            <span className={styles.summaryValue}>
              {passes.entropy.overall_entropy.toFixed(2)} overall
            </span>
            <span className={styles.summaryDetail}>
              {passes.entropy.packing_detected
                ? `Packing detected${passes.entropy.packer_name ? `: ${passes.entropy.packer_name}` : ''}`
                : 'No packing detected'}
            </span>
          </div>
        )}

        {passes.disassembly && (
          <div className={styles.summaryCard}>
            <span className={styles.summaryLabel}>DISASSEMBLY</span>
            <span className={styles.summaryValue}>
              {passes.disassembly.total_functions} functions
            </span>
            <span className={styles.summaryDetail}>
              {passes.disassembly.total_instructions} instructions
            </span>
          </div>
        )}

        {passes.threat && (
          <div className={styles.summaryCard}>
            <span className={styles.summaryLabel}>YARA</span>
            <span className={styles.summaryValue}>
              {passes.threat.yara_matches.length} rule matches
            </span>
            <span className={styles.summaryDetail}>{passes.threat.summary}</span>
          </div>
        )}
      </div>

      {passes.format && passes.format.anomalies.length > 0 && (
        <section className={styles.overviewSection}>
          <span className={styles.sectionLabel}>ANOMALIES</span>
          <div className={styles.anomalyList}>
            {passes.format.anomalies.map((anomaly, i) => (
              <div key={`anomaly-${i.toString()}`} className={styles.anomalyItem}>
                {typeof anomaly === 'string' ? (
                  <span>{anomaly}</span>
                ) : (
                  Object.entries(anomaly).map(([key, val]) => (
                    <span key={key}>
                      {key}: {String(val)}
                    </span>
                  ))
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {passes.threat && passes.threat.mitre_techniques.length > 0 && (
        <section className={styles.overviewSection}>
          <span className={styles.sectionLabel}>MITRE ATT&CK</span>
          <div className={styles.mitrePills}>
            {passes.threat.mitre_techniques.map((technique) => (
              <a
                key={technique.technique_id}
                href={formatMitreUrl(technique.technique_id)}
                target="_blank"
                rel="noopener noreferrer"
                className={styles.mitrePill}
              >
                <span className={styles.mitreId}>{technique.technique_id}</span>
                <span className={styles.mitreName}>
                  {technique.technique_name}
                </span>
              </a>
            ))}
          </div>
        </section>
      )}
    </div>
  )
}
