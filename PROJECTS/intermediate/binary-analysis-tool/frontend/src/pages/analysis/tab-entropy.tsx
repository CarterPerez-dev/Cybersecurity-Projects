// ===================
// © AngelaMos | 2026
// tab-entropy.tsx
//
// Entropy tab with per-section entropy bars, packing
// detection alert, and classification coloring
//
// Displays overall entropy as a prominent value out of
// MAX_ENTROPY (8.0). When packing is detected, renders
// a packing alert with packer name and indicator list
// (type and description for each). Per-section entropy
// is shown as horizontal bars where fill width is
// entropy/8 percentage and color is mapped from
// ENTROPY_CLASSIFICATION_COLORS (Plaintext green,
// NativeCode blue, Compressed yellow, Packed orange,
// Encrypted red). Each EntropyBar shows section name,
// classification label, bar visualization, numeric
// entropy value, size, virtual-to-raw ratio, and any
// EntropyFlag badges (HighEntropy, Rwx, Packer
// SectionName, etc.), with anomalous sections
// highlighted
//
// Connects to:
//   api/types         - AnalysisResponse, SectionEntropy
//   config.ts         - ENTROPY_CLASSIFICATION_COLORS
//   analysis/index    - mounted in renderTab switch
//   analysis.module
//     .scss           - entropyRow, entropyBarFill,
//                        packingAlert styles
// ===================

import type { AnalysisResponse, SectionEntropy } from '@/api'
import { ENTROPY_CLASSIFICATION_COLORS } from '@/config'
import styles from './analysis.module.scss'

const MAX_ENTROPY = 8

function EntropyBar({
  section,
}: {
  section: SectionEntropy
}): React.ReactElement {
  const pct = (section.entropy / MAX_ENTROPY) * 100
  const color = ENTROPY_CLASSIFICATION_COLORS[section.classification] ?? '#888'

  return (
    <div
      className={`${styles.entropyRow} ${section.is_anomalous ? styles.anomalous : ''}`}
    >
      <div className={styles.entropyMeta}>
        <span className={styles.entropySectionName}>{section.name}</span>
        <span className={styles.entropyClassification} style={{ color }}>
          {section.classification}
        </span>
      </div>
      <div className={styles.entropyBarWrap}>
        <div className={styles.entropyBarTrack}>
          <div
            className={styles.entropyBarFill}
            style={{ width: `${pct}%`, background: color }}
          />
        </div>
        <span className={styles.entropyValue}>{section.entropy.toFixed(2)}</span>
      </div>
      <div className={styles.entropyDetails}>
        <span className={styles.entropyDetail}>
          SIZE {section.size.toLocaleString()}
        </span>
        <span className={styles.entropyDetail}>
          V/R {section.virtual_to_raw_ratio.toFixed(2)}
        </span>
        {section.flags.length > 0 && (
          <div className={styles.entropyFlags}>
            {section.flags.map((flag) => (
              <span key={flag} className={styles.entropyFlag}>
                {flag}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export function TabEntropy({
  data,
}: {
  data: AnalysisResponse
}): React.ReactElement {
  const ent = data.passes.entropy

  if (!ent) {
    return (
      <div className={styles.tabPanel}>
        <span className={styles.noData}>No entropy data available</span>
      </div>
    )
  }

  return (
    <div className={styles.tabPanel}>
      <div className={styles.entropyOverall}>
        <span className={styles.entropyOverallLabel}>OVERALL ENTROPY</span>
        <span className={styles.entropyOverallValue}>
          {ent.overall_entropy.toFixed(4)}
        </span>
        <span className={styles.entropyOverallScale}>/ {MAX_ENTROPY}</span>
      </div>

      {ent.packing_detected && (
        <div className={styles.packingAlert}>
          <span className={styles.packingTitle}>PACKING DETECTED</span>
          {ent.packer_name && (
            <span className={styles.packingName}>{ent.packer_name}</span>
          )}
          {ent.packing_indicators.map((ind, i) => (
            <div key={`ind-${i.toString()}`} className={styles.packingIndicator}>
              <span className={styles.packingType}>{ind.indicator_type}</span>
              <span className={styles.packingEvidence}>{ind.description}</span>
            </div>
          ))}
        </div>
      )}

      <section className={styles.overviewSection}>
        <span className={styles.sectionLabel}>PER-SECTION ENTROPY</span>
        <div className={styles.entropyBars}>
          {ent.sections.map((sec) => (
            <EntropyBar key={sec.name} section={sec} />
          ))}
        </div>
      </section>
    </div>
  )
}
