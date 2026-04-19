// ©AngelaMos | 2026
// index.tsx

import { useMitreHeatmap, useMitreTechniques } from '@/api/hooks'
import styles from './mitre.module.scss'

const TACTIC_ORDER = [
  'reconnaissance',
  'initial-access',
  'execution',
  'credential-access',
  'discovery',
  'lateral-movement',
  'command-and-control',
  'persistence',
  'impact',
] as const

const HEAT_THRESHOLDS = [0, 5, 20, 50, 100] as const

function heatLevel(count: number): number {
  for (let i = HEAT_THRESHOLDS.length - 1; i >= 0; i--) {
    if (count >= (HEAT_THRESHOLDS[i] ?? 0)) return i
  }
  return 0
}

export function MitrePage() {
  const { data: techniques } = useMitreTechniques()
  const { data: heatmap } = useMitreHeatmap()

  const countMap = new Map(
    heatmap?.map((h) => [h.technique_id, h.count])
  )

  const byTactic = new Map<string, typeof techniques>()
  for (const t of techniques ?? []) {
    const existing = byTactic.get(t.tactic) ?? []
    existing.push(t)
    byTactic.set(t.tactic, existing)
  }

  return (
    <div className={styles.page}>
      <header className={styles.heading}>
        <h1 className={styles.title}>MITRE ATT&CK</h1>
        <span className={styles.subtitle}>ADVERSARY TECHNIQUE HEATMAP</span>
      </header>

      <div className={styles.legend}>
        <span className={styles.legendLabel}>INTENSITY</span>
        {HEAT_THRESHOLDS.map((t, i) => (
          <span key={t} className={styles.legendItem}>
            <span
              className={`${styles.legendSwatch} ${styles[`heat${i}`]}`}
            />
            <span className={styles.legendText}>{t}+</span>
          </span>
        ))}
      </div>

      <div className={styles.matrix}>
        {TACTIC_ORDER.map((tactic) => {
          const techs = byTactic.get(tactic)
          if (!techs) return null

          return (
            <div key={tactic} className={styles.tacticColumn}>
              <h3 className={styles.tacticLabel}>
                {tactic.replace(/-/g, ' ')}
              </h3>
              <div className={styles.techniques}>
                {techs.map((t) => {
                  const count = countMap.get(t.id) ?? 0
                  const level = heatLevel(count)

                  return (
                    <div
                      key={t.id}
                      className={`${styles.technique} ${styles[`heat${level}`]}`}
                      title={`${t.id}: ${t.name} (${count} detections)`}
                    >
                      <span className={styles.techId}>{t.id}</span>
                      <span className={styles.techName}>{t.name}</span>
                      {count > 0 && (
                        <span className={styles.techCount}>
                          {count}
                        </span>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
