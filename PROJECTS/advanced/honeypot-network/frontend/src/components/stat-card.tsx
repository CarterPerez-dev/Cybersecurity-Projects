// ©AngelaMos | 2026
// stat-card.tsx

import styles from './stat-card.module.scss'

interface StatCardProps {
  label: string
  value: string | number
  accent?: string
}

export function StatCard({ label, value, accent }: StatCardProps) {
  return (
    <div className={styles.card}>
      <span className={styles.label}>{label}</span>
      <span
        className={styles.value}
        style={accent ? { color: accent } : undefined}
      >
        {typeof value === 'number' ? value.toLocaleString() : value}
      </span>
    </div>
  )
}
