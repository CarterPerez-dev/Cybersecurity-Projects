// ===================
// © AngelaMos | 2026
// stat-card.tsx
//
// Dashboard metric card component
//
// Renders a card displaying a prominent value (string or
// number), a descriptive label underneath, and an optional
// sublabel for secondary context. Used on the dashboard
// page to show threat counts, detection rates, and time
// range indicators. Connects to pages/dashboard
// ===================

import styles from './stat-card.module.scss'

interface StatCardProps {
  label: string
  value: string | number
  sublabel?: string
}

export function StatCard({
  label,
  value,
  sublabel,
}: StatCardProps): React.ReactElement {
  return (
    <div className={styles.card}>
      <span className={styles.value}>{value}</span>
      <span className={styles.label}>{label}</span>
      {sublabel && <span className={styles.sublabel}>{sublabel}</span>}
    </div>
  )
}
