// ===================
// © AngelaMos | 2026
// severity-badge.tsx
//
// Threat severity level badge component
//
// Renders a span with a base badge class and a
// severity-specific SCSS module class derived by
// lowercasing the severity prop (HIGH, MEDIUM, LOW).
// Used across the alert feed, threats table, and threat
// detail modal. Connects to components/alert-feed,
// components/threat-detail, pages/threats, pages/dashboard
// ===================

import styles from './severity-badge.module.scss'

interface SeverityBadgeProps {
  severity: 'HIGH' | 'MEDIUM' | 'LOW'
}

export function SeverityBadge({
  severity,
}: SeverityBadgeProps): React.ReactElement {
  return (
    <span className={`${styles.badge} ${styles[severity.toLowerCase()]}`}>
      {severity}
    </span>
  )
}
