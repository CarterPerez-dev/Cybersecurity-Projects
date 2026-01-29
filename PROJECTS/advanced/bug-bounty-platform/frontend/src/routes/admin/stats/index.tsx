/**
 * AngelaMos | 2026
 * index.tsx
 */

import { usePlatformStats } from '@/api/hooks'
import styles from './stats.module.scss'

export function Component(): React.ReactElement {
  const { data: stats, isLoading } = usePlatformStats()

  if (isLoading) {
    return (
      <div className={styles.page}>
        <div className={styles.loading}>Loading stats...</div>
      </div>
    )
  }

  if (!stats) {
    return (
      <div className={styles.page}>
        <div className={styles.error}>Failed to load platform statistics</div>
      </div>
    )
  }

  const formatCurrency = (cents: number): string => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
    }).format(cents / 100)
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>Platform Statistics</h1>
      </div>

      <div className={styles.statsGrid}>
        <div className={styles.statCard}>
          <span className={styles.statLabel}>Total Users</span>
          <span className={styles.statValue}>{stats.total_users}</span>
        </div>
        <div className={styles.statCard}>
          <span className={styles.statLabel}>Researchers</span>
          <span className={styles.statValue}>{stats.total_researchers}</span>
        </div>
        <div className={styles.statCard}>
          <span className={styles.statLabel}>Companies</span>
          <span className={styles.statValue}>{stats.total_companies}</span>
        </div>
        <div className={styles.statCard}>
          <span className={styles.statLabel}>New Users (30d)</span>
          <span className={styles.statValue}>{stats.new_users_this_month}</span>
        </div>
      </div>

      <div className={styles.statsGrid}>
        <div className={styles.statCard}>
          <span className={styles.statLabel}>Total Programs</span>
          <span className={styles.statValue}>{stats.total_programs}</span>
        </div>
        <div className={styles.statCard}>
          <span className={styles.statLabel}>Active Programs</span>
          <span className={`${styles.statValue} ${styles.highlight}`}>
            {stats.active_programs}
          </span>
        </div>
        <div className={styles.statCard}>
          <span className={styles.statLabel}>Total Reports</span>
          <span className={styles.statValue}>{stats.total_reports}</span>
        </div>
        <div className={styles.statCard}>
          <span className={styles.statLabel}>Reports (30d)</span>
          <span className={styles.statValue}>{stats.reports_this_month}</span>
        </div>
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>Total Bounties Paid</h2>
        <div className={styles.bountyTotal}>
          {formatCurrency(stats.total_bounties_paid)}
        </div>
      </div>

      <div className={styles.section}>
        <h2 className={styles.sectionTitle}>Reports by Status</h2>
        <div className={styles.statusGrid}>
          {Object.entries(stats.reports_by_status).map(([status, count]) => (
            <div key={status} className={styles.statusItem}>
              <span className={styles.statusLabel}>{status}</span>
              <span className={styles.statusCount}>{count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

Component.displayName = 'AdminStats'
