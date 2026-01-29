/**
 * AngelaMos | 2026
 * index.tsx
 */

import { Link } from 'react-router-dom'
import { useMyReports, useReportStats } from '@/api/hooks'
import { REPORT_STATUS_LABELS, type Report, SEVERITY_LABELS } from '@/api/types'
import { ROUTES } from '@/config'
import { useUser } from '@/core/lib'
import styles from './dashboard.module.scss'

function formatCurrency(cents: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 0,
    maximumFractionDigits: 0,
  }).format(cents / 100)
}

function formatDate(dateString: string): string {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
  }).format(new Date(dateString))
}

function StatsGrid(): React.ReactElement {
  const { data: stats, isLoading } = useReportStats()

  if (isLoading) {
    return <div className={styles.statsLoading}>Loading stats...</div>
  }

  const statItems = [
    { label: 'Total Reports', value: stats?.total_reports ?? 0 },
    { label: 'Accepted', value: stats?.accepted_reports ?? 0 },
    { label: 'Total Earned', value: formatCurrency(stats?.total_earned ?? 0) },
    { label: 'Reputation', value: stats?.reputation_score ?? 0 },
  ]

  return (
    <div className={styles.statsGrid}>
      {statItems.map((stat) => (
        <div key={stat.label} className={styles.statCard}>
          <span className={styles.statValue}>{stat.value}</span>
          <span className={styles.statLabel}>{stat.label}</span>
        </div>
      ))}
    </div>
  )
}

function RecentReports(): React.ReactElement {
  const { data, isLoading } = useMyReports(1, 5)

  if (isLoading) {
    return <div className={styles.reportsLoading}>Loading reports...</div>
  }

  const reports = data?.items ?? []

  if (reports.length === 0) {
    return (
      <div className={styles.emptyReports}>
        <p>No reports yet</p>
        <Link to={ROUTES.PROGRAMS.LIST} className={styles.browseLink}>
          Browse Programs
        </Link>
      </div>
    )
  }

  return (
    <div className={styles.reportsList}>
      {reports.map((report: Report) => (
        <Link
          key={report.id}
          to={ROUTES.REPORTS.DETAIL(report.id)}
          className={styles.reportItem}
        >
          <div className={styles.reportMain}>
            <span className={styles.reportTitle}>{report.title}</span>
            <span className={styles.reportDate}>
              {formatDate(report.created_at)}
            </span>
          </div>
          <div className={styles.reportMeta}>
            <span
              className={styles.severity}
              data-severity={report.severity_submitted}
            >
              {SEVERITY_LABELS[report.severity_submitted]}
            </span>
            <span className={styles.status} data-status={report.status}>
              {REPORT_STATUS_LABELS[report.status]}
            </span>
          </div>
        </Link>
      ))}
      <Link to={ROUTES.REPORTS.LIST} className={styles.viewAll}>
        View All Reports
      </Link>
    </div>
  )
}

export function Component(): React.ReactElement {
  const user = useUser()

  return (
    <div className={styles.page}>
      <div className={styles.container}>
        <div className={styles.header}>
          <h1 className={styles.title}>
            Welcome{user?.full_name ? `, ${user.full_name}` : ''}
          </h1>
          <p className={styles.subtitle}>Your security research dashboard</p>
        </div>

        <StatsGrid />

        <div className={styles.columns}>
          <section className={styles.section}>
            <div className={styles.sectionHeader}>
              <h2 className={styles.sectionTitle}>Recent Reports</h2>
            </div>
            <RecentReports />
          </section>

          <section className={styles.section}>
            <div className={styles.sectionHeader}>
              <h2 className={styles.sectionTitle}>Quick Actions</h2>
            </div>
            <div className={styles.quickActions}>
              <Link to={ROUTES.PROGRAMS.LIST} className={styles.actionCard}>
                <span className={styles.actionTitle}>Browse Programs</span>
                <span className={styles.actionDesc}>
                  Find new targets to test
                </span>
              </Link>
              <Link to={ROUTES.REPORTS.LIST} className={styles.actionCard}>
                <span className={styles.actionTitle}>My Reports</span>
                <span className={styles.actionDesc}>Track your submissions</span>
              </Link>
              <Link to={ROUTES.SETTINGS} className={styles.actionCard}>
                <span className={styles.actionTitle}>Settings</span>
                <span className={styles.actionDesc}>Manage your account</span>
              </Link>
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}

Component.displayName = 'Dashboard'
