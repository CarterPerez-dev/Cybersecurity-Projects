/**
 * AngelaMos | 2026
 * index.tsx
 */

import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMyReports, useReportStats } from '@/api/hooks'
import { REPORT_STATUS_LABELS, type Report, SEVERITY_LABELS } from '@/api/types'
import { ROUTES } from '@/config'
import styles from './reports.module.scss'

function formatDate(dateString: string): string {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }).format(new Date(dateString))
}

function formatCurrency(cents: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 0,
    maximumFractionDigits: 0,
  }).format(cents / 100)
}

function StatsCard(): React.ReactElement {
  const { data: stats, isLoading } = useReportStats()

  if (isLoading || !stats) {
    return <div className={styles.statsCard}>Loading stats...</div>
  }

  return (
    <div className={styles.statsCard}>
      <div className={styles.stat}>
        <span className={styles.statValue}>{stats.total_reports}</span>
        <span className={styles.statLabel}>Total Reports</span>
      </div>
      <div className={styles.stat}>
        <span className={styles.statValue}>{stats.accepted_reports}</span>
        <span className={styles.statLabel}>Accepted</span>
      </div>
      <div className={styles.stat}>
        <span className={styles.statValue}>
          {formatCurrency(stats.total_earned)}
        </span>
        <span className={styles.statLabel}>Earned</span>
      </div>
      <div className={styles.stat}>
        <span className={styles.statValue}>{stats.reputation_score}</span>
        <span className={styles.statLabel}>Reputation</span>
      </div>
    </div>
  )
}

function ReportRow({ report }: { report: Report }): React.ReactElement {
  return (
    <Link to={ROUTES.REPORTS.DETAIL(report.id)} className={styles.row}>
      <div className={styles.cell}>
        <span className={styles.reportTitle}>{report.title}</span>
        <span className={styles.reportDate}>
          Submitted {formatDate(report.created_at)}
        </span>
      </div>
      <div className={styles.cell}>
        <span
          className={styles.severity}
          data-severity={report.severity_submitted}
        >
          {SEVERITY_LABELS[report.severity_submitted]}
        </span>
      </div>
      <div className={styles.cell}>
        <span className={styles.status} data-status={report.status}>
          {REPORT_STATUS_LABELS[report.status]}
        </span>
      </div>
      <div className={styles.cell}>
        {report.bounty_amount ? (
          <span className={styles.bounty}>
            {formatCurrency(report.bounty_amount)}
          </span>
        ) : (
          <span className={styles.noBounty}>-</span>
        )}
      </div>
    </Link>
  )
}

export function Component(): React.ReactElement {
  const [page, setPage] = useState(1)
  const { data, isLoading, error } = useMyReports(page, 20)

  if (isLoading) {
    return (
      <div className={styles.page}>
        <div className={styles.container}>
          <div className={styles.loading}>Loading reports...</div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className={styles.page}>
        <div className={styles.container}>
          <div className={styles.error}>Failed to load reports</div>
        </div>
      </div>
    )
  }

  const reports = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.ceil(total / 20)

  return (
    <div className={styles.page}>
      <div className={styles.container}>
        <div className={styles.header}>
          <h1 className={styles.title}>My Reports</h1>
          <p className={styles.subtitle}>
            Track your submitted vulnerability reports
          </p>
        </div>

        <StatsCard />

        {reports.length === 0 ? (
          <div className={styles.empty}>
            <p>No reports submitted yet</p>
            <Link to={ROUTES.PROGRAMS.LIST} className={styles.browseLink}>
              Browse Programs
            </Link>
          </div>
        ) : (
          <>
            <div className={styles.table}>
              <div className={styles.tableHeader}>
                <span className={styles.headerCell}>Report</span>
                <span className={styles.headerCell}>Severity</span>
                <span className={styles.headerCell}>Status</span>
                <span className={styles.headerCell}>Bounty</span>
              </div>
              <div className={styles.tableBody}>
                {reports.map((report) => (
                  <ReportRow key={report.id} report={report} />
                ))}
              </div>
            </div>

            {totalPages > 1 && (
              <div className={styles.pagination}>
                <button
                  type="button"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className={styles.pageButton}
                >
                  Previous
                </button>
                <span className={styles.pageInfo}>
                  Page {page} of {totalPages}
                </span>
                <button
                  type="button"
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className={styles.pageButton}
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

Component.displayName = 'MyReports'
