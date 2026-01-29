/**
 * AngelaMos | 2026
 * index.tsx
 */

import { Link } from 'react-router-dom'
import { useInbox } from '@/api/hooks'
import { REPORT_STATUS_LABELS, type Report, SEVERITY_LABELS } from '@/api/types'
import { ROUTES } from '@/config'
import styles from './inbox.module.scss'

function formatDate(dateString: string): string {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }).format(new Date(dateString))
}

function ReportRow({ report }: { report: Report }): React.ReactElement {
  return (
    <Link to={ROUTES.COMPANY.REPORT(report.id)} className={styles.row}>
      <div className={styles.cell}>
        <span className={styles.reportTitle}>{report.title}</span>
      </div>
      <div className={styles.cell}>
        <span className={styles.status} data-status={report.status}>
          {REPORT_STATUS_LABELS[report.status]}
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
        <span className={styles.date}>{formatDate(report.created_at)}</span>
      </div>
    </Link>
  )
}

export function Component(): React.ReactElement {
  const { data, isLoading, error } = useInbox(1, 50)

  if (isLoading) {
    return (
      <div className={styles.page}>
        <div className={styles.container}>
          <div className={styles.loading}>Loading inbox...</div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className={styles.page}>
        <div className={styles.container}>
          <div className={styles.error}>Failed to load inbox</div>
        </div>
      </div>
    )
  }

  const reports = data?.items ?? []

  return (
    <div className={styles.page}>
      <div className={styles.container}>
        <div className={styles.header}>
          <div>
            <h1 className={styles.title}>Inbox</h1>
            <p className={styles.subtitle}>
              Review and triage incoming vulnerability reports
            </p>
          </div>
          <div className={styles.stats}>
            <span className={styles.statValue}>{data?.total ?? 0}</span>
            <span className={styles.statLabel}>total reports</span>
          </div>
        </div>

        {reports.length === 0 ? (
          <div className={styles.empty}>
            <p>No reports in your inbox</p>
            <span className={styles.emptyHint}>
              Reports will appear here when researchers submit vulnerabilities to
              your programs
            </span>
          </div>
        ) : (
          <div className={styles.table}>
            <div className={styles.tableHeader}>
              <span className={styles.headerCell}>Report</span>
              <span className={styles.headerCell}>Status</span>
              <span className={styles.headerCell}>Severity</span>
              <span className={styles.headerCell}>Submitted</span>
            </div>
            <div className={styles.tableBody}>
              {reports.map((report) => (
                <ReportRow key={report.id} report={report} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

Component.displayName = 'CompanyInbox'
