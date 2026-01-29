/**
 * AngelaMos | 2026
 * [id].tsx
 */

import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useAddComment, useReport, useTriageReport } from '@/api/hooks'
import {
  type Comment,
  REPORT_STATUS_LABELS,
  type ReportDetail,
  type ReportStatus,
  ReportStatus as ReportStatusEnum,
  SEVERITY_LABELS,
  type Severity,
  Severity as SeverityEnum,
} from '@/api/types'
import { ROUTES } from '@/config'
import styles from './triage.module.scss'

function formatDate(dateString: string): string {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
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

function CommentItem({ comment }: { comment: Comment }): React.ReactElement {
  return (
    <div
      className={styles.comment}
      data-internal={comment.is_internal ? 'true' : undefined}
    >
      <div className={styles.commentHeader}>
        <span className={styles.commentAuthor}>User</span>
        <span className={styles.commentDate}>
          {formatDate(comment.created_at)}
        </span>
        {comment.is_internal && (
          <span className={styles.internalBadge}>Internal</span>
        )}
      </div>
      <div className={styles.commentContent}>{comment.content}</div>
    </div>
  )
}

function CommentForm({ reportId }: { reportId: string }): React.ReactElement {
  const [content, setContent] = useState('')
  const [isInternal, setIsInternal] = useState(false)
  const addComment = useAddComment()

  const handleSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault()
    if (!content.trim()) return

    try {
      await addComment.mutateAsync({
        reportId,
        data: { content, is_internal: isInternal },
      })
      setContent('')
      setIsInternal(false)
    } catch {
      // Error handled by mutation
    }
  }

  return (
    <form onSubmit={handleSubmit} className={styles.commentForm}>
      <textarea
        value={content}
        onChange={(e) => setContent(e.target.value)}
        className={styles.commentInput}
        placeholder="Add a comment..."
        rows={3}
      />
      <div className={styles.commentActions}>
        <label className={styles.internalCheck}>
          <input
            type="checkbox"
            checked={isInternal}
            onChange={(e) => setIsInternal(e.target.checked)}
          />
          Internal note (hidden from researcher)
        </label>
        <button
          type="submit"
          className={styles.commentButton}
          disabled={addComment.isPending || !content.trim()}
        >
          {addComment.isPending ? 'Posting...' : 'Post Comment'}
        </button>
      </div>
    </form>
  )
}

function ReportContent({ report }: { report: ReportDetail }): React.ReactElement {
  return (
    <div className={styles.content}>
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Description</h2>
        <div className={styles.prose}>{report.description}</div>
      </section>

      {report.steps_to_reproduce && (
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>Steps to Reproduce</h2>
          <div className={styles.prose}>{report.steps_to_reproduce}</div>
        </section>
      )}

      {report.impact && (
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>Impact</h2>
          <div className={styles.prose}>{report.impact}</div>
        </section>
      )}

      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>
          Comments ({report.comments.length})
        </h2>
        <div className={styles.commentList}>
          {report.comments.length === 0 ? (
            <p className={styles.noComments}>No comments yet</p>
          ) : (
            report.comments.map((comment) => (
              <CommentItem key={comment.id} comment={comment} />
            ))
          )}
        </div>
        <CommentForm reportId={report.id} />
      </section>
    </div>
  )
}

function TriagePanel({ report }: { report: ReportDetail }): React.ReactElement {
  const triageReport = useTriageReport()
  const [status, setStatus] = useState<ReportStatus>(report.status)
  const [severity, setSeverity] = useState<Severity | ''>(
    report.severity_final ?? ''
  )
  const [cvss, setCvss] = useState<string>(report.cvss_score?.toString() ?? '')
  const [cwe, setCwe] = useState(report.cwe_id ?? '')
  const [bounty, setBounty] = useState<string>(
    report.bounty_amount ? (report.bounty_amount / 100).toString() : ''
  )

  const handleTriage = async (): Promise<void> => {
    try {
      await triageReport.mutateAsync({
        id: report.id,
        data: {
          status: status !== report.status ? status : undefined,
          severity_final: severity || undefined,
          cvss_score: cvss ? parseFloat(cvss) : undefined,
          cwe_id: cwe || undefined,
          bounty_amount: bounty
            ? Math.round(parseFloat(bounty) * 100)
            : undefined,
        },
      })
    } catch {
      // Error handled by mutation
    }
  }

  const statusOptions: ReportStatus[] = [
    ReportStatusEnum.NEW,
    ReportStatusEnum.TRIAGING,
    ReportStatusEnum.NEEDS_MORE_INFO,
    ReportStatusEnum.ACCEPTED,
    ReportStatusEnum.DUPLICATE,
    ReportStatusEnum.INFORMATIVE,
    ReportStatusEnum.NOT_APPLICABLE,
    ReportStatusEnum.RESOLVED,
    ReportStatusEnum.DISCLOSED,
  ]

  const severityOptions: Severity[] = [
    SeverityEnum.CRITICAL,
    SeverityEnum.HIGH,
    SeverityEnum.MEDIUM,
    SeverityEnum.LOW,
    SeverityEnum.INFORMATIONAL,
  ]

  return (
    <aside className={styles.sidebar}>
      <div className={styles.triageCard}>
        <h3 className={styles.triageTitle}>Triage</h3>

        <label className={styles.triageField}>
          <span className={styles.triageLabel}>Status</span>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as ReportStatus)}
            className={styles.triageSelect}
          >
            {statusOptions.map((s) => (
              <option key={s} value={s}>
                {REPORT_STATUS_LABELS[s]}
              </option>
            ))}
          </select>
        </label>

        <label className={styles.triageField}>
          <span className={styles.triageLabel}>Final Severity</span>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as Severity)}
            className={styles.triageSelect}
          >
            <option value="">Select severity...</option>
            {severityOptions.map((s) => (
              <option key={s} value={s}>
                {SEVERITY_LABELS[s]}
              </option>
            ))}
          </select>
        </label>

        <label className={styles.triageField}>
          <span className={styles.triageLabel}>CVSS Score</span>
          <input
            type="number"
            value={cvss}
            onChange={(e) => setCvss(e.target.value)}
            className={styles.triageInput}
            placeholder="0.0 - 10.0"
            min={0}
            max={10}
            step={0.1}
          />
        </label>

        <label className={styles.triageField}>
          <span className={styles.triageLabel}>CWE ID</span>
          <input
            type="text"
            value={cwe}
            onChange={(e) => setCwe(e.target.value)}
            className={styles.triageInput}
            placeholder="CWE-79"
          />
        </label>

        <label className={styles.triageField}>
          <span className={styles.triageLabel}>Bounty Amount ($)</span>
          <input
            type="number"
            value={bounty}
            onChange={(e) => setBounty(e.target.value)}
            className={styles.triageInput}
            placeholder="0"
            min={0}
            step={1}
          />
        </label>

        <button
          type="button"
          onClick={handleTriage}
          className={styles.triageBtn}
          disabled={triageReport.isPending}
        >
          {triageReport.isPending ? 'Saving...' : 'Update Triage'}
        </button>
      </div>

      <div className={styles.infoCard}>
        <h3 className={styles.infoTitle}>Report Info</h3>

        <div className={styles.infoRow}>
          <span className={styles.infoLabel}>Current Status</span>
          <span className={styles.status} data-status={report.status}>
            {REPORT_STATUS_LABELS[report.status]}
          </span>
        </div>

        <div className={styles.infoRow}>
          <span className={styles.infoLabel}>Submitted Severity</span>
          <span
            className={styles.severity}
            data-severity={report.severity_submitted}
          >
            {SEVERITY_LABELS[report.severity_submitted]}
          </span>
        </div>

        {report.severity_final && (
          <div className={styles.infoRow}>
            <span className={styles.infoLabel}>Final Severity</span>
            <span
              className={styles.severity}
              data-severity={report.severity_final}
            >
              {SEVERITY_LABELS[report.severity_final]}
            </span>
          </div>
        )}

        {report.bounty_amount !== null && (
          <div className={styles.infoRow}>
            <span className={styles.infoLabel}>Bounty</span>
            <span className={styles.bounty}>
              {formatCurrency(report.bounty_amount)}
            </span>
          </div>
        )}

        <div className={styles.infoRow}>
          <span className={styles.infoLabel}>Submitted</span>
          <span className={styles.infoValue}>
            {formatDate(report.created_at)}
          </span>
        </div>

        {report.triaged_at && (
          <div className={styles.infoRow}>
            <span className={styles.infoLabel}>Triaged</span>
            <span className={styles.infoValue}>
              {formatDate(report.triaged_at)}
            </span>
          </div>
        )}
      </div>
    </aside>
  )
}

export function Component(): React.ReactElement {
  const { id } = useParams<{ id: string }>()
  const { data: report, isLoading, error } = useReport(id ?? '')

  if (isLoading) {
    return (
      <div className={styles.page}>
        <div className={styles.container}>
          <div className={styles.loading}>Loading report...</div>
        </div>
      </div>
    )
  }

  if (error || !report) {
    return (
      <div className={styles.page}>
        <div className={styles.container}>
          <div className={styles.error}>Report not found</div>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <div className={styles.container}>
        <div className={styles.header}>
          <Link to={ROUTES.COMPANY.INBOX} className={styles.backLink}>
            Back to Inbox
          </Link>
          <h1 className={styles.title}>{report.title}</h1>
        </div>

        <div className={styles.layout}>
          <ReportContent report={report} />
          <TriagePanel report={report} />
        </div>
      </div>
    </div>
  )
}

Component.displayName = 'TriageReport'
