/**
 * AngelaMos | 2026
 * index.tsx
 */

import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useAddComment, useReport } from '@/api/hooks'
import {
  type Comment,
  REPORT_STATUS_LABELS,
  type ReportDetail,
  SEVERITY_LABELS,
} from '@/api/types'
import { ROUTES } from '@/config'
import styles from './detail.module.scss'

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
  const addComment = useAddComment()

  const handleSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault()
    if (!content.trim()) return

    try {
      await addComment.mutateAsync({
        reportId,
        data: { content, is_internal: false },
      })
      setContent('')
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
      <button
        type="submit"
        className={styles.commentButton}
        disabled={addComment.isPending || !content.trim()}
      >
        {addComment.isPending ? 'Posting...' : 'Post Comment'}
      </button>
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

function Sidebar({ report }: { report: ReportDetail }): React.ReactElement {
  return (
    <aside className={styles.sidebar}>
      <div className={styles.infoCard}>
        <h3 className={styles.infoTitle}>Report Details</h3>

        <div className={styles.infoRow}>
          <span className={styles.infoLabel}>Status</span>
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

        {report.cvss_score !== null && (
          <div className={styles.infoRow}>
            <span className={styles.infoLabel}>CVSS Score</span>
            <span className={styles.infoValue}>{report.cvss_score}</span>
          </div>
        )}

        {report.cwe_id && (
          <div className={styles.infoRow}>
            <span className={styles.infoLabel}>CWE</span>
            <span className={styles.infoValue}>{report.cwe_id}</span>
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

        {report.resolved_at && (
          <div className={styles.infoRow}>
            <span className={styles.infoLabel}>Resolved</span>
            <span className={styles.infoValue}>
              {formatDate(report.resolved_at)}
            </span>
          </div>
        )}

        {report.disclosed_at && (
          <div className={styles.infoRow}>
            <span className={styles.infoLabel}>Disclosed</span>
            <span className={styles.infoValue}>
              {formatDate(report.disclosed_at)}
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
          <Link to={ROUTES.REPORTS.LIST} className={styles.backLink}>
            Back to My Reports
          </Link>
          <h1 className={styles.title}>{report.title}</h1>
        </div>

        <div className={styles.layout}>
          <ReportContent report={report} />
          <Sidebar report={report} />
        </div>
      </div>
    </div>
  )
}

Component.displayName = 'ReportDetail'
