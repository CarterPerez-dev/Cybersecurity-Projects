/**
 * AngelaMos | 2026
 * index.tsx
 */

import { useState } from 'react'
import { LuPencil, LuX } from 'react-icons/lu'
import { useAdminReports, useAdminUpdateReport } from '@/api/hooks'
import {
  type AdminReportResponse,
  type AdminReportUpdate,
  REPORT_STATUS_LABELS,
  type ReportStatus,
  SEVERITY_LABELS,
  type Severity,
} from '@/api/types'
import { PAGINATION } from '@/config'
import styles from './reports.module.scss'

type ModalState =
  | { type: 'closed' }
  | { type: 'edit'; report: AdminReportResponse }

export function Component(): React.ReactElement {
  const [page, setPage] = useState<number>(PAGINATION.DEFAULT_PAGE)
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [severityFilter, setSeverityFilter] = useState<string>('')
  const [modal, setModal] = useState<ModalState>({ type: 'closed' })

  const { data, isLoading } = useAdminReports({
    page,
    size: PAGINATION.DEFAULT_SIZE,
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
  })
  const updateReport = useAdminUpdateReport()

  const handleUpdate = (reportId: string, formData: FormData): void => {
    const updateData: AdminReportUpdate = {}

    const status = formData.get('status') as ReportStatus
    if (status) updateData.status = status

    const severityFinal = formData.get('severity_final') as Severity
    if (severityFinal) updateData.severity_final = severityFinal

    const bountyAmountStr = formData.get('bounty_amount') as string
    if (bountyAmountStr) {
      updateData.bounty_amount = Math.round(parseFloat(bountyAmountStr) * 100)
    }

    updateReport.mutate(
      { id: reportId, data: updateData },
      { onSuccess: () => setModal({ type: 'closed' }) }
    )
  }

  const formatCurrency = (cents: number | null): string => {
    if (cents === null) return '-'
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
    }).format(cents / 100)
  }

  const toCamelCase = (str: string): string =>
    str.replace(/_([a-z])/g, (_, letter: string) => letter.toUpperCase())

  const totalPages = data ? Math.ceil(data.total / PAGINATION.DEFAULT_SIZE) : 0

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>Reports</h1>
        <div className={styles.filters}>
          <select
            className={styles.filterSelect}
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value)
              setPage(1)
            }}
          >
            <option value="">All Statuses</option>
            {Object.entries(REPORT_STATUS_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <select
            className={styles.filterSelect}
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value)
              setPage(1)
            }}
          >
            <option value="">All Severities</option>
            {Object.entries(SEVERITY_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className={styles.table}>
        <div className={styles.tableHeader}>
          <div className={styles.tableHeaderCell}>Report</div>
          <div className={styles.tableHeaderCell}>Program</div>
          <div className={styles.tableHeaderCell}>Researcher</div>
          <div className={styles.tableHeaderCell}>Severity</div>
          <div className={styles.tableHeaderCell}>Status</div>
          <div className={styles.tableHeaderCell}>Bounty</div>
          <div className={styles.tableHeaderCell}>Actions</div>
        </div>

        <div className={styles.tableBody}>
          {isLoading && <div className={styles.loading}>Loading...</div>}

          {!isLoading && data?.items.length === 0 && (
            <div className={styles.empty}>No reports found</div>
          )}

          {data?.items.map((report) => (
            <div key={report.id} className={styles.tableRow}>
              <div className={styles.tableCell} data-label="Report">
                <span className={styles.reportTitle}>{report.title}</span>
              </div>
              <div className={styles.tableCell} data-label="Program">
                <span className={styles.programName}>{report.program_name}</span>
              </div>
              <div className={styles.tableCell} data-label="Researcher">
                <div className={styles.researcherInfo}>
                  <span className={styles.researcherName}>
                    {report.researcher_name ?? 'Anonymous'}
                  </span>
                  <span className={styles.researcherEmail}>
                    {report.researcher_email}
                  </span>
                </div>
              </div>
              <div className={styles.tableCell} data-label="Severity">
                <span
                  className={`${styles.severityBadge} ${styles[report.severity_final ?? report.severity_submitted]}`}
                >
                  {
                    SEVERITY_LABELS[
                      report.severity_final ?? report.severity_submitted
                    ]
                  }
                </span>
              </div>
              <div className={styles.tableCell} data-label="Status">
                <span
                  className={`${styles.statusBadge} ${styles[toCamelCase(report.status)]}`}
                >
                  {REPORT_STATUS_LABELS[report.status]}
                </span>
              </div>
              <div className={styles.tableCell} data-label="Bounty">
                <span className={styles.bountyAmount}>
                  {formatCurrency(report.bounty_amount)}
                </span>
              </div>
              <div className={styles.actions}>
                <button
                  type="button"
                  className={styles.actionBtn}
                  onClick={() => setModal({ type: 'edit', report })}
                  aria-label="Edit report"
                >
                  <LuPencil />
                </button>
              </div>
            </div>
          ))}
        </div>

        {data && data.total > PAGINATION.DEFAULT_SIZE && (
          <div className={styles.pagination}>
            <span className={styles.paginationInfo}>
              Page {page} of {totalPages} ({data.total} reports)
            </span>
            <div className={styles.paginationBtns}>
              <button
                type="button"
                className={styles.paginationBtn}
                onClick={() => setPage((p) => p - 1)}
                disabled={page <= 1}
              >
                Previous
              </button>
              <button
                type="button"
                className={styles.paginationBtn}
                onClick={() => setPage((p) => p + 1)}
                disabled={page >= totalPages}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {modal.type === 'edit' && (
        <div className={styles.modal}>
          <button
            type="button"
            className={styles.modalOverlay}
            onClick={() => setModal({ type: 'closed' })}
            onKeyDown={(e) => e.key === 'Escape' && setModal({ type: 'closed' })}
            aria-label="Close modal"
          />
          <div className={styles.modalContent}>
            <div className={styles.modalHeader}>
              <h2 className={styles.modalTitle}>Override Report</h2>
              <button
                type="button"
                className={styles.modalClose}
                onClick={() => setModal({ type: 'closed' })}
              >
                <LuX />
              </button>
            </div>
            <form
              className={styles.form}
              onSubmit={(e) => {
                e.preventDefault()
                handleUpdate(modal.report.id, new FormData(e.currentTarget))
              }}
            >
              <div className={styles.reportLabel}>
                {modal.report.title}
                <span className={styles.reportSubLabel}>
                  {modal.report.program_name} - {modal.report.researcher_email}
                </span>
              </div>
              <div className={styles.field}>
                <label className={styles.label} htmlFor="editStatus">
                  Status
                </label>
                <select
                  id="editStatus"
                  name="status"
                  className={styles.select}
                  defaultValue={modal.report.status}
                >
                  {Object.entries(REPORT_STATUS_LABELS).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </div>
              <div className={styles.field}>
                <label className={styles.label} htmlFor="editSeverity">
                  Final Severity
                </label>
                <select
                  id="editSeverity"
                  name="severity_final"
                  className={styles.select}
                  defaultValue={modal.report.severity_final ?? ''}
                >
                  <option value="">Not set</option>
                  {Object.entries(SEVERITY_LABELS).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </div>
              <div className={styles.field}>
                <label className={styles.label} htmlFor="editBounty">
                  Bounty Amount ($)
                </label>
                <input
                  id="editBounty"
                  name="bounty_amount"
                  type="number"
                  step="0.01"
                  min="0"
                  className={styles.input}
                  defaultValue={
                    modal.report.bounty_amount !== null
                      ? (modal.report.bounty_amount / 100).toFixed(2)
                      : ''
                  }
                  placeholder="0.00"
                />
              </div>
              <div className={styles.formActions}>
                <button
                  type="button"
                  className={styles.cancelBtn}
                  onClick={() => setModal({ type: 'closed' })}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className={styles.submitBtn}
                  disabled={updateReport.isPending}
                >
                  {updateReport.isPending ? 'Saving...' : 'Save Override'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

Component.displayName = 'AdminReports'
