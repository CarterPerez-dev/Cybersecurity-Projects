/**
 * AngelaMos | 2026
 * index.tsx
 */

import { useState } from 'react'
import { LuPencil, LuTrash2, LuX } from 'react-icons/lu'
import {
  useAdminDeleteProgram,
  useAdminPrograms,
  useAdminUpdateProgram,
} from '@/api/hooks'
import {
  type AdminProgramResponse,
  type ProgramStatus,
  ProgramVisibility,
  STATUS_LABELS,
} from '@/api/types'
import { PAGINATION } from '@/config'
import styles from './programs.module.scss'

type ModalState =
  | { type: 'closed' }
  | { type: 'edit'; program: AdminProgramResponse }
  | { type: 'delete'; program: AdminProgramResponse }

export function Component(): React.ReactElement {
  const [page, setPage] = useState<number>(PAGINATION.DEFAULT_PAGE)
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [modal, setModal] = useState<ModalState>({ type: 'closed' })

  const { data, isLoading } = useAdminPrograms({
    page,
    size: PAGINATION.DEFAULT_SIZE,
    status: statusFilter || undefined,
  })
  const updateProgram = useAdminUpdateProgram()
  const deleteProgram = useAdminDeleteProgram()

  const handleUpdate = (programId: string, formData: FormData): void => {
    const status = formData.get('status') as ProgramStatus
    const visibility = formData.get('visibility') as ProgramVisibility

    updateProgram.mutate(
      { id: programId, data: { status, visibility } },
      { onSuccess: () => setModal({ type: 'closed' }) }
    )
  }

  const handleDelete = (programId: string): void => {
    deleteProgram.mutate(programId, {
      onSuccess: () => setModal({ type: 'closed' }),
    })
  }

  const totalPages = data ? Math.ceil(data.total / PAGINATION.DEFAULT_SIZE) : 0

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>Programs</h1>
        <select
          className={styles.filterSelect}
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value)
            setPage(1)
          }}
        >
          <option value="">All Statuses</option>
          {Object.entries(STATUS_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </div>

      <div className={styles.table}>
        <div className={styles.tableHeader}>
          <div className={styles.tableHeaderCell}>Program</div>
          <div className={styles.tableHeaderCell}>Company</div>
          <div className={styles.tableHeaderCell}>Status</div>
          <div className={styles.tableHeaderCell}>Visibility</div>
          <div className={styles.tableHeaderCell}>Reports</div>
          <div className={styles.tableHeaderCell}>Actions</div>
        </div>

        <div className={styles.tableBody}>
          {isLoading && <div className={styles.loading}>Loading...</div>}

          {!isLoading && data?.items.length === 0 && (
            <div className={styles.empty}>No programs found</div>
          )}

          {data?.items.map((program) => (
            <div key={program.id} className={styles.tableRow}>
              <div className={styles.tableCell} data-label="Program">
                <div className={styles.programInfo}>
                  <span className={styles.programName}>{program.name}</span>
                  <span className={styles.programSlug}>/{program.slug}</span>
                </div>
              </div>
              <div className={styles.tableCell} data-label="Company">
                <div className={styles.companyInfo}>
                  <span className={styles.companyName}>
                    {program.company_name ?? 'N/A'}
                  </span>
                  <span className={styles.companyEmail}>
                    {program.company_email}
                  </span>
                </div>
              </div>
              <div className={styles.tableCell} data-label="Status">
                <span className={`${styles.badge} ${styles[program.status]}`}>
                  {STATUS_LABELS[program.status]}
                </span>
              </div>
              <div className={styles.tableCell} data-label="Visibility">
                <span className={styles.visibility}>{program.visibility}</span>
              </div>
              <div className={styles.tableCell} data-label="Reports">
                <span className={styles.reportCount}>{program.report_count}</span>
              </div>
              <div className={styles.actions}>
                <button
                  type="button"
                  className={styles.actionBtn}
                  onClick={() => setModal({ type: 'edit', program })}
                  aria-label="Edit program"
                >
                  <LuPencil />
                </button>
                <button
                  type="button"
                  className={`${styles.actionBtn} ${styles.delete}`}
                  onClick={() => setModal({ type: 'delete', program })}
                  aria-label="Delete program"
                >
                  <LuTrash2 />
                </button>
              </div>
            </div>
          ))}
        </div>

        {data && data.total > PAGINATION.DEFAULT_SIZE && (
          <div className={styles.pagination}>
            <span className={styles.paginationInfo}>
              Page {page} of {totalPages} ({data.total} programs)
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
              <h2 className={styles.modalTitle}>Edit Program</h2>
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
                handleUpdate(modal.program.id, new FormData(e.currentTarget))
              }}
            >
              <div className={styles.programLabel}>
                {modal.program.name}
                <span className={styles.programSubLabel}>
                  by {modal.program.company_name ?? modal.program.company_email}
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
                  defaultValue={modal.program.status}
                >
                  {Object.entries(STATUS_LABELS).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </div>
              <div className={styles.field}>
                <label className={styles.label} htmlFor="editVisibility">
                  Visibility
                </label>
                <select
                  id="editVisibility"
                  name="visibility"
                  className={styles.select}
                  defaultValue={modal.program.visibility}
                >
                  <option value={ProgramVisibility.PUBLIC}>Public</option>
                  <option value={ProgramVisibility.PRIVATE}>Private</option>
                  <option value={ProgramVisibility.INVITE_ONLY}>
                    Invite Only
                  </option>
                </select>
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
                  disabled={updateProgram.isPending}
                >
                  {updateProgram.isPending ? 'Saving...' : 'Save'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {modal.type === 'delete' && (
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
              <h2 className={styles.modalTitle}>Delete Program</h2>
              <button
                type="button"
                className={styles.modalClose}
                onClick={() => setModal({ type: 'closed' })}
              >
                <LuX />
              </button>
            </div>
            <div className={styles.deleteConfirm}>
              <p className={styles.deleteText}>
                Are you sure you want to delete{' '}
                <span className={styles.deleteName}>{modal.program.name}</span>?
                This will permanently remove the program and all associated data.
              </p>
              <div className={styles.formActions}>
                <button
                  type="button"
                  className={styles.cancelBtn}
                  onClick={() => setModal({ type: 'closed' })}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className={styles.deleteBtn}
                  onClick={() => handleDelete(modal.program.id)}
                  disabled={deleteProgram.isPending}
                >
                  {deleteProgram.isPending ? 'Deleting...' : 'Delete'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

Component.displayName = 'AdminPrograms'
