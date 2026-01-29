/**
 * AngelaMos | 2026
 * index.tsx
 */

import { Link } from 'react-router-dom'
import { useMyPrograms } from '@/api/hooks'
import { type Program, STATUS_LABELS } from '@/api/types'
import { ROUTES } from '@/config'
import styles from './programs.module.scss'

function formatDate(dateString: string): string {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }).format(new Date(dateString))
}

function ProgramRow({ program }: { program: Program }): React.ReactElement {
  return (
    <div className={styles.row}>
      <div className={styles.cell}>
        <span className={styles.programName}>{program.name}</span>
        <span className={styles.programSlug}>/{program.slug}</span>
      </div>
      <div className={styles.cell}>
        <span className={styles.status} data-status={program.status}>
          {STATUS_LABELS[program.status]}
        </span>
      </div>
      <div className={styles.cell}>
        <span className={styles.date}>{formatDate(program.created_at)}</span>
      </div>
      <div className={styles.cell}>
        <div className={styles.actions}>
          <Link
            to={ROUTES.PROGRAMS.DETAIL(program.slug)}
            className={styles.actionBtn}
          >
            View
          </Link>
          <Link
            to={ROUTES.COMPANY.EDIT_PROGRAM(program.slug)}
            className={styles.actionBtn}
          >
            Edit
          </Link>
        </div>
      </div>
    </div>
  )
}

export function Component(): React.ReactElement {
  const { data, isLoading, error } = useMyPrograms(1, 50)

  if (isLoading) {
    return (
      <div className={styles.page}>
        <div className={styles.container}>
          <div className={styles.loading}>Loading programs...</div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className={styles.page}>
        <div className={styles.container}>
          <div className={styles.error}>Failed to load programs</div>
        </div>
      </div>
    )
  }

  const programs = data?.items ?? []

  return (
    <div className={styles.page}>
      <div className={styles.container}>
        <div className={styles.header}>
          <div>
            <h1 className={styles.title}>My Programs</h1>
            <p className={styles.subtitle}>Manage your bug bounty programs</p>
          </div>
          <Link to={ROUTES.COMPANY.NEW_PROGRAM} className={styles.createBtn}>
            Create Program
          </Link>
        </div>

        {programs.length === 0 ? (
          <div className={styles.empty}>
            <p>You haven't created any programs yet</p>
            <Link to={ROUTES.COMPANY.NEW_PROGRAM} className={styles.emptyBtn}>
              Create Your First Program
            </Link>
          </div>
        ) : (
          <div className={styles.table}>
            <div className={styles.tableHeader}>
              <span className={styles.headerCell}>Program</span>
              <span className={styles.headerCell}>Status</span>
              <span className={styles.headerCell}>Created</span>
              <span className={styles.headerCell}>Actions</span>
            </div>
            <div className={styles.tableBody}>
              {programs.map((program) => (
                <ProgramRow key={program.id} program={program} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

Component.displayName = 'CompanyPrograms'
