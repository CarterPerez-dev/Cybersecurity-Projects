/**
 * AngelaMos | 2025
 * index.tsx
 */

import { useState } from 'react'
import { Link } from 'react-router-dom'
import { usePrograms } from '@/api/hooks'
import { type Program, STATUS_LABELS } from '@/api/types'
import { ROUTES } from '@/config'
import styles from './programs.module.scss'

function ProgramCard({ program }: { program: Program }): React.ReactElement {
  return (
    <Link to={ROUTES.PROGRAMS.DETAIL(program.slug)} className={styles.card}>
      <div className={styles.cardHeader}>
        <h3 className={styles.cardTitle}>{program.name}</h3>
        <span className={styles.status} data-status={program.status}>
          {STATUS_LABELS[program.status]}
        </span>
      </div>
      <p className={styles.cardDescription}>
        {program.description ?? 'No description provided'}
      </p>
      <div className={styles.cardFooter}>
        <span className={styles.sla}>
          Response SLA: {program.response_sla_hours}h
        </span>
      </div>
    </Link>
  )
}

export function Component(): React.ReactElement {
  const [page, setPage] = useState(1)
  const { data, isLoading, error } = usePrograms(page, 20)

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
  const total = data?.total ?? 0
  const totalPages = Math.ceil(total / 20)

  return (
    <div className={styles.page}>
      <div className={styles.container}>
        <div className={styles.header}>
          <h1 className={styles.title}>Bug Bounty Programs</h1>
          <p className={styles.subtitle}>
            {total} active program{total !== 1 ? 's' : ''} available
          </p>
        </div>

        {programs.length === 0 ? (
          <div className={styles.empty}>
            <p>No programs available yet</p>
          </div>
        ) : (
          <>
            <div className={styles.grid}>
              {programs.map((program) => (
                <ProgramCard key={program.id} program={program} />
              ))}
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

Component.displayName = 'Programs'
