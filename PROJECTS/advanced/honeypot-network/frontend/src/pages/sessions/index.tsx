// ©AngelaMos | 2026
// index.tsx

import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useSessions } from '@/api/hooks'
import { ServiceBadge } from '@/components/service-badge'
import styles from './sessions.module.scss'

const PAGE_SIZE = 50

export function SessionsPage() {
  const [offset, setOffset] = useState(0)
  const { data, isLoading } = useSessions(PAGE_SIZE, offset)
  const sessions = data?.data ?? []
  const total = data?.total ?? 0

  return (
    <div className={styles.page}>
      <header className={styles.heading}>
        <h1 className={styles.title}>Sessions</h1>
        <span className={styles.subtitle}>RECORDED ENCOUNTERS</span>
      </header>

      {isLoading ? (
        <div className={styles.loading}>LOADING ...</div>
      ) : (
        <>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>ID</th>
                <th>Service</th>
                <th>Source IP</th>
                <th>Username</th>
                <th>Commands</th>
                <th>Threat</th>
                <th>Started</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => {
                const duration = s.ended_at
                  ? Math.round(
                      (new Date(s.ended_at).getTime() -
                        new Date(s.started_at).getTime()) /
                        1000
                    )
                  : null

                return (
                  <tr key={s.id}>
                    <td>
                      <Link
                        to={`/sessions/${s.id}`}
                        className={styles.link}
                      >
                        {s.id.slice(0, 8)}
                      </Link>
                    </td>
                    <td>
                      <ServiceBadge service={s.service_type} />
                    </td>
                    <td>{s.source_ip}</td>
                    <td>{s.username || '\u2014'}</td>
                    <td>{s.command_count}</td>
                    <td className={styles.threat}>{s.threat_score}</td>
                    <td>{new Date(s.started_at).toLocaleString()}</td>
                    <td>
                      {duration !== null ? `${duration}s` : 'active'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>

          <div className={styles.pagination}>
            <button
              type="button"
              className={styles.pageBtn}
              disabled={offset === 0}
              onClick={() =>
                setOffset(Math.max(0, offset - PAGE_SIZE))
              }
            >
              &#9664; PREV
            </button>
            <span className={styles.pageInfo}>
              {offset + 1}&ndash;{Math.min(offset + PAGE_SIZE, total)}{' '}
              OF {total}
            </span>
            <button
              type="button"
              className={styles.pageBtn}
              disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              NEXT &#9654;
            </button>
          </div>
        </>
      )}
    </div>
  )
}
