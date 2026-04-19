// ©AngelaMos | 2026
// index.tsx

import { Link } from 'react-router-dom'
import { useAttackers } from '@/api/hooks'
import styles from './attackers.module.scss'

export function AttackersPage() {
  const { data: attackers, isLoading } = useAttackers()

  return (
    <div className={styles.page}>
      <header className={styles.heading}>
        <h1 className={styles.title}>Attackers</h1>
        <span className={styles.subtitle}>THREAT ACTOR DATABASE</span>
      </header>

      {isLoading ? (
        <div className={styles.loading}>LOADING ...</div>
      ) : (
        <table className={styles.table}>
          <thead>
            <tr>
              <th>IP</th>
              <th>Country</th>
              <th>Events</th>
              <th>Sessions</th>
              <th>Tool Family</th>
              <th>Threat Score</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {attackers?.map((a) => (
              <tr key={a.id}>
                <td>
                  <Link
                    to={`/attackers/${a.id}`}
                    className={styles.link}
                  >
                    {a.ip}
                  </Link>
                </td>
                <td>
                  {a.geo.country_code}
                  {a.geo.city ? ` \u2014 ${a.geo.city}` : ''}
                </td>
                <td>{a.total_events}</td>
                <td>{a.total_sessions}</td>
                <td>{a.tool_family || '\u2014'}</td>
                <td className={styles.threat}>{a.threat_score}</td>
                <td>{new Date(a.last_seen).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
