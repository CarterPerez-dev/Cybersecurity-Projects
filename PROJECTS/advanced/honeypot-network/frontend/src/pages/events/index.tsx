// ©AngelaMos | 2026
// index.tsx

import { useState } from 'react'
import { useEvents } from '@/api/hooks'
import { ServiceBadge } from '@/components/service-badge'
import styles from './events.module.scss'

const PAGE_SIZE = 50

export function EventsPage() {
  const [ipFilter, setIpFilter] = useState('')
  const { data: events, isLoading } = useEvents(
    PAGE_SIZE,
    ipFilter || undefined
  )

  return (
    <div className={styles.page}>
      <header className={styles.heading}>
        <div className={styles.headingLeft}>
          <h1 className={styles.title}>Events</h1>
          <span className={styles.subtitle}>SYSTEM EVENT LOG</span>
        </div>
        <div className={styles.filterGroup}>
          <span className={styles.filterLabel}>FILTER IP</span>
          <input
            className={styles.filter}
            type="text"
            placeholder="0.0.0.0"
            value={ipFilter}
            onChange={(e) => setIpFilter(e.target.value)}
          />
        </div>
      </header>

      {isLoading ? (
        <div className={styles.loading}>LOADING ...</div>
      ) : (
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Time</th>
              <th>Service</th>
              <th>Type</th>
              <th>Source IP</th>
              <th>Port</th>
              <th>Session</th>
            </tr>
          </thead>
          <tbody>
            {events?.map((ev) => (
              <tr key={ev.id}>
                <td>{new Date(ev.timestamp).toLocaleString()}</td>
                <td>
                  <ServiceBadge service={ev.service_type} />
                </td>
                <td>{ev.event_type}</td>
                <td>{ev.source_ip}</td>
                <td>{ev.dest_port}</td>
                <td className={styles.dim}>{ev.session_id.slice(0, 8)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
