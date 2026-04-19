// ©AngelaMos | 2026
// event-feed.tsx

import { useWebSocketStore } from '@/core/lib/websocket.store'
import { ServiceBadge } from './service-badge'
import styles from './event-feed.module.scss'

const MAX_VISIBLE = 15

export function EventFeed() {
  const events = useWebSocketStore((s) => s.events)
  const visible = events.slice(0, MAX_VISIBLE)

  if (visible.length === 0) {
    return <div className={styles.empty}>AWAITING SIGNAL ...</div>
  }

  return (
    <div className={styles.feed}>
      {visible.map((ev) => (
        <div key={ev.id} className={styles.entry}>
          <span className={styles.time}>
            {new Date(ev.timestamp).toLocaleTimeString()}
          </span>
          <ServiceBadge service={ev.service_type} />
          <span className={styles.type}>{ev.event_type}</span>
          <span className={styles.ip}>{ev.source_ip}</span>
        </div>
      ))}
    </div>
  )
}
