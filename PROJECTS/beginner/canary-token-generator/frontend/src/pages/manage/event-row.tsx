// ===================
// ©AngelaMos | 2026
// event-row.tsx
// ===================

import type { EventResponse, GeoView } from '@/api'
import { Pill } from '@/components'
import { NOTIFY_TONE } from './copy'
import styles from './manage.module.scss'

type EventRowProps = {
  event: EventResponse
  index: number
}

export function EventRow({ event, index }: EventRowProps): React.ReactElement {
  const tone = NOTIFY_TONE[event.notify_status] ?? 'paper'
  return (
    <article className={styles.eventRow}>
      <header className={styles.eventHead}>
        <span className={styles.eventIndex}>
          {String(index).padStart(4, '0')}
        </span>
        <time className={styles.eventTime} dateTime={event.triggered_at}>
          {formatTimestamp(event.triggered_at)}
        </time>
        <Pill tone={tone} size="sm">
          {event.notify_status}
        </Pill>
      </header>
      <div className={styles.eventGrid}>
        <EventField label="src ip" mono>
          {event.source_ip}
        </EventField>
        <EventField label="geo">{formatGeo(event.geo)}</EventField>
        {event.geo.asn ? (
          <EventField label="asn" mono>
            AS{event.geo.asn}
            {event.geo.asn_org ? ` · ${event.geo.asn_org}` : ''}
          </EventField>
        ) : null}
        <EventField label="user agent" wide truncate>
          {event.user_agent ?? '—'}
        </EventField>
        {event.referer ? (
          <EventField label="referer" wide truncate>
            {event.referer}
          </EventField>
        ) : null}
        {event.notified_at ? (
          <EventField label="notified" mono>
            {formatTimestamp(event.notified_at)}
          </EventField>
        ) : null}
      </div>
      {hasExtraDetails(event.extra) ? (
        <details className={styles.eventExtra}>
          <summary>extra fingerprint</summary>
          <pre className={styles.eventExtraBody}>
            {JSON.stringify(event.extra, null, 2)}
          </pre>
        </details>
      ) : null}
    </article>
  )
}

type EventFieldProps = React.PropsWithChildren<{
  label: string
  mono?: boolean
  wide?: boolean
  truncate?: boolean
}>

function EventField({
  label,
  mono = false,
  wide = false,
  truncate = false,
  children,
}: EventFieldProps): React.ReactElement {
  return (
    <div
      className={styles.eventField}
      data-mono={mono}
      data-wide={wide}
      data-truncate={truncate}
    >
      <span className={styles.eventLabel}>{label}</span>
      <span className={styles.eventValue}>{children}</span>
    </div>
  )
}

function formatTimestamp(iso: string): string {
  try {
    const dt = new Date(iso)
    return dt
      .toISOString()
      .replace('T', ' ')
      .replace(/\.\d+Z$/, 'Z')
  } catch (_err) {
    return iso
  }
}

function formatGeo(geo: GeoView): string {
  const parts: string[] = []
  if (geo.city) parts.push(geo.city)
  if (geo.region) parts.push(geo.region)
  if (geo.country) parts.push(geo.country)
  if (parts.length === 0) {
    return '—'
  }
  return parts.join(' · ')
}

function hasExtraDetails(extra: unknown): boolean {
  if (extra == null) return false
  if (typeof extra !== 'object') return false
  return Object.keys(extra as Record<string, unknown>).length > 0
}
