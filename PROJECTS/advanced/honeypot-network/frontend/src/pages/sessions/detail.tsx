// ©AngelaMos | 2026
// detail.tsx

import { Link, useParams } from 'react-router-dom'
import { useSession, useSessionReplay } from '@/api/hooks'
import { ServiceBadge } from '@/components/service-badge'
import { SessionPlayer } from '@/components/session-player'
import styles from './sessions.module.scss'

export function SessionDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: session, isLoading } = useSession(id ?? '')
  const { data: replayData } = useSessionReplay(id ?? '')

  if (isLoading || !session) {
    return <div className={styles.loading}>LOADING ...</div>
  }

  const rows = [
    { label: 'SERVICE', value: <ServiceBadge service={session.service_type} /> },
    { label: 'SOURCE', value: `${session.source_ip}:${session.source_port}` },
    { label: 'USERNAME', value: session.username || '\u2014' },
    { label: 'COMMANDS', value: String(session.command_count) },
    { label: 'THREAT SCORE', value: String(session.threat_score) },
    { label: 'STARTED', value: new Date(session.started_at).toLocaleString() },
    {
      label: 'ENDED',
      value: session.ended_at
        ? new Date(session.ended_at).toLocaleString()
        : 'Active',
    },
  ]

  if (session.mitre_techniques && session.mitre_techniques.length > 0) {
    rows.push({
      label: 'MITRE',
      value: session.mitre_techniques.join(', '),
    })
  }

  return (
    <div className={styles.page}>
      <Link to="/sessions" className={styles.back}>
        &#8592; SESSIONS
      </Link>

      <h1 className={styles.detailTitle}>
        SESSION {session.id.slice(0, 8)}
      </h1>

      <div className={styles.dossier}>
        {rows.map((row) => (
          <div key={row.label} className={styles.dossierRow}>
            <span className={styles.dossierLabel}>{row.label}</span>
            <span className={styles.dossierValue}>{row.value}</span>
          </div>
        ))}
      </div>

      {replayData && (
        <>
          <h2 className={styles.replayHeading}>Session Replay</h2>
          <SessionPlayer castData={replayData} />
        </>
      )}
    </div>
  )
}
