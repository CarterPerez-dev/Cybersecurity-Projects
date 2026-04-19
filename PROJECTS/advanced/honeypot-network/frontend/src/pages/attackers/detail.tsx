// ©AngelaMos | 2026
// detail.tsx

import { Link, useParams } from 'react-router-dom'
import { useAttacker } from '@/api/hooks'
import styles from './attackers.module.scss'

export function AttackerDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: attacker, isLoading } = useAttacker(Number(id))

  if (isLoading || !attacker) {
    return <div className={styles.loading}>LOADING ...</div>
  }

  const rows = [
    {
      label: 'COUNTRY',
      value: `${attacker.geo.country} (${attacker.geo.country_code})`,
    },
    { label: 'CITY', value: attacker.geo.city || '\u2014' },
    {
      label: 'ASN / ORG',
      value: `AS${attacker.geo.asn} ${attacker.geo.org}`,
    },
    {
      label: 'TOTAL EVENTS',
      value: attacker.total_events.toLocaleString(),
    },
    { label: 'SESSIONS', value: String(attacker.total_sessions) },
    { label: 'TOOL FAMILY', value: attacker.tool_family || '\u2014' },
    {
      label: 'FIRST SEEN',
      value: new Date(attacker.first_seen).toLocaleString(),
    },
    {
      label: 'LAST SEEN',
      value: new Date(attacker.last_seen).toLocaleString(),
    },
  ]

  return (
    <div className={styles.page}>
      <Link to="/attackers" className={styles.back}>
        &#8592; ATTACKERS
      </Link>

      <h1 className={styles.detailTitle}>{attacker.ip}</h1>

      <div className={styles.dossier}>
        {rows.map((row) => (
          <div key={row.label} className={styles.dossierRow}>
            <span className={styles.dossierLabel}>{row.label}</span>
            <span className={styles.dossierValue}>{row.value}</span>
          </div>
        ))}

        <div className={styles.dossierRow}>
          <span className={styles.dossierLabel}>THREAT SCORE</span>
          <span
            className={`${styles.dossierValue} ${styles.threatValue}`}
          >
            {attacker.threat_score}
          </span>
        </div>

        {attacker.tags && attacker.tags.length > 0 && (
          <div className={styles.dossierRow}>
            <span className={styles.dossierLabel}>TAGS</span>
            <span className={styles.dossierValue}>
              <span className={styles.tags}>
                {attacker.tags.map((tag) => (
                  <span key={tag} className={styles.tag}>
                    {tag}
                  </span>
                ))}
              </span>
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
