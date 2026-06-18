/**
 * ©AngelaMos | 2026
 * index.tsx
 */

import { Link } from 'react-router-dom'
import { RegMark } from '@/components'
import { ROUTES } from '@/config'
import styles from './landing.module.scss'

const FOOTNOTES = [
  'ja3 / ja4 / ja4+ / quic',
  'biometric overlays',
  'x-ray scans of bodies & objects',
  'timestamped data grids',
]

export function Component(): React.ReactElement {
  return (
    <div className={styles.page}>
      <img
        src="/assets/objects/xray-butterfly.jpg"
        alt=""
        className={styles.specimen}
      />
      <span className={styles.scan} />

      <RegMark className={styles.markTL} />
      <RegMark className={styles.markTR} />
      <RegMark className={styles.markBL} />
      <RegMark className={styles.markBR} />

      <header className={styles.head}>
        <span className={styles.kicker}>tls dossier / passive</span>
        <span className={styles.stamp}>specimen 006 / handshake</span>
      </header>

      <main className={styles.center}>
        <span className={styles.over}>sleep is counter surveillance</span>
        <h1 className={styles.title}>TLSFP</h1>
        <span className={styles.under}>
          the fingerprint of every client that speaks tls
        </span>
        <p className={styles.thesis}>
          An x-ray of the handshake. Every client carries a fingerprint it cannot
          hide, and the instant a user-agent claims to be a browser while its
          fingerprint is a script, the lie is on the table.
        </p>
        <Link to={ROUTES.SCOPE} className={styles.enter}>
          <span className={styles.enterMark}>-&gt;</span>
          <span>enter the scope</span>
        </Link>
      </main>

      <footer className={styles.foot}>
        {FOOTNOTES.map((note) => (
          <span key={note} className={styles.note}>
            {note}
          </span>
        ))}
      </footer>
    </div>
  )
}

Component.displayName = 'Landing'
