// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import { Link } from 'react-router-dom'
import { Strip, StripItem } from '@/components'
import styles from './notfound.module.scss'

export function Component(): React.ReactElement {
  return (
    <div className={styles.page}>
      <Strip>
        <StripItem label="FIELD STATION">canary</StripItem>
        <StripItem label="STATUS" inverted>
          off-route
        </StripItem>
      </Strip>
      <main className={styles.body}>
        <p className={styles.index}>404 · OFF-ROUTE</p>
        <h1 className={styles.headline}>NO SPECIMEN HERE</h1>
        <p className={styles.purpose}>
          This path is not part of the catalog. Maybe a typo, maybe a deleted
          dossier. The intake is still open.
        </p>
        <Link to="/" className={styles.link}>
          ← back to intake
        </Link>
      </main>
    </div>
  )
}

Component.displayName = 'NotFound'
