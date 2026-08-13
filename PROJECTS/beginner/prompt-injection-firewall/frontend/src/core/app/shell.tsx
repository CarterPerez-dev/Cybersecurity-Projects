/**
 * ©AngelaMos | 2026
 * shell.tsx
 */

import { Suspense } from 'react'
import { ErrorBoundary } from 'react-error-boundary'
import { Outlet } from 'react-router-dom'
import { COPY } from '@/config'
import styles from './shell.module.scss'

function ShellErrorFallback({ error }: { error: Error }): React.ReactElement {
  return (
    <div className={styles.error}>
      <h2 className={styles.errorHeading}>{COPY.ERRORS.DEFAULT}</h2>
      <pre className={styles.errorBody}>{error.message}</pre>
    </div>
  )
}

function ShellLoading(): React.ReactElement {
  return <div className={styles.loading}>{COPY.SUBMITTING}</div>
}

export function Shell(): React.ReactElement {
  return (
    <div className={styles.shell}>
      <div className={styles.sheet}>
        <header className={styles.strip}>
          <div className={styles.stripCell}>
            <span className={styles.stripKey}>{COPY.UNIT_ID}</span>
            <span className={styles.stripValue}>{COPY.UNIT_ROLE}</span>
          </div>
          <div className={styles.stripCell}>
            <span className={styles.stripKey}>{COPY.NODE}</span>
            <span className={styles.stripValue}>{COPY.NODE_STATE}</span>
          </div>
          <div className={`${styles.stripCell} ${styles.stripCellEnd}`}>
            <span className={styles.stripKey}>{COPY.ORIGIN}</span>
            <span className={styles.stripValue}>{COPY.ORIGIN_DETAIL}</span>
          </div>
        </header>

        <main className={styles.content}>
          <ErrorBoundary FallbackComponent={ShellErrorFallback}>
            <Suspense fallback={<ShellLoading />}>
              <Outlet />
            </Suspense>
          </ErrorBoundary>
        </main>

        <footer className={styles.strip}>
          <span className={styles.stripValue}>{COPY.FOOTER_SPEC}</span>
          <span className={styles.stripValue}>{COPY.FOOTER_BUILD}</span>
          <span className={`${styles.stripValue} ${styles.stripCellEnd}`}>
            {COPY.FOOTER_MARK}
          </span>
        </footer>
      </div>
    </div>
  )
}
