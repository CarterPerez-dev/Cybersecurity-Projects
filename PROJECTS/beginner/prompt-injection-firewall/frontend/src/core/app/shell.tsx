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
      <h2>{COPY.ERRORS.DEFAULT}</h2>
      <pre>{error.message}</pre>
    </div>
  )
}

function ShellLoading(): React.ReactElement {
  return <div className={styles.loading}>{COPY.SUBMITTING}</div>
}

export function Shell(): React.ReactElement {
  return (
    <div className={styles.shell}>
      <main className={styles.content}>
        <ErrorBoundary FallbackComponent={ShellErrorFallback}>
          <Suspense fallback={<ShellLoading />}>
            <Outlet />
          </Suspense>
        </ErrorBoundary>
      </main>
    </div>
  )
}
