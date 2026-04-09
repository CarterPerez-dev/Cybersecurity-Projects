// ===================
// © AngelaMos | 2026
// shell.tsx
//
// Root application shell with error boundary and
// suspense wrapper around the router outlet
//
// Shell renders a full-page layout container with an
// ErrorBoundary (ShellErrorFallback displays the error
// message) wrapping a Suspense boundary (ShellLoading
// shows a spinner placeholder) around the react-router
// Outlet. All lazy-loaded page components resolve
// through this boundary pair, ensuring both loading
// states and uncaught render errors are handled at the
// top level
//
// Connects to:
//   routers.tsx        - mounted as parent route element
//   shell.module.scss  - shell, content, error, loading
//                        layout styles
//   pages/             - rendered via Outlet
// ===================

import { Suspense } from 'react'
import { ErrorBoundary } from 'react-error-boundary'
import { Outlet } from 'react-router-dom'
import styles from './shell.module.scss'

function ShellErrorFallback({ error }: { error: Error }): React.ReactElement {
  return (
    <div className={styles.error}>
      <h2>Something went wrong</h2>
      <pre>{error.message}</pre>
    </div>
  )
}

function ShellLoading(): React.ReactElement {
  return <div className={styles.loading}>Loading...</div>
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
