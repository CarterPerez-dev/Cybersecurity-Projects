// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import type { PropsWithChildren, ReactNode } from 'react'
import styles from './DataRow.module.scss'

type DataRowProps = PropsWithChildren<{
  label: ReactNode
  mono?: boolean
  emphasize?: boolean
  alarm?: boolean
}>

export function DataRow({
  label,
  children,
  mono = false,
  emphasize = false,
  alarm = false,
}: DataRowProps): React.ReactElement {
  return (
    <div className={styles.row} data-alarm={alarm}>
      <span className={styles.label}>{label}</span>
      <span className={styles.leader} aria-hidden="true" />
      <span className={styles.value} data-mono={mono} data-emphasize={emphasize}>
        {children}
      </span>
    </div>
  )
}
