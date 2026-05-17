// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import type { PropsWithChildren } from 'react'
import styles from './Pill.module.scss'

type PillProps = PropsWithChildren<{
  tone?: 'paper' | 'ink' | 'alarm' | 'signal'
  size?: 'sm' | 'md'
}>

export function Pill({
  children,
  tone = 'paper',
  size = 'sm',
}: PillProps): React.ReactElement {
  return (
    <span className={styles.pill} data-tone={tone} data-size={size}>
      {children}
    </span>
  )
}
