// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import type { PropsWithChildren, ReactNode } from 'react'
import styles from './Strip.module.scss'

type StripProps = PropsWithChildren<{
  align?: 'left' | 'split'
  border?: 'bottom' | 'top' | 'both' | 'none'
}>

export function Strip({
  children,
  align = 'split',
  border = 'bottom',
}: StripProps): React.ReactElement {
  return (
    <div className={styles.strip} data-align={align} data-border={border}>
      {children}
    </div>
  )
}

type StripItemProps = PropsWithChildren<{
  inverted?: boolean
  label?: string
  mark?: ReactNode
}>

export function StripItem({
  children,
  inverted = false,
  label,
  mark,
}: StripItemProps): React.ReactElement {
  return (
    <span className={styles.item} data-inverted={inverted}>
      {mark ? (
        <span className={styles.mark} aria-hidden="true">
          {mark}
        </span>
      ) : null}
      {label ? <span className={styles.label}>{label}</span> : null}
      <span className={styles.value}>{children}</span>
    </span>
  )
}
