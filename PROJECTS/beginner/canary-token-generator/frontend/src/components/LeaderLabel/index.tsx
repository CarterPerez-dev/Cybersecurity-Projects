// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import type { PropsWithChildren, ReactNode } from 'react'
import styles from './LeaderLabel.module.scss'

type LeaderLabelProps = PropsWithChildren<{
  index?: string
  caption?: ReactNode
  align?: 'left' | 'right'
}>

export function LeaderLabel({
  children,
  index,
  caption,
  align = 'left',
}: LeaderLabelProps): React.ReactElement {
  return (
    <div className={styles.label} data-align={align}>
      <div className={styles.head}>
        {index ? <span className={styles.index}>{index}</span> : null}
        <span className={styles.rule} aria-hidden="true" />
      </div>
      <div className={styles.body}>{children}</div>
      {caption ? <div className={styles.caption}>{caption}</div> : null}
    </div>
  )
}
