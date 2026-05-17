// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import type { PropsWithChildren, ReactNode } from 'react'
import styles from './SpecimenCard.module.scss'

type SpecimenCardProps = PropsWithChildren<{
  tag?: ReactNode
  serial?: ReactNode
  tone?: 'paper' | 'ink' | 'alarm'
  dense?: boolean
}>

export function SpecimenCard({
  children,
  tag,
  serial,
  tone = 'paper',
  dense = false,
}: SpecimenCardProps): React.ReactElement {
  return (
    <article className={styles.card} data-tone={tone} data-dense={dense}>
      {tag ? <span className={styles.tag}>{tag}</span> : null}
      <div className={styles.body}>{children}</div>
      {serial ? <span className={styles.serial}>{serial}</span> : null}
    </article>
  )
}

export function SpecimenCardSection({
  children,
  label,
}: PropsWithChildren<{ label?: ReactNode }>): React.ReactElement {
  return (
    <section className={styles.section}>
      {label ? <header className={styles.sectionHead}>{label}</header> : null}
      <div className={styles.sectionBody}>{children}</div>
    </section>
  )
}
