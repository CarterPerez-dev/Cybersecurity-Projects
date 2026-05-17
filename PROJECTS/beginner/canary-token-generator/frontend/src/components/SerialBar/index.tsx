// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import { useMemo } from 'react'
import styles from './SerialBar.module.scss'

type SerialBarProps = {
  value: string
  prefix?: string
}

const BAR_CHARS = ['▮', '▯', '▮', '▮', '▯', '▮', '▯', '▯', '▮']

function fingerprintToBars(value: string): string {
  if (value.length === 0) {
    return BAR_CHARS.join('')
  }
  let acc = ''
  for (let i = 0; i < 22; i += 1) {
    const ch = value.charCodeAt(i % value.length)
    acc += (ch & 1) === 0 ? '▮' : '▯'
  }
  return acc
}

export function SerialBar({
  value,
  prefix = 'SN',
}: SerialBarProps): React.ReactElement {
  const bars = useMemo(() => fingerprintToBars(value), [value])
  return (
    <div className={styles.serial}>
      <span className={styles.prefix}>{prefix}</span>
      <span className={styles.bars} aria-hidden="true">
        {bars}
      </span>
      <span className={styles.code}>{value}</span>
    </div>
  )
}
