// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import styles from './Halftone.module.scss'

type HalftoneProps = {
  density?: 'sparse' | 'normal' | 'dense'
  height?: number
}

export function Halftone({
  density = 'normal',
  height = 24,
}: HalftoneProps): React.ReactElement {
  return (
    <div
      className={styles.halftone}
      data-density={density}
      style={{ blockSize: `${height}px` }}
      aria-hidden="true"
    />
  )
}
