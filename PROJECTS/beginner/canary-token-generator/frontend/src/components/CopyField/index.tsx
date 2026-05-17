// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import { useState } from 'react'
import { toast } from 'sonner'
import styles from './CopyField.module.scss'

type CopyFieldProps = {
  value: string
  label?: string
  fullWidth?: boolean
}

const COPY_FEEDBACK_MS = 1200

export function CopyField({
  value,
  label,
  fullWidth = false,
}: CopyFieldProps): React.ReactElement {
  const [copied, setCopied] = useState(false)

  async function handleCopy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), COPY_FEEDBACK_MS)
    } catch (_err) {
      toast.error('Copy failed — your browser blocked clipboard access')
    }
  }

  return (
    <div className={styles.field} data-full={fullWidth}>
      {label ? <span className={styles.label}>{label}</span> : null}
      <code className={styles.value}>{value}</code>
      <button
        type="button"
        className={styles.copy}
        onClick={handleCopy}
        aria-label={`Copy ${label ?? 'value'}`}
      >
        {copied ? 'copied' : 'copy'}
      </button>
    </div>
  )
}
