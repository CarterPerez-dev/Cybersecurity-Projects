// ===================
// © AngelaMos | 2026
// method-badge.tsx
//
// Color-coded HTTP method badge component
//
// Renders a span with a base badge class and an
// additional SCSS module class mapped from the method
// string (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
// via the METHOD_STYLES record. Unknown methods receive
// only the base style. Connects to pages/threats
// ===================

import styles from './method-badge.module.scss'

const METHOD_STYLES: Record<string, string> = {
  GET: styles.get,
  POST: styles.post,
  PUT: styles.put,
  DELETE: styles.delete,
  PATCH: styles.patch,
  HEAD: styles.head,
  OPTIONS: styles.options,
}

interface MethodBadgeProps {
  method: string
}

export function MethodBadge({ method }: MethodBadgeProps): React.ReactElement {
  return (
    <span className={`${styles.badge} ${METHOD_STYLES[method] ?? ''}`}>
      {method}
    </span>
  )
}
