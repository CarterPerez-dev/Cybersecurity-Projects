// ©AngelaMos | 2026
// service-badge.tsx

import type { ServiceType } from '@/api/types'
import styles from './service-badge.module.scss'

interface ServiceBadgeProps {
  service: ServiceType
}

export function ServiceBadge({ service }: ServiceBadgeProps) {
  return (
    <span className={styles.badge}>
      {service.toUpperCase()}
    </span>
  )
}
