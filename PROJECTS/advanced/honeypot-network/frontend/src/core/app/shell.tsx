// ©AngelaMos | 2026
// shell.tsx

import { useEffect } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useWebSocketStore } from '@/core/lib/websocket.store'
import styles from './shell.module.scss'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/events', label: 'Events' },
  { to: '/sessions', label: 'Sessions' },
  { to: '/attackers', label: 'Attackers' },
  { to: '/mitre', label: 'MITRE' },
  { to: '/intel', label: 'Intel' },
] as const

export function Shell() {
  const { connect, disconnect, connected } = useWebSocketStore()

  useEffect(() => {
    connect()
    return () => disconnect()
  }, [connect, disconnect])

  return (
    <div className={styles.layout}>
      <header className={styles.header}>
        <div className={styles.brand}>
          <span className={styles.brandMark}>&#x2B22;</span>
          <span className={styles.brandName}>HIVE</span>
        </div>

        <div className={styles.divider} />

        <nav className={styles.nav}>
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={'end' in item}
              className={({ isActive }) =>
                `${styles.navLink} ${isActive ? styles.navActive : ''}`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className={styles.divider} />

        <div className={styles.status}>
          <span className={styles.statusLabel}>LINK</span>
          <span
            className={connected ? styles.statusOn : styles.statusOff}
          >
            {connected ? 'ACTIVE' : 'DOWN'}
          </span>
        </div>
      </header>

      <div className={styles.substrip}>
        <span>HONEYPOT NETWORK MONITOR</span>
        <span>SYS-01 / REV 1.0</span>
      </div>

      <main className={styles.main}>
        <Outlet />
      </main>
    </div>
  )
}
