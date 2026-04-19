// ©AngelaMos | 2026
// index.tsx

import {
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  useAttackers,
  useStatsCountries,
  useStatsCredentials,
  useStatsOverview,
} from '@/api/hooks'
import { AttackMap } from '@/components/attack-map'
import { EventFeed } from '@/components/event-feed'
import { StatCard } from '@/components/stat-card'
import { useWebSocketStore } from '@/core/lib/websocket.store'
import styles from './dashboard.module.scss'

const TOP_COUNTRIES_LIMIT = 10
const TOP_CREDS_LIMIT = 8

const TOOLTIP_STYLE = {
  background: 'oklch(22% 0.005 55)',
  border: '1px solid oklch(30% 0.005 55)',
  borderRadius: 0,
  fontSize: 12,
  fontFamily: 'var(--font-mono)',
} as const

export function DashboardPage() {
  const { data: stats } = useStatsOverview()
  const { data: countries } = useStatsCountries()
  const { data: credentials } = useStatsCredentials()
  const { data: attackers } = useAttackers()
  const wsEventCount = useWebSocketStore((s) => s.eventCount)

  const serviceData = stats
    ? Object.entries(stats.events_by_service).map(([name, count]) => ({
        name: name.toUpperCase(),
        count,
      }))
    : []

  const countryData = countries
    ? Object.entries(countries)
        .sort(([, a], [, b]) => b - a)
        .slice(0, TOP_COUNTRIES_LIMIT)
        .map(([code, count]) => ({ code, count }))
    : []

  return (
    <div className={styles.page}>
      <header className={styles.heading}>
        <h1 className={styles.title}>Dashboard</h1>
        <span className={styles.subtitle}>
          NETWORK OPERATIONS / LIVE OVERVIEW
        </span>
      </header>

      <div className={styles.metrics}>
        <StatCard label="Total Events" value={stats?.total_events ?? 0} />
        <StatCard
          label="Active Sessions"
          value={stats?.active_sessions ?? 0}
          accent="var(--active)"
        />
        <StatCard
          label="Live Events"
          value={wsEventCount}
          accent="var(--accent)"
        />
        <StatCard
          label="Threat Actors"
          value={attackers?.length ?? 0}
          accent="var(--critical)"
        />
      </div>

      <div className={styles.rowWide}>
        <section className={styles.panel}>
          <h2 className={styles.panelLabel}>Attack Origins</h2>
          <AttackMap attackers={attackers ?? []} />
        </section>

        <section className={styles.panel}>
          <h2 className={styles.panelLabel}>Live Feed</h2>
          <EventFeed />
        </section>
      </div>

      <div className={styles.row}>
        <section className={styles.panel}>
          <h2 className={styles.panelLabel}>Events by Service</h2>
          <div className={styles.chart}>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={serviceData}>
                <XAxis
                  dataKey="name"
                  stroke="oklch(32% 0.005 55)"
                  tick={{ fill: 'oklch(52% 0.005 55)', fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ strokeWidth: 2 }}
                />
                <YAxis
                  stroke="oklch(32% 0.005 55)"
                  tick={{ fill: 'oklch(52% 0.005 55)', fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip contentStyle={TOOLTIP_STYLE} cursor={false} />
                <Bar
                  dataKey="count"
                  fill="oklch(70% 0.19 55)"
                  radius={0}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className={styles.panel}>
          <h2 className={styles.panelLabel}>Top Countries</h2>
          <div className={styles.list}>
            {countryData.map((c) => (
              <div key={c.code} className={styles.listRow}>
                <span className={styles.listLabel}>{c.code}</span>
                <span className={styles.listValue}>
                  {c.count.toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </section>
      </div>

      {credentials && (
        <div className={styles.row}>
          <section className={styles.panel}>
            <h2 className={styles.panelLabel}>Top Usernames</h2>
            <div className={styles.list}>
              {credentials.top_usernames
                .slice(0, TOP_CREDS_LIMIT)
                .map((u) => (
                  <div key={u.value} className={styles.listRow}>
                    <span className={styles.listLabel}>{u.value}</span>
                    <span className={styles.listValue}>{u.count}</span>
                  </div>
                ))}
            </div>
          </section>

          <section className={styles.panel}>
            <h2 className={styles.panelLabel}>Top Passwords</h2>
            <div className={styles.list}>
              {credentials.top_passwords
                .slice(0, TOP_CREDS_LIMIT)
                .map((p) => (
                  <div key={p.value} className={styles.listRow}>
                    <span className={styles.listLabel}>{p.value}</span>
                    <span className={styles.listValue}>{p.count}</span>
                  </div>
                ))}
            </div>
          </section>
        </div>
      )}
    </div>
  )
}
