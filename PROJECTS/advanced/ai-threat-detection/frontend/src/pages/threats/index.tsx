// ===================
// © AngelaMos | 2026
// index.tsx
//
// Threats table page with severity and IP filters,
// pagination, and detail modal
//
// Exports a lazy-loaded Component (displayName ThreatsPage)
// that manages offset, severity filter (ALL/HIGH/MEDIUM/
// LOW), and source IP text filter as local state. Passes
// these as ThreatParams to useThreats with PAGINATION
// defaults. Renders a responsive table with time, source
// IP, MethodBadge, path, score to 3 decimals,
// SeverityBadge, and status code columns. Rows are
// clickable to open ThreatDetail in a modal. Previous/Next
// pagination controls show the current range and total.
// Connects to api/hooks/useThreats, api/types/threats.types,
// components/method-badge, components/severity-badge,
// components/threat-detail, config
// ===================

import { useState } from 'react'
import { useThreats } from '@/api/hooks'
import type { ThreatEvent } from '@/api/types'
import { MethodBadge, SeverityBadge, ThreatDetail } from '@/components'
import { PAGINATION } from '@/config'
import styles from './threats.module.scss'

type SeverityFilter = 'ALL' | 'HIGH' | 'MEDIUM' | 'LOW'

function formatTime(dateStr: string): string {
  return new Date(dateStr).toLocaleString()
}

export function Component(): React.ReactElement {
  const [offset, setOffset] = useState(0)
  const [severity, setSeverity] = useState<SeverityFilter>('ALL')
  const [sourceIp, setSourceIp] = useState('')
  const [selectedThreat, setSelectedThreat] = useState<ThreatEvent | null>(null)

  const params = {
    limit: PAGINATION.DEFAULT_LIMIT,
    offset,
    ...(severity !== 'ALL' && { severity }),
    ...(sourceIp && { source_ip: sourceIp }),
  }

  const { data, isLoading } = useThreats(params)

  const total = data?.total ?? 0
  const items = data?.items ?? []
  const showing = Math.min(offset + PAGINATION.DEFAULT_LIMIT, total)
  const hasPrev = offset > 0
  const hasNext = offset + PAGINATION.DEFAULT_LIMIT < total

  return (
    <div className={styles.page}>
      <div className={styles.filters}>
        <select
          className={styles.select}
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value as SeverityFilter)
            setOffset(0)
          }}
        >
          <option value="ALL">All Severities</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <input
          className={styles.input}
          type="text"
          placeholder="Filter by source IP..."
          value={sourceIp}
          onChange={(e) => {
            setSourceIp(e.target.value)
            setOffset(0)
          }}
        />
      </div>

      <div className={styles.tableWrapper}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Time</th>
              <th>Source IP</th>
              <th>Method</th>
              <th>Path</th>
              <th>Score</th>
              <th>Severity</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={7} className={styles.loadingCell}>
                  Loading threats...
                </td>
              </tr>
            ) : items.length === 0 ? (
              <tr>
                <td colSpan={7} className={styles.emptyCell}>
                  No threats found matching your filters
                </td>
              </tr>
            ) : (
              items.map((threat) => (
                <tr
                  key={threat.id}
                  className={styles.row}
                  onClick={() => setSelectedThreat(threat)}
                >
                  <td className={styles.timeCell}>
                    {formatTime(threat.created_at)}
                  </td>
                  <td className={styles.monoCell}>{threat.source_ip}</td>
                  <td>
                    <MethodBadge method={threat.request_method} />
                  </td>
                  <td className={styles.pathCell}>{threat.request_path}</td>
                  <td className={styles.scoreCell}>
                    {threat.threat_score.toFixed(3)}
                  </td>
                  <td>
                    <SeverityBadge severity={threat.severity} />
                  </td>
                  <td>{threat.status_code}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className={styles.pagination}>
        <span className={styles.paginationInfo}>
          {total === 0 ? 'No results' : `${offset + 1}–${showing} of ${total}`}
        </span>
        <div className={styles.paginationButtons}>
          <button
            type="button"
            className={styles.pageBtn}
            disabled={!hasPrev}
            onClick={() => setOffset(offset - PAGINATION.DEFAULT_LIMIT)}
          >
            Previous
          </button>
          <button
            type="button"
            className={styles.pageBtn}
            disabled={!hasNext}
            onClick={() => setOffset(offset + PAGINATION.DEFAULT_LIMIT)}
          >
            Next
          </button>
        </div>
      </div>

      <ThreatDetail
        threat={selectedThreat}
        onClose={() => setSelectedThreat(null)}
      />
    </div>
  )
}

Component.displayName = 'ThreatsPage'
