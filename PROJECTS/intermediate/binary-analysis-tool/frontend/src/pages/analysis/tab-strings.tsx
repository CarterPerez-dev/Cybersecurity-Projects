// ===================
// © AngelaMos | 2026
// tab-strings.tsx
//
// Strings tab with search, encoding/category filters,
// pagination, and expandable string values
//
// Provides a filter bar with text search, encoding
// dropdown (All/Ascii/Utf8/Utf16Le), category dropdown
// (All plus 14 StringCategory values), and a suspicious
// -only toggle. Filters apply via useMemo over the full
// string array, with results paginated at PAGE_SIZE (50)
// and displayed in a table showing hex offset, value
// (truncated at 80 chars with expand toggle tracked via
// expandedRows Set), encoding, category badge, and
// section name. StringRow highlights suspicious entries
// and supports click-to-expand for long values. Prev/
// Next pagination controls appear when totalPages
// exceeds one
//
// Connects to:
//   api/types         - AnalysisResponse, Extracted
//                        String, StringCategory,
//                        StringEncoding
//   core/lib          - formatHex
//   analysis/index    - mounted in renderTab switch
//   analysis.module
//     .scss           - filterBar, searchInput,
//                        pagination, dataTable styles
// ===================

import { useMemo, useState } from 'react'
import type {
  AnalysisResponse,
  ExtractedString,
  StringCategory,
  StringEncoding,
} from '@/api'
import { formatHex } from '@/core/lib'
import styles from './analysis.module.scss'

const ENCODING_OPTIONS: readonly ('All' | StringEncoding)[] = [
  'All',
  'Ascii',
  'Utf8',
  'Utf16Le',
] as const

const CATEGORY_OPTIONS: readonly ('All' | StringCategory)[] = [
  'All',
  'Url',
  'IpAddress',
  'FilePath',
  'RegistryKey',
  'ShellCommand',
  'CryptoWallet',
  'Email',
  'SuspiciousApi',
  'PackerSignature',
  'DebugArtifact',
  'AntiAnalysis',
  'PersistencePath',
  'EncodedData',
  'Generic',
] as const

const PAGE_SIZE = 50

function StringRow({
  str,
  expanded,
  onToggle,
}: {
  str: ExtractedString
  expanded: boolean
  onToggle: () => void
}): React.ReactElement {
  const MAX_DISPLAY = 80
  const needsTruncate = str.value.length > MAX_DISPLAY
  const display =
    expanded || !needsTruncate
      ? str.value
      : `${str.value.slice(0, MAX_DISPLAY)}\u2026`

  return (
    <tr
      className={`${styles.tableRow} ${str.is_suspicious ? styles.suspicious : ''}`}
    >
      <td className={styles.cellMono}>{formatHex(str.offset)}</td>
      <td>
        <button
          type="button"
          className={styles.stringValue}
          onClick={needsTruncate ? onToggle : undefined}
        >
          {display}
        </button>
      </td>
      <td className={styles.cellMono}>{str.encoding}</td>
      <td>
        <span className={styles.categoryBadge}>{str.category}</span>
      </td>
      <td className={styles.cellMono}>{str.section ?? '\u2014'}</td>
    </tr>
  )
}

export function TabStrings({
  data,
}: {
  data: AnalysisResponse
}): React.ReactElement {
  const str = data.passes.strings
  const [search, setSearch] = useState('')
  const [encoding, setEncoding] = useState<'All' | StringEncoding>('All')
  const [category, setCategory] = useState<'All' | StringCategory>('All')
  const [suspiciousOnly, setSuspiciousOnly] = useState(false)
  const [page, setPage] = useState(0)
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set())

  const filtered = useMemo(() => {
    if (!str) return []
    return str.strings.filter((s) => {
      if (search && !s.value.toLowerCase().includes(search.toLowerCase()))
        return false
      if (encoding !== 'All' && s.encoding !== encoding) return false
      if (category !== 'All' && s.category !== category) return false
      if (suspiciousOnly && !s.is_suspicious) return false
      return true
    })
  }, [str, search, encoding, category, suspiciousOnly])

  if (!str) {
    return (
      <div className={styles.tabPanel}>
        <span className={styles.noData}>No string data available</span>
      </div>
    )
  }

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE)
  const pageStrings = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  const toggleRow = (offset: number) => {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(offset)) next.delete(offset)
      else next.add(offset)
      return next
    })
  }

  return (
    <div className={styles.tabPanel}>
      <div className={styles.filterBar}>
        <input
          type="text"
          className={styles.searchInput}
          placeholder="SEARCH STRINGS..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value)
            setPage(0)
          }}
        />
        <select
          className={styles.filterSelect}
          value={encoding}
          onChange={(e) => {
            setEncoding(e.target.value as 'All' | StringEncoding)
            setPage(0)
          }}
        >
          {ENCODING_OPTIONS.map((opt) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </select>
        <select
          className={styles.filterSelect}
          value={category}
          onChange={(e) => {
            setCategory(e.target.value as 'All' | StringCategory)
            setPage(0)
          }}
        >
          {CATEGORY_OPTIONS.map((opt) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </select>
        <button
          type="button"
          className={`${styles.filterToggle} ${suspiciousOnly ? styles.filterActive : ''}`}
          onClick={() => {
            setSuspiciousOnly((p) => !p)
            setPage(0)
          }}
        >
          SUSPICIOUS
        </button>
      </div>

      <span className={styles.filterCount}>
        {filtered.length} / {str.statistics.total} strings
      </span>

      <div className={styles.tableWrap}>
        <table className={styles.dataTable}>
          <thead>
            <tr>
              <th>OFFSET</th>
              <th>VALUE</th>
              <th>ENCODING</th>
              <th>CATEGORY</th>
              <th>SECTION</th>
            </tr>
          </thead>
          <tbody>
            {pageStrings.map((s) => (
              <StringRow
                key={s.offset}
                str={s}
                expanded={expandedRows.has(s.offset)}
                onToggle={() => toggleRow(s.offset)}
              />
            ))}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className={styles.pagination}>
          <button
            type="button"
            className={styles.pageBtn}
            disabled={page === 0}
            onClick={() => setPage((p) => p - 1)}
          >
            PREV
          </button>
          <span className={styles.pageInfo}>
            {page + 1} / {totalPages}
          </span>
          <button
            type="button"
            className={styles.pageBtn}
            disabled={page >= totalPages - 1}
            onClick={() => setPage((p) => p + 1)}
          >
            NEXT
          </button>
        </div>
      )}
    </div>
  )
}
