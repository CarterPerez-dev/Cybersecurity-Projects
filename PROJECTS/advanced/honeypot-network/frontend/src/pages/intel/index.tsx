// ©AngelaMos | 2026
// index.tsx

import { useState } from 'react'
import { useIOCs } from '@/api/hooks'
import { API_ENDPOINTS, BLOCKLIST_FORMATS, PAGINATION } from '@/config'
import { apiClient } from '@/core/api'
import styles from './intel.module.scss'

function downloadBlob(data: string, filename: string, mime: string) {
  const blob = new Blob([data], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function IntelPage() {
  const [offset, setOffset] = useState(0)
  const { data, isLoading } = useIOCs(PAGINATION.DEFAULT_LIMIT, offset)
  const iocs = data?.data ?? []
  const total = data?.total ?? 0

  async function exportSTIX() {
    const res = await apiClient.get(API_ENDPOINTS.IOCS.EXPORT_STIX, {
      responseType: 'text',
    })
    downloadBlob(
      res.data as string,
      'hive-iocs.stix.json',
      'application/json'
    )
  }

  async function exportBlocklist(format: string) {
    const res = await apiClient.get(
      API_ENDPOINTS.IOCS.EXPORT_BLOCKLIST,
      { params: { format }, responseType: 'text' }
    )
    const ext = format === 'csv' ? '.csv' : '.txt'
    downloadBlob(
      res.data as string,
      `hive-blocklist${ext}`,
      'text/plain'
    )
  }

  return (
    <div className={styles.page}>
      <header className={styles.heading}>
        <div className={styles.headingLeft}>
          <h1 className={styles.title}>Intel</h1>
          <span className={styles.subtitle}>
            THREAT INTELLIGENCE PRODUCTS
          </span>
        </div>

        <div className={styles.exports}>
          <span className={styles.exportLabel}>EXPORT</span>
          <button
            type="button"
            className={styles.exportBtn}
            onClick={exportSTIX}
          >
            STIX 2.1
          </button>
          {BLOCKLIST_FORMATS.map((fmt) => (
            <button
              key={fmt}
              type="button"
              className={styles.exportBtn}
              onClick={() => exportBlocklist(fmt)}
            >
              {fmt.toUpperCase()}
            </button>
          ))}
        </div>
      </header>

      {isLoading ? (
        <div className={styles.loading}>LOADING ...</div>
      ) : (
        <>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Confidence</th>
                <th>Sightings</th>
                <th>Source</th>
                <th>First Seen</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc) => (
                <tr key={ioc.id}>
                  <td className={styles.iocType}>{ioc.type}</td>
                  <td>{ioc.value}</td>
                  <td>{ioc.confidence}%</td>
                  <td>{ioc.sight_count}</td>
                  <td>{ioc.source}</td>
                  <td>
                    {new Date(ioc.first_seen).toLocaleDateString()}
                  </td>
                  <td>
                    {new Date(ioc.last_seen).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className={styles.pagination}>
            <button
              type="button"
              className={styles.pageBtn}
              disabled={offset === 0}
              onClick={() =>
                setOffset(
                  Math.max(0, offset - PAGINATION.DEFAULT_LIMIT)
                )
              }
            >
              &#9664; PREV
            </button>
            <span className={styles.pageInfo}>
              {offset + 1}&ndash;
              {Math.min(offset + PAGINATION.DEFAULT_LIMIT, total)} OF{' '}
              {total}
            </span>
            <button
              type="button"
              className={styles.pageBtn}
              disabled={offset + PAGINATION.DEFAULT_LIMIT >= total}
              onClick={() =>
                setOffset(offset + PAGINATION.DEFAULT_LIMIT)
              }
            >
              NEXT &#9654;
            </button>
          </div>
        </>
      )}
    </div>
  )
}
