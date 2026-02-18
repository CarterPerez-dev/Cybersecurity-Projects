// ===========================
// ScansList.tsx
// ©AngelaMos | 2025
// ===========================

import { GiMagnifyingGlass } from 'react-icons/gi'
import { Link } from 'react-router-dom'
import { useGetScans } from '@/hooks/useScan'
import { formatDate } from '@/lib/utils'
import './ScansList.css'

export const ScansList = (): React.ReactElement => {
  const { data: scans, isLoading, error } = useGetScans()

  if (isLoading) {
    return (
      <div className="scans-list__loading">
        <p>Loading scans...</p>
      </div>
    )
  }

  if (error !== null && error !== undefined) {
    return (
      <div className="scans-list__error">
        <p>Failed to load scans. Please try again.</p>
      </div>
    )
  }

  if (
    scans === null ||
    scans === undefined ||
    !Array.isArray(scans) ||
    scans.length === 0
  ) {
    return (
      <div className="scans-list__empty">
        <GiMagnifyingGlass className="scans-list__empty-icon" />
        <h3 className="scans-list__empty-title">No Scans Yet</h3>
        <p className="scans-list__empty-text">
          Get started by running your first security scan above
        </p>
      </div>
    )
  }

  return (
    <div className="scans-list">
      <div className="scans-list__table">
        <div className="scans-list__header">
          <div className="scans-list__header-cell">Target URL</div>
          <div className="scans-list__header-cell">Date</div>
          <div className="scans-list__header-cell">Tests</div>
          <div className="scans-list__header-cell">Vulnerabilities</div>
          <div className="scans-list__header-cell">Actions</div>
        </div>

        <div className="scans-list__body">
          {scans.map((scan) => {
            const vulnerableCount = scan.test_results.filter(
              (r) => r.status === 'vulnerable'
            ).length

            const scanDate = formatDate(scan.scan_date)

            return (
              <div key={scan.id} className="scans-list__row">
                <div className="scans-list__cell">
                  <span className="scans-list__url">{scan.target_url}</span>
                </div>
                <div className="scans-list__cell">{scanDate}</div>
                <div className="scans-list__cell">{scan.test_results.length}</div>
                <div className="scans-list__cell">
                  <span
                    className={`scans-list__vuln-badge ${
                      vulnerableCount > 0
                        ? 'scans-list__vuln-badge--danger'
                        : 'scans-list__vuln-badge--safe'
                    }`}
                  >
                    {vulnerableCount}
                  </span>
                </div>
                <div className="scans-list__cell">
                  <Link
                    to={`/scans/${scan.id.toString()}`}
                    className="scans-list__view-link"
                  >
                    View Results
                  </Link>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
