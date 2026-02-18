// ===========================
// ScanResultsPage.tsx
// ©AngelaMos | 2025
// ===========================

import { Link, useParams } from 'react-router-dom'
import { TestResultCard } from '@/components/scan/TestResultCard'
import { useGetScan } from '@/hooks/useScan'
import { formatDateTime } from '@/lib/utils'
import './ScanResultsPage.css'

export const ScanResultsPage = (): React.ReactElement => {
  const { id } = useParams<{ id: string }>()
  const scanId = id !== null && id !== undefined ? parseInt(id, 10) : 0

  const { data: scan, isLoading, error } = useGetScan(scanId)

  if (isLoading) {
    return (
      <div className="scan-results__loading">
        <p>Loading scan results...</p>
      </div>
    )
  }

  if (error !== null && error !== undefined) {
    return (
      <div className="scan-results__error">
        <p>Failed to load scan results. Please try again.</p>
        <Link to="/" className="scan-results__back-link">
          Back to Dashboard
        </Link>
      </div>
    )
  }

  if (scan === null || scan === undefined) {
    return (
      <div className="scan-results__error">
        <p>Scan not found.</p>
        <Link to="/" className="scan-results__back-link">
          Back to Dashboard
        </Link>
      </div>
    )
  }

  const scanDate = formatDateTime(scan.scan_date)

  const vulnerableCount = scan.test_results.filter(
    (r) => r.status === 'vulnerable'
  ).length

  return (
    <div className="scan-results">
      <div className="scan-results__container">
        <header className="scan-results__header">
          <Link to="/" className="scan-results__back-link">
            ← Back to Dashboard
          </Link>
          <h1 className="scan-results__title">Scan Results</h1>
          <div className="scan-results__metadata">
            <div className="scan-results__meta-item">
              <span className="scan-results__meta-label">Target:</span>
              <span className="scan-results__meta-value">{scan.target_url}</span>
            </div>
            <div className="scan-results__meta-item">
              <span className="scan-results__meta-label">Date:</span>
              <span className="scan-results__meta-value">{scanDate}</span>
            </div>
            <div className="scan-results__meta-item">
              <span className="scan-results__meta-label">Tests Run:</span>
              <span className="scan-results__meta-value">
                {scan.test_results.length}
              </span>
            </div>
            <div className="scan-results__meta-item">
              <span className="scan-results__meta-label">Vulnerabilities:</span>
              <span
                className={`scan-results__vuln-count ${
                  vulnerableCount > 0
                    ? 'scan-results__vuln-count--danger'
                    : 'scan-results__vuln-count--safe'
                }`}
              >
                {vulnerableCount}
              </span>
            </div>
          </div>
        </header>

        <div className="scan-results__tests">
          {scan.test_results.map((result) => (
            <TestResultCard key={result.id} result={result} />
          ))}
        </div>
      </div>
    </div>
  )
}
