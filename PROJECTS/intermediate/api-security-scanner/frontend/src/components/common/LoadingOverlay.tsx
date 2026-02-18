// ===========================
// LoadingOverlay.tsx
// ©AngelaMos | 2025
// ===========================

import { type ScanTestType, TEST_TYPE_LABELS } from '@/config/constants'
import './LoadingOverlay.css'

interface LoadingOverlayProps {
  tests: ScanTestType[]
}

export const LoadingOverlay = ({
  tests,
}: LoadingOverlayProps): React.ReactElement => {
  return (
    <div className="loading-overlay" role="dialog" aria-label="Scan in progress">
      <div className="loading-overlay__content">
        <div className="loading-overlay__spinner">
          <div className="spinner" />
        </div>
        <h2 className="loading-overlay__title">Running Security Scan</h2>
        <p className="loading-overlay__subtitle">
          Testing {tests.length}{' '}
          {tests.length === 1 ? 'vulnerability' : 'vulnerabilities'}
        </p>
        <div className="loading-overlay__tests">
          {tests.map((test) => (
            <div key={test} className="loading-overlay__test">
              {TEST_TYPE_LABELS[test]}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
