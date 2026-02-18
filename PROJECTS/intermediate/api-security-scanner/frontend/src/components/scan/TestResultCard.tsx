// ===========================
// TestResultCard.tsx
// ©AngelaMos | 2025
// ===========================

import {
  SEVERITY_COLORS,
  STATUS_COLORS,
  TEST_TYPE_LABELS,
} from '@/config/constants'
import { useUIStore } from '@/store/uiStore'
import type { TestResult } from '@/types/scan.types'
import './TestResultCard.css'

interface TestResultCardProps {
  result: TestResult
}

export const TestResultCard = ({
  result,
}: TestResultCardProps): React.ReactElement => {
  const showEvidence = useUIStore(
    (state) => state.testResults.expandedTests[result.id] ?? false
  )
  const toggleTestExpanded = useUIStore((state) => state.toggleTestExpanded)

  const statusColor = STATUS_COLORS[result.status]
  const severityColor = SEVERITY_COLORS[result.severity]

  return (
    <div className="test-result-card">
      <div className="test-result-card__header">
        <div className="test-result-card__title-section">
          <h3 className="test-result-card__title">
            {TEST_TYPE_LABELS[result.test_name]}
          </h3>
          <div className="test-result-card__badges">
            <span
              className="test-result-card__badge test-result-card__badge--status"
              style={{ backgroundColor: statusColor }}
            >
              {result.status.toUpperCase()}
            </span>
            <span
              className="test-result-card__badge test-result-card__badge--severity"
              style={{ backgroundColor: severityColor }}
            >
              {result.severity.toUpperCase()}
            </span>
          </div>
        </div>
      </div>

      <div className="test-result-card__content">
        <div className="test-result-card__section">
          <h4 className="test-result-card__section-title">Details</h4>
          <p className="test-result-card__details">{result.details}</p>
        </div>

        {result.recommendations_json.length > 0 ? (
          <div className="test-result-card__section">
            <h4 className="test-result-card__section-title">Recommendations</h4>
            <ul className="test-result-card__recommendations">
              {result.recommendations_json.map((rec) => (
                <li
                  key={`${result.id.toString()}-rec-${rec}`}
                  className="test-result-card__recommendation"
                >
                  {rec}
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {Object.keys(result.evidence_json).length > 0 ? (
          <div className="test-result-card__section">
            <button
              type="button"
              onClick={() => toggleTestExpanded(result.id)}
              className="test-result-card__evidence-toggle"
              aria-expanded={showEvidence}
            >
              <span>{showEvidence ? '▼' : '▶'} Technical Evidence</span>
            </button>
            {showEvidence ? (
              <pre className="test-result-card__evidence">
                {JSON.stringify(result.evidence_json, null, 2)}
              </pre>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  )
}
