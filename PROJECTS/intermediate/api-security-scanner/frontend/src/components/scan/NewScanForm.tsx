// ===========================
// NewScanForm.tsx
// ©AngelaMos | 2025
// ===========================

import { useEffect, useState } from 'react'
import { Button } from '@/components/common/Button'
import { Input } from '@/components/common/Input'
import { LoadingOverlay } from '@/components/common/LoadingOverlay'
import {
  SCAN_TEST_TYPES,
  type ScanTestType,
  TEST_TYPE_LABELS,
} from '@/config/constants'
import { useCreateScan } from '@/hooks/useScan'
import { scanSchema } from '@/lib/validation'
import { useUIStore } from '@/store/uiStore'
import './ScanForm.css'

export const NewScanForm = (): React.ReactElement => {
  const scanFormState = useUIStore((state) => state.scanForm)
  const setScanFormField = useUIStore((state) => state.setScanFormField)
  const clearScanForm = useUIStore((state) => state.clearScanForm)
  const clearExpiredData = useUIStore((state) => state.clearExpiredData)

  const [targetUrl, setTargetUrl] = useState<string>('')
  const [authToken, setAuthToken] = useState<string>('')
  const [selectedTests, setSelectedTests] = useState<ScanTestType[]>([])
  const [maxRequests, setMaxRequests] = useState<string>('50')
  const [errors, setErrors] = useState<{
    targetUrl?: string
    authToken?: string
    testsToRun?: string
    maxRequests?: string
  }>({})

  const { mutate: createScan, isPending } = useCreateScan()

  useEffect(() => {
    clearExpiredData()
    setTargetUrl(scanFormState.targetUrl)
    setAuthToken(scanFormState.authToken)
    setSelectedTests(
      scanFormState.selectedTests.length > 0
        ? scanFormState.selectedTests
        : [SCAN_TEST_TYPES.RATE_LIMIT]
    )
    setMaxRequests(scanFormState.maxRequests)
  }, [
    clearExpiredData,
    scanFormState.targetUrl,
    scanFormState.authToken,
    scanFormState.selectedTests,
    scanFormState.maxRequests,
  ])

  const validateForm = (): boolean => {
    const maxReq = parseInt(maxRequests, 10)

    const result = scanSchema.safeParse({
      targetUrl: targetUrl.trim(),
      authToken: authToken.trim().length > 0 ? authToken.trim() : undefined,
      testsToRun: selectedTests,
      maxRequests: maxReq,
    })

    if (!result.success) {
      const newErrors: {
        targetUrl?: string
        authToken?: string
        testsToRun?: string
        maxRequests?: string
      } = {}

      result.error.issues.forEach((err) => {
        const field = err.path[0] as keyof typeof newErrors
        if (field !== null && field !== undefined) {
          newErrors[field] = err.message
        }
      })

      setErrors(newErrors)
      return false
    }

    setErrors({})
    return true
  }

  const handleTargetUrlChange = (value: string): void => {
    setTargetUrl(value)
    setScanFormField('targetUrl', value)
  }

  const handleAuthTokenChange = (value: string): void => {
    setAuthToken(value)
    setScanFormField('authToken', value)
  }

  const handleMaxRequestsChange = (value: string): void => {
    setMaxRequests(value)
    setScanFormField('maxRequests', value)
  }

  const handleTestToggle = (test: ScanTestType): void => {
    const newTests = selectedTests.includes(test)
      ? selectedTests.filter((t) => t !== test)
      : [...selectedTests, test]

    setSelectedTests(newTests)
    setScanFormField('selectedTests', newTests)
  }

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault()

    if (!validateForm()) {
      return
    }

    const maxReq = parseInt(maxRequests, 10)

    createScan(
      {
        target_url: targetUrl.trim(),
        auth_token: authToken.trim().length > 0 ? authToken.trim() : null,
        tests_to_run: selectedTests,
        max_requests: maxReq,
      },
      {
        onSuccess: () => {
          clearScanForm()
        },
      }
    )
  }

  return (
    <>
      {isPending ? <LoadingOverlay tests={selectedTests} /> : null}
      <form className="scan-form" onSubmit={handleSubmit}>
        <div className="scan-form__fields">
          <Input
            label="Target URL"
            type="url"
            value={targetUrl}
            onChange={(e) => handleTargetUrlChange(e.target.value)}
            error={errors.targetUrl}
            placeholder="https://api.example.com/endpoint"
            required
          />

          <Input
            label="Auth Token (Optional)"
            type="text"
            value={authToken}
            onChange={(e) => handleAuthTokenChange(e.target.value)}
            error={errors.authToken}
            placeholder="Bearer token or API key"
          />

          <div className="scan-form__field">
            <span className="scan-form__label">
              Select Tests
              {errors.testsToRun !== null && errors.testsToRun !== undefined ? (
                <span className="scan-form__error" role="alert">
                  {errors.testsToRun}
                </span>
              ) : null}
            </span>
            <div className="scan-form__checkboxes">
              {Object.values(SCAN_TEST_TYPES).map((test) => (
                <label key={test} className="scan-form__checkbox-label">
                  <input
                    type="checkbox"
                    checked={selectedTests.includes(test)}
                    onChange={() => handleTestToggle(test)}
                    className="scan-form__checkbox"
                  />
                  <span>{TEST_TYPE_LABELS[test]}</span>
                </label>
              ))}
            </div>
          </div>

          <Input
            label="Max Requests"
            type="number"
            value={maxRequests}
            onChange={(e) => handleMaxRequestsChange(e.target.value)}
            error={errors.maxRequests}
            placeholder="50"
            min="1"
            max="50"
            required
          />
        </div>

        <Button type="submit" isLoading={isPending} disabled={isPending}>
          {isPending ? 'Running Scan...' : 'Start Scan'}
        </Button>
      </form>
    </>
  )
}
