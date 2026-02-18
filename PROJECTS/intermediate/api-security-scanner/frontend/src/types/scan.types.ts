// ===========================
// scan.types.ts
// ©AngelaMos | 2025
// ===========================

import type { ScanStatus, ScanTestType, Severity } from '@/config/constants'

export type { ScanTestType, ScanStatus, Severity }

export interface TestResult {
  id: number
  scan_id: number
  test_name: ScanTestType
  status: ScanStatus
  severity: Severity
  details: string
  evidence_json: Record<string, unknown>
  recommendations_json: string[]
  created_at: string
}

export interface Scan {
  id: number
  user_id: number
  target_url: string
  scan_date: string
  created_at: string
  test_results: TestResult[]
}

export interface CreateScanRequest {
  target_url: string
  auth_token: string | null
  tests_to_run: ScanTestType[]
  max_requests: number
}

export type CreateScanResponse = Scan

export type GetScansResponse = Scan[]

export type GetScanResponse = Scan
