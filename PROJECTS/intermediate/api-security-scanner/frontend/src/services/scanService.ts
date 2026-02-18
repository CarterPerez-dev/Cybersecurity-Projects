// ===========================
// scanService.ts
// ©AngelaMos | 2025
// ===========================

import { SCAN_ENDPOINTS } from '@/config/constants'
import { api } from '@/lib/api'
import type {
  CreateScanRequest,
  CreateScanResponse,
  GetScanResponse,
  GetScansResponse,
} from '@/types/scan.types'

export const scanQueryKeys = {
  all: ['scans'] as const,

  lists: () => [...scanQueryKeys.all, 'list'] as const,
  list: () => [...scanQueryKeys.lists()] as const,

  details: () => [...scanQueryKeys.all, 'detail'] as const,
  detail: (id: number) => [...scanQueryKeys.details(), id] as const,
} as const

export const scanQueries = {
  getScans: async (): Promise<GetScansResponse> => {
    return api.get<GetScansResponse>(SCAN_ENDPOINTS.LIST)
  },

  getScan: async (id: number): Promise<GetScanResponse> => {
    return api.get<GetScanResponse>(SCAN_ENDPOINTS.GET(id))
  },
}

export const scanMutations = {
  createScan: async (data: CreateScanRequest): Promise<CreateScanResponse> => {
    return api.post<CreateScanResponse>(SCAN_ENDPOINTS.CREATE, data)
  },

  deleteScan: async (id: number): Promise<void> => {
    await api.delete<undefined>(SCAN_ENDPOINTS.DELETE(id))
  },
}
