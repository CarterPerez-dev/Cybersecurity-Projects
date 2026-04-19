// ===================
// ©AngelaMos | 2026
// useIOCs.ts
// ===================

import type { UseQueryResult } from '@tanstack/react-query'
import { useQuery } from '@tanstack/react-query'
import type { IOC, PaginatedResponse } from '@/api/types'
import { API_ENDPOINTS, PAGINATION, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export const iocQueries = {
  all: () => QUERY_KEYS.IOCS.ALL,
  list: (limit: number, offset: number) => QUERY_KEYS.IOCS.LIST(limit, offset),
} as const

export const useIOCs = (
  limit = PAGINATION.DEFAULT_LIMIT,
  offset = 0
): UseQueryResult<PaginatedResponse<IOC[]>, Error> => {
  return useQuery({
    queryKey: iocQueries.list(limit, offset),
    queryFn: async () => {
      const response = await apiClient.get<PaginatedResponse<IOC[]>>(
        API_ENDPOINTS.IOCS.LIST,
        { params: { limit, offset } }
      )
      return response.data
    },
    ...QUERY_STRATEGIES.standard,
  })
}
