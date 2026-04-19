// ===================
// ©AngelaMos | 2026
// useEvents.ts
// ===================

import type { UseQueryResult } from '@tanstack/react-query'
import { useQuery } from '@tanstack/react-query'
import type { ApiResponse, HoneypotEvent } from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export const eventQueries = {
  all: () => QUERY_KEYS.EVENTS.ALL,
  list: (limit: number, ip?: string) => QUERY_KEYS.EVENTS.LIST(limit, ip),
} as const

export const useEvents = (
  limit = 50,
  ip?: string
): UseQueryResult<HoneypotEvent[], Error> => {
  return useQuery({
    queryKey: eventQueries.list(limit, ip),
    queryFn: async () => {
      const response = await apiClient.get<ApiResponse<HoneypotEvent[]>>(
        API_ENDPOINTS.EVENTS.LIST,
        { params: { limit, ip } }
      )
      return response.data.data
    },
    ...QUERY_STRATEGIES.live,
  })
}
