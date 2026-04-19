// ===================
// ©AngelaMos | 2026
// useAttackers.ts
// ===================

import type { UseQueryResult } from '@tanstack/react-query'
import { useQuery } from '@tanstack/react-query'
import type { ApiResponse, Attacker } from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export const attackerQueries = {
  all: () => QUERY_KEYS.ATTACKERS.ALL,
  list: (limit: number, since: string) => QUERY_KEYS.ATTACKERS.LIST(limit, since),
  byId: (id: string | number) => QUERY_KEYS.ATTACKERS.BY_ID(id),
} as const

export const useAttackers = (
  limit = 50,
  since = '24h'
): UseQueryResult<Attacker[], Error> => {
  return useQuery({
    queryKey: attackerQueries.list(limit, since),
    queryFn: async () => {
      const response = await apiClient.get<ApiResponse<Attacker[]>>(
        API_ENDPOINTS.ATTACKERS.LIST,
        { params: { limit, since } }
      )
      return response.data.data
    },
    ...QUERY_STRATEGIES.slow,
  })
}

export const useAttacker = (id: number): UseQueryResult<Attacker, Error> => {
  return useQuery({
    queryKey: attackerQueries.byId(id),
    queryFn: async () => {
      const response = await apiClient.get<ApiResponse<Attacker>>(
        API_ENDPOINTS.ATTACKERS.BY_ID(id)
      )
      return response.data.data
    },
    enabled: id > 0,
  })
}
