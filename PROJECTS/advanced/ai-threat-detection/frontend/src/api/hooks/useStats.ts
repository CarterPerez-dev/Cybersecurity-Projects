// ===================
// © AngelaMos | 2026
// useStats.ts
//
// TanStack Query hook for dashboard statistics
//
// useStats accepts an optional time range string (defaults
// to 24h) and queries API_ENDPOINTS.STATS with the range
// as a query parameter. The response is validated through
// StatsResponseSchema and the hook uses the frequent query
// strategy for short stale times and automatic refetch
// intervals. Connects to api/types/stats.types, core/api,
// config, pages/dashboard
// ===================

import { useQuery } from '@tanstack/react-query'
import type { StatsResponse } from '@/api/types'
import { StatsResponseSchema } from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export function useStats(range = '24h') {
  return useQuery<StatsResponse>({
    queryKey: QUERY_KEYS.STATS.BY_RANGE(range),
    queryFn: async () => {
      const { data } = await apiClient.get<unknown>(API_ENDPOINTS.STATS, {
        params: { range },
      })
      return StatsResponseSchema.parse(data)
    },
    ...QUERY_STRATEGIES.frequent,
  })
}
