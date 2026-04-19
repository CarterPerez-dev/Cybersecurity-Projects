// ===================
// ©AngelaMos | 2026
// useMitre.ts
// ===================

import type { UseQueryResult } from '@tanstack/react-query'
import { useQuery } from '@tanstack/react-query'
import type { ApiResponse, HeatmapEntry, TechniqueInfo } from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export const mitreQueries = {
  all: () => QUERY_KEYS.MITRE.ALL,
  techniques: () => QUERY_KEYS.MITRE.TECHNIQUES(),
  heatmap: (since: string) => QUERY_KEYS.MITRE.HEATMAP(since),
} as const

export const useMitreTechniques = (): UseQueryResult<TechniqueInfo[], Error> => {
  return useQuery({
    queryKey: mitreQueries.techniques(),
    queryFn: async () => {
      const response = await apiClient.get<ApiResponse<TechniqueInfo[]>>(
        API_ENDPOINTS.MITRE.TECHNIQUES
      )
      return response.data.data
    },
    ...QUERY_STRATEGIES.static,
  })
}

export const useMitreHeatmap = (
  since = '24h'
): UseQueryResult<HeatmapEntry[], Error> => {
  return useQuery({
    queryKey: mitreQueries.heatmap(since),
    queryFn: async () => {
      const response = await apiClient.get<ApiResponse<HeatmapEntry[]>>(
        API_ENDPOINTS.MITRE.HEATMAP,
        { params: { since } }
      )
      return response.data.data
    },
    ...QUERY_STRATEGIES.slow,
  })
}
