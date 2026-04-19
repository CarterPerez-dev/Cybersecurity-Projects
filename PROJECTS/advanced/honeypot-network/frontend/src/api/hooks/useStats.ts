// ===================
// ©AngelaMos | 2026
// useStats.ts
// ===================

import type { UseQueryResult } from '@tanstack/react-query'
import { useQuery } from '@tanstack/react-query'
import type { ApiResponse, CredentialStats, OverviewStats } from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export const statsQueries = {
  all: () => QUERY_KEYS.STATS.ALL,
  overview: (since: string) => QUERY_KEYS.STATS.OVERVIEW(since),
  countries: (since: string) => QUERY_KEYS.STATS.COUNTRIES(since),
  credentials: () => QUERY_KEYS.STATS.CREDENTIALS(),
} as const

export const useStatsOverview = (
  since = '24h'
): UseQueryResult<OverviewStats, Error> => {
  return useQuery({
    queryKey: statsQueries.overview(since),
    queryFn: async () => {
      const response = await apiClient.get<ApiResponse<OverviewStats>>(
        API_ENDPOINTS.STATS.OVERVIEW,
        { params: { since } }
      )
      return response.data.data
    },
    ...QUERY_STRATEGIES.live,
  })
}

export const useStatsCountries = (
  since = '24h'
): UseQueryResult<Record<string, number>, Error> => {
  return useQuery({
    queryKey: statsQueries.countries(since),
    queryFn: async () => {
      const response = await apiClient.get<ApiResponse<Record<string, number>>>(
        API_ENDPOINTS.STATS.COUNTRIES,
        { params: { since } }
      )
      return response.data.data
    },
    ...QUERY_STRATEGIES.slow,
  })
}

export const useStatsCredentials = (): UseQueryResult<CredentialStats, Error> => {
  return useQuery({
    queryKey: statsQueries.credentials(),
    queryFn: async () => {
      const response = await apiClient.get<ApiResponse<CredentialStats>>(
        API_ENDPOINTS.STATS.CREDENTIALS
      )
      return response.data.data
    },
    ...QUERY_STRATEGIES.slow,
  })
}
