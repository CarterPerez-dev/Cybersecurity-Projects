// ===================
// ©AngelaMos | 2026
// useSensors.ts
// ===================

import type { UseQueryResult } from '@tanstack/react-query'
import { useQuery } from '@tanstack/react-query'
import type { ApiResponse, SensorInfo } from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export const sensorQueries = {
  all: () => QUERY_KEYS.SENSORS.ALL,
  list: () => QUERY_KEYS.SENSORS.LIST(),
} as const

export const useSensors = (): UseQueryResult<SensorInfo[], Error> => {
  return useQuery({
    queryKey: sensorQueries.list(),
    queryFn: async () => {
      const response = await apiClient.get<ApiResponse<SensorInfo[]>>(
        API_ENDPOINTS.SENSORS.LIST
      )
      return response.data.data
    },
    ...QUERY_STRATEGIES.static,
  })
}
