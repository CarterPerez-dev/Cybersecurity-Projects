// ===================
// © AngelaMos | 2026
// index.ts
// ===================

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  type AttemptRequest,
  type AttemptResponse,
  attemptResponseSchema,
  type LevelsResponse,
  levelsResponseSchema,
  type SessionResponse,
  sessionResponseSchema,
} from '@/api/types'
import { API_ENDPOINTS, HTTP_STATUS, QUERY_CONFIG, QUERY_KEYS } from '@/config'
import { apiClient } from '@/core/api'
import { ApiError } from '@/core/api/errors'

export const useLevels = () =>
  useQuery<LevelsResponse>({
    queryKey: QUERY_KEYS.LEVELS,
    staleTime: QUERY_CONFIG.STALE_TIME.STATIC,
    gcTime: QUERY_CONFIG.GC_TIME.DEFAULT,
    retry: QUERY_CONFIG.RETRY.DEFAULT,
    queryFn: async () => {
      const { data } = await apiClient.get(API_ENDPOINTS.ARENA.LEVELS)
      return levelsResponseSchema.parse(data)
    },
  })

export const useSession = () =>
  useQuery<SessionResponse>({
    queryKey: QUERY_KEYS.SESSION,
    staleTime: QUERY_CONFIG.STALE_TIME.STATIC,
    gcTime: QUERY_CONFIG.GC_TIME.DEFAULT,
    retry: QUERY_CONFIG.RETRY.DEFAULT,
    queryFn: async () => {
      const { data } = await apiClient.post(API_ENDPOINTS.ARENA.SESSION)
      return sessionResponseSchema.parse(data)
    },
  })

export const useAttempt = () => {
  const client = useQueryClient()

  return useMutation<AttemptResponse, Error, AttemptRequest>({
    retry: QUERY_CONFIG.RETRY.NONE,
    mutationFn: async (request) => {
      const { data } = await apiClient.post(API_ENDPOINTS.ARENA.ATTEMPT, request)
      return attemptResponseSchema.parse(data)
    },
    onError: (error) => {
      if (
        error instanceof ApiError &&
        error.statusCode === HTTP_STATUS.NOT_FOUND
      ) {
        void client.refetchQueries({ queryKey: QUERY_KEYS.SESSION })
      }
    },
  })
}
