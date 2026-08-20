// ===================
// © AngelaMos | 2026
// index.ts
// ===================

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  type AttemptRequest,
  type AttemptResponse,
  attemptResponseSchema,
  type CodepointsResponse,
  codepointsResponseSchema,
  type LevelsResponse,
  levelsResponseSchema,
  type SessionResponse,
  sessionResponseSchema,
} from '@/api/types'
import {
  API_ENDPOINTS,
  HTTP_STATUS,
  QUERY_CONFIG,
  QUERY_KEYS,
  STORAGE_KEYS,
} from '@/config'
import { apiClient } from '@/core/api'
import { ApiError } from '@/core/api/errors'

const readStoredSession = (): SessionResponse | null => {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEYS.SESSION)
    return raw === null ? null : sessionResponseSchema.parse(JSON.parse(raw))
  } catch {
    return null
  }
}

const writeStoredSession = (session: SessionResponse): void => {
  try {
    window.localStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(session))
  } catch {
    return
  }
}

const clearStoredSession = (): void => {
  try {
    window.localStorage.removeItem(STORAGE_KEYS.SESSION)
  } catch {
    return
  }
}

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

export const useCodepoints = () =>
  useQuery<CodepointsResponse>({
    queryKey: QUERY_KEYS.CODEPOINTS,
    staleTime: QUERY_CONFIG.STALE_TIME.STATIC,
    gcTime: QUERY_CONFIG.GC_TIME.LONG,
    retry: QUERY_CONFIG.RETRY.DEFAULT,
    queryFn: async () => {
      const { data } = await apiClient.get(API_ENDPOINTS.ARENA.CODEPOINTS)
      return codepointsResponseSchema.parse(data)
    },
  })

export const useSession = () =>
  useQuery<SessionResponse>({
    queryKey: QUERY_KEYS.SESSION,
    staleTime: QUERY_CONFIG.STALE_TIME.STATIC,
    gcTime: QUERY_CONFIG.GC_TIME.DEFAULT,
    retry: QUERY_CONFIG.RETRY.DEFAULT,
    queryFn: async () => {
      const stored = readStoredSession()
      if (stored !== null) {
        return stored
      }

      const { data } = await apiClient.post(API_ENDPOINTS.ARENA.SESSION)
      const parsed = sessionResponseSchema.parse(data)
      writeStoredSession(parsed)
      return parsed
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
        clearStoredSession()
        void client.refetchQueries({ queryKey: QUERY_KEYS.SESSION })
      }
    },
  })
}
