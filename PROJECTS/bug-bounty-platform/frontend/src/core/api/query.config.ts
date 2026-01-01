// ===================
// © AngelaMos | 2025
// query.config.ts
// ===================

import { MutationCache, QueryCache, QueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { QUERY_CONFIG } from '@/config'
import { ApiError, ApiErrorCode } from './errors'

const NO_RETRY_ERROR_CODES: readonly ApiErrorCode[] = [
  ApiErrorCode.AUTHENTICATION_ERROR,
  ApiErrorCode.AUTHORIZATION_ERROR,
  ApiErrorCode.NOT_FOUND,
  ApiErrorCode.VALIDATION_ERROR,
] as const

const shouldRetryQuery = (failureCount: number, error: Error): boolean => {
  if (error instanceof ApiError) {
    if (NO_RETRY_ERROR_CODES.includes(error.code)) {
      return false
    }
  }
  return failureCount < QUERY_CONFIG.RETRY.DEFAULT
}

const calculateRetryDelay = (attemptIndex: number): number => {
  const baseDelay = 1000
  const maxDelay = 30000
  return Math.min(baseDelay * 2 ** attemptIndex, maxDelay)
}

const handleQueryCacheError = (
  error: Error,
  query: { state: { data: unknown } }
): void => {
  if (query.state.data !== undefined) {
    const message =
      error instanceof ApiError
        ? error.getUserMessage()
        : 'Background update failed'
    toast.error(message)
  }
}

const handleMutationCacheError = (
  error: Error,
  _variables: unknown,
  _context: unknown,
  mutation: { options: { onError?: unknown } }
): void => {
  if (mutation.options.onError === undefined) {
    const message =
      error instanceof ApiError ? error.getUserMessage() : 'Operation failed'
    toast.error(message)
  }
}

export const QUERY_STRATEGIES = {
  standard: {
    staleTime: QUERY_CONFIG.STALE_TIME.USER,
    gcTime: QUERY_CONFIG.GC_TIME.DEFAULT,
  },
  frequent: {
    staleTime: QUERY_CONFIG.STALE_TIME.FREQUENT,
    gcTime: QUERY_CONFIG.GC_TIME.DEFAULT,
    refetchInterval: QUERY_CONFIG.STALE_TIME.FREQUENT,
  },
  static: {
    staleTime: QUERY_CONFIG.STALE_TIME.STATIC,
    gcTime: QUERY_CONFIG.GC_TIME.LONG,
    refetchOnMount: false,
    refetchOnWindowFocus: false,
  },
  auth: {
    staleTime: QUERY_CONFIG.STALE_TIME.USER,
    gcTime: QUERY_CONFIG.GC_TIME.DEFAULT,
    retry: QUERY_CONFIG.RETRY.NONE,
  },
} as const

export type QueryStrategy = keyof typeof QUERY_STRATEGIES

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: QUERY_CONFIG.STALE_TIME.USER,
      gcTime: QUERY_CONFIG.GC_TIME.DEFAULT,
      retry: shouldRetryQuery,
      retryDelay: calculateRetryDelay,
      refetchOnWindowFocus: true,
      refetchOnMount: true,
      refetchOnReconnect: true,
    },
    mutations: {
      retry: QUERY_CONFIG.RETRY.NONE,
    },
  },
  queryCache: new QueryCache({
    onError: handleQueryCacheError,
  }),
  mutationCache: new MutationCache({
    onError: handleMutationCacheError,
  }),
})
