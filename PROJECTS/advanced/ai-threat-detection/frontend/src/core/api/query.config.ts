// ===================
// © AngelaMos | 2026
// query.config.ts
//
// TanStack React Query client configuration with retry
// logic and global error toasts
//
// Configures QueryClient with smart retry (skips NOT_FOUND
// and VALIDATION_ERROR, retries up to 3 times with
// exponential backoff capped at 30s), window focus refetch,
// and reconnect refetch. QueryCache shows toast errors only
// for background updates (stale data present). MutationCache
// shows toast errors only when no per-mutation onError is
// set. Exports QUERY_STRATEGIES (standard, frequent, static)
// with tuned stale/gc/refetch settings
// ===================

import { MutationCache, QueryCache, QueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { QUERY_CONFIG } from '@/config'
import { ApiError, ApiErrorCode } from './errors'

const NO_RETRY_ERROR_CODES: readonly ApiErrorCode[] = [
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
    staleTime: QUERY_CONFIG.STALE_TIME.STANDARD,
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
} as const

export type QueryStrategy = keyof typeof QUERY_STRATEGIES

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: QUERY_CONFIG.STALE_TIME.STANDARD,
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
