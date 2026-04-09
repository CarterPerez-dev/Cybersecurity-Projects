// ===================
// © AngelaMos | 2026
// index.ts
//
// Barrel export for the core API module
//
// Re-exports apiClient from api.config, ApiError and
// transformAxiosError from errors, and queryClient with
// QUERY_STRATEGIES from query.config
// ===================

export * from './api.config'
export * from './errors'
export * from './query.config'
