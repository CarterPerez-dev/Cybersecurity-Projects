// ===================
// © AngelaMos | 2026
// config.ts
//
// Centralized application constants including API
// endpoint paths, TanStack Query cache keys, route
// definitions, localStorage keys, query timing
// strategies (stale/gc/retry), HTTP status codes,
// upload timeout (120s), and color maps for
// RiskLevel (5 levels) and EntropyClassification
// (5 bands)
//
// Connects to:
//   api/hooks     - API_ENDPOINTS, QUERY_KEYS
//   core/app      - ROUTES
//   core/api      - QUERY_CONFIG
//   pages/        - RISK_LEVEL_COLORS,
//                   ENTROPY_CLASSIFICATION_COLORS
// ===================

export const API_ENDPOINTS = {
  UPLOAD: '/upload',
  ANALYSIS: (slug: string) => `/analysis/${slug}`,
  HEALTH: '/health',
} as const

export const QUERY_KEYS = {
  ANALYSIS: {
    BY_SLUG: (slug: string) => ['analysis', slug] as const,
  },
} as const

export const ROUTES = {
  HOME: '/',
  ANALYSIS: '/analysis/:slug',
} as const

export const STORAGE_KEYS = {
  UI: 'ui-storage',
} as const

export const QUERY_CONFIG = {
  STALE_TIME: {
    USER: 1000 * 60 * 5,
    STATIC: Infinity,
    FREQUENT: 1000 * 30,
  },
  GC_TIME: {
    DEFAULT: 1000 * 60 * 30,
    LONG: 1000 * 60 * 60,
  },
  RETRY: {
    DEFAULT: 3,
    NONE: 0,
  },
} as const

export const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER: 500,
} as const

export const UPLOAD_TIMEOUT_MS = 120_000

export const RISK_LEVEL_COLORS: Record<string, string> = {
  Benign: '#22c55e',
  Low: '#84cc16',
  Medium: '#eab308',
  High: '#f97316',
  Critical: '#ef4444',
} as const

export const ENTROPY_CLASSIFICATION_COLORS: Record<string, string> = {
  Plaintext: '#22c55e',
  NativeCode: '#3b82f6',
  Compressed: '#eab308',
  Packed: '#f97316',
  Encrypted: '#ef4444',
} as const

export type ApiEndpoint = typeof API_ENDPOINTS
export type QueryKey = typeof QUERY_KEYS
export type Route = typeof ROUTES
