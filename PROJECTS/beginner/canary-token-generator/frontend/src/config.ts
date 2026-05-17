// ===================
// ©AngelaMos | 2026
// config.ts
// ===================

export const ROUTES = {
  HOME: '/',
  MANAGE: '/m/:manageId',
} as const

export type Route = typeof ROUTES

export function manageRoute(manageId: string): string {
  return `/m/${encodeURIComponent(manageId)}`
}

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
