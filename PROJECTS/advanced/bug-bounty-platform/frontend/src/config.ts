// ===================
// © AngelaMos | 2026
// config.ts
// ===================
const API_VERSION = 'v1'

export const API_ENDPOINTS = {
  AUTH: {
    LOGIN: `/${API_VERSION}/auth/login`,
    REFRESH: `/${API_VERSION}/auth/refresh`,
    LOGOUT: `/${API_VERSION}/auth/logout`,
    LOGOUT_ALL: `/${API_VERSION}/auth/logout-all`,
    ME: `/${API_VERSION}/auth/me`,
    CHANGE_PASSWORD: `/${API_VERSION}/auth/change-password`,
  },
  USERS: {
    BASE: `/${API_VERSION}/users`,
    BY_ID: (id: string) => `/${API_VERSION}/users/${id}`,
    ME: `/${API_VERSION}/users/me`,
    REGISTER: `/${API_VERSION}/users`,
  },
  PROGRAMS: {
    LIST: `/${API_VERSION}/programs`,
    MINE: `/${API_VERSION}/programs/mine`,
    CREATE: `/${API_VERSION}/programs`,
    BY_SLUG: (slug: string) => `/${API_VERSION}/programs/${slug}`,
    BY_ID: (id: string) => `/${API_VERSION}/programs/${id}`,
    ASSETS: (id: string) => `/${API_VERSION}/programs/${id}/assets`,
    ASSET: (programId: string, assetId: string) =>
      `/${API_VERSION}/programs/${programId}/assets/${assetId}`,
    REWARDS: (id: string) => `/${API_VERSION}/programs/${id}/rewards`,
  },
  REPORTS: {
    LIST: `/${API_VERSION}/reports`,
    INBOX: `/${API_VERSION}/reports/inbox`,
    STATS: `/${API_VERSION}/reports/stats`,
    SUBMIT: `/${API_VERSION}/reports`,
    BY_PROGRAM: (programId: string) =>
      `/${API_VERSION}/reports/program/${programId}`,
    BY_ID: (id: string) => `/${API_VERSION}/reports/${id}`,
    TRIAGE: (id: string) => `/${API_VERSION}/reports/${id}/triage`,
    COMMENTS: (id: string) => `/${API_VERSION}/reports/${id}/comments`,
  },
  ADMIN: {
    STATS: `/${API_VERSION}/admin/stats`,
    USERS: {
      LIST: `/${API_VERSION}/admin/users`,
      CREATE: `/${API_VERSION}/admin/users`,
      BY_ID: (id: string) => `/${API_VERSION}/admin/users/${id}`,
      UPDATE: (id: string) => `/${API_VERSION}/admin/users/${id}`,
      DELETE: (id: string) => `/${API_VERSION}/admin/users/${id}`,
    },
    PROGRAMS: {
      LIST: `/${API_VERSION}/admin/programs`,
      BY_ID: (id: string) => `/${API_VERSION}/admin/programs/${id}`,
      UPDATE: (id: string) => `/${API_VERSION}/admin/programs/${id}`,
      DELETE: (id: string) => `/${API_VERSION}/admin/programs/${id}`,
    },
    REPORTS: {
      LIST: `/${API_VERSION}/admin/reports`,
      BY_ID: (id: string) => `/${API_VERSION}/admin/reports/${id}`,
      UPDATE: (id: string) => `/${API_VERSION}/admin/reports/${id}`,
    },
  },
} as const

export const QUERY_KEYS = {
  AUTH: {
    ALL: ['auth'] as const,
    ME: () => [...QUERY_KEYS.AUTH.ALL, 'me'] as const,
  },
  USERS: {
    ALL: ['users'] as const,
    BY_ID: (id: string) => [...QUERY_KEYS.USERS.ALL, 'detail', id] as const,
    ME: () => [...QUERY_KEYS.USERS.ALL, 'me'] as const,
  },
  PROGRAMS: {
    ALL: ['programs'] as const,
    LIST: (page: number, size: number) =>
      [...QUERY_KEYS.PROGRAMS.ALL, 'list', { page, size }] as const,
    MINE: (page: number, size: number) =>
      [...QUERY_KEYS.PROGRAMS.ALL, 'mine', { page, size }] as const,
    BY_SLUG: (slug: string) =>
      [...QUERY_KEYS.PROGRAMS.ALL, 'detail', slug] as const,
  },
  REPORTS: {
    ALL: ['reports'] as const,
    LIST: (page: number, size: number) =>
      [...QUERY_KEYS.REPORTS.ALL, 'list', { page, size }] as const,
    INBOX: (page: number, size: number) =>
      [...QUERY_KEYS.REPORTS.ALL, 'inbox', { page, size }] as const,
    STATS: () => [...QUERY_KEYS.REPORTS.ALL, 'stats'] as const,
    BY_ID: (id: string) => [...QUERY_KEYS.REPORTS.ALL, 'detail', id] as const,
    BY_PROGRAM: (programId: string, page: number, size: number) =>
      [...QUERY_KEYS.REPORTS.ALL, 'program', programId, { page, size }] as const,
  },
  ADMIN: {
    ALL: ['admin'] as const,
    STATS: () => [...QUERY_KEYS.ADMIN.ALL, 'stats'] as const,
    USERS: {
      ALL: () => [...QUERY_KEYS.ADMIN.ALL, 'users'] as const,
      LIST: (page: number, size: number, role?: string) =>
        [...QUERY_KEYS.ADMIN.USERS.ALL(), 'list', { page, size, role }] as const,
      BY_ID: (id: string) =>
        [...QUERY_KEYS.ADMIN.USERS.ALL(), 'detail', id] as const,
    },
    PROGRAMS: {
      ALL: () => [...QUERY_KEYS.ADMIN.ALL, 'programs'] as const,
      LIST: (page: number, size: number, status?: string) =>
        [
          ...QUERY_KEYS.ADMIN.PROGRAMS.ALL(),
          'list',
          { page, size, status },
        ] as const,
    },
    REPORTS: {
      ALL: () => [...QUERY_KEYS.ADMIN.ALL, 'reports'] as const,
      LIST: (page: number, size: number, status?: string, severity?: string) =>
        [
          ...QUERY_KEYS.ADMIN.REPORTS.ALL(),
          'list',
          { page, size, status, severity },
        ] as const,
    },
  },
} as const

export const ROUTES = {
  HOME: '/',
  LOGIN: '/login',
  REGISTER: '/register',
  DASHBOARD: '/dashboard',
  SETTINGS: '/settings',
  UNAUTHORIZED: '/unauthorized',
  PROGRAMS: {
    LIST: '/programs',
    DETAIL: (slug: string) => `/programs/${slug}`,
    SUBMIT: (slug: string) => `/programs/${slug}/submit`,
  },
  REPORTS: {
    LIST: '/reports',
    DETAIL: (id: string) => `/reports/${id}`,
  },
  COMPANY: {
    DASHBOARD: '/company',
    PROGRAMS: '/company/programs',
    NEW_PROGRAM: '/company/programs/new',
    EDIT_PROGRAM: (slug: string) => `/company/programs/${slug}/edit`,
    INBOX: '/company/inbox',
    REPORT: (id: string) => `/company/reports/${id}`,
  },
  ADMIN: {
    DASHBOARD: '/admin',
    USERS: '/admin/users',
    USER_DETAIL: (id: string) => `/admin/users/${id}`,
    PROGRAMS: '/admin/programs',
    REPORTS: '/admin/reports',
  },
} as const

export const STORAGE_KEYS = {
  AUTH: 'auth-storage',
  UI: 'ui-storage',
} as const

export const QUERY_CONFIG = {
  STALE_TIME: {
    USER: 0,
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

export const PASSWORD_CONSTRAINTS = {
  MIN_LENGTH: 8,
  MAX_LENGTH: 128,
} as const

export const PAGINATION = {
  DEFAULT_PAGE: 1,
  DEFAULT_SIZE: 20,
  MAX_SIZE: 100,
} as const

export type ApiEndpoint = typeof API_ENDPOINTS
export type QueryKey = typeof QUERY_KEYS
export type Route = typeof ROUTES
