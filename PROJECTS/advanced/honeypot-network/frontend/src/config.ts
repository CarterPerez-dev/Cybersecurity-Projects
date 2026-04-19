// ===================
// ©AngelaMos | 2026
// config.ts
// ===================

export const API_ENDPOINTS = {
  HEALTH: '/health',
  STATS: {
    OVERVIEW: '/stats/overview',
    COUNTRIES: '/stats/countries',
    CREDENTIALS: '/stats/credentials',
  },
  EVENTS: {
    LIST: '/events',
  },
  SESSIONS: {
    LIST: '/sessions',
    BY_ID: (id: string) => `/sessions/${id}`,
    REPLAY: (id: string) => `/sessions/${id}/replay`,
  },
  ATTACKERS: {
    LIST: '/attackers',
    BY_ID: (id: string | number) => `/attackers/${id}`,
  },
  MITRE: {
    TECHNIQUES: '/mitre/techniques',
    HEATMAP: '/mitre/heatmap',
  },
  IOCS: {
    LIST: '/iocs',
    EXPORT_STIX: '/iocs/export/stix',
    EXPORT_BLOCKLIST: '/iocs/export/blocklist',
  },
  SENSORS: {
    LIST: '/sensors',
  },
} as const

export const QUERY_KEYS = {
  STATS: {
    ALL: ['stats'] as const,
    OVERVIEW: (since: string) =>
      [...QUERY_KEYS.STATS.ALL, 'overview', since] as const,
    COUNTRIES: (since: string) =>
      [...QUERY_KEYS.STATS.ALL, 'countries', since] as const,
    CREDENTIALS: () => [...QUERY_KEYS.STATS.ALL, 'credentials'] as const,
  },
  EVENTS: {
    ALL: ['events'] as const,
    LIST: (limit: number, ip?: string) =>
      [...QUERY_KEYS.EVENTS.ALL, 'list', { limit, ip }] as const,
  },
  SESSIONS: {
    ALL: ['sessions'] as const,
    LIST: (limit: number, offset: number, service?: string) =>
      [...QUERY_KEYS.SESSIONS.ALL, 'list', { limit, offset, service }] as const,
    BY_ID: (id: string) => [...QUERY_KEYS.SESSIONS.ALL, 'detail', id] as const,
    REPLAY: (id: string) => [...QUERY_KEYS.SESSIONS.ALL, 'replay', id] as const,
  },
  ATTACKERS: {
    ALL: ['attackers'] as const,
    LIST: (limit: number, since: string) =>
      [...QUERY_KEYS.ATTACKERS.ALL, 'list', { limit, since }] as const,
    BY_ID: (id: string | number) =>
      [...QUERY_KEYS.ATTACKERS.ALL, 'detail', id] as const,
  },
  MITRE: {
    ALL: ['mitre'] as const,
    TECHNIQUES: () => [...QUERY_KEYS.MITRE.ALL, 'techniques'] as const,
    HEATMAP: (since: string) =>
      [...QUERY_KEYS.MITRE.ALL, 'heatmap', since] as const,
  },
  IOCS: {
    ALL: ['iocs'] as const,
    LIST: (limit: number, offset: number) =>
      [...QUERY_KEYS.IOCS.ALL, 'list', { limit, offset }] as const,
  },
  SENSORS: {
    ALL: ['sensors'] as const,
    LIST: () => [...QUERY_KEYS.SENSORS.ALL, 'list'] as const,
  },
} as const

export const ROUTES = {
  DASHBOARD: '/',
  EVENTS: '/events',
  SESSIONS: '/sessions',
  SESSION_DETAIL: '/sessions/:id',
  ATTACKERS: '/attackers',
  ATTACKER_DETAIL: '/attackers/:id',
  MITRE: '/mitre',
  INTEL: '/intel',
} as const

export const QUERY_CONFIG = {
  STALE_TIME: {
    DEFAULT: 0,
    STATIC: Infinity,
    LIVE: 1000 * 10,
    SLOW: 1000 * 60,
    DASHBOARD: 1000 * 15,
  },
  GC_TIME: {
    DEFAULT: 1000 * 60 * 30,
    LONG: 1000 * 60 * 60,
  },
  RETRY: {
    DEFAULT: 3,
    NONE: 0,
  },
  REFETCH: {
    LIVE: 1000 * 10,
    SLOW: 1000 * 60,
  },
} as const

export const PAGINATION = {
  DEFAULT_LIMIT: 50,
  MAX_LIMIT: 500,
} as const

export const SERVICE_LABELS: Record<string, string> = {
  ssh: 'SSH',
  http: 'HTTP',
  ftp: 'FTP',
  smb: 'SMB',
  mysql: 'MySQL',
  redis: 'Redis',
}

export const BLOCKLIST_FORMATS = ['plain', 'iptables', 'nginx', 'csv'] as const

export type ApiEndpoint = typeof API_ENDPOINTS
export type QueryKey = typeof QUERY_KEYS
export type Route = typeof ROUTES
