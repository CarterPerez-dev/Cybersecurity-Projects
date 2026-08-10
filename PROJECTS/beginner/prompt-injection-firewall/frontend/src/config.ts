// ===================
// © AngelaMos | 2026
// config.ts
// ===================

export const API_ENDPOINTS = {
  ARENA: {
    LEVELS: '/levels',
    SESSION: '/session',
    ATTEMPT: '/attempt',
  },
} as const

export const QUERY_KEYS = {
  LEVELS: ['levels'] as const,
  SESSION: ['session'] as const,
} as const

export const ROUTES = {
  HOME: '/',
} as const

export const STORAGE_KEYS = {
  UI: 'ui-storage',
  SESSION: 'not-sandboxed-session',
} as const

export const QUERY_CONFIG = {
  STALE_TIME: {
    USER: 1000 * 60 * 5,
    STATIC: Number.POSITIVE_INFINITY,
    FREQUENT: 1000 * 30,
  },
  GC_TIME: {
    DEFAULT: 1000 * 60 * 30,
    LONG: 1000 * 60 * 60,
  },
  RETRY: {
    DEFAULT: 1,
    NONE: 0,
  },
} as const

export const HTTP_STATUS = {
  OK: 200,
  BAD_REQUEST: 400,
  NOT_FOUND: 404,
  PAYLOAD_TOO_LARGE: 413,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER: 500,
} as const

export const ARENA = {
  FIRST_LEVEL: 1,
  LAST_LEVEL: 6,
  BOUNTY_LEVEL: 6,
  MAX_TICKET_CHARS: 4000,
} as const

export const LAYER_ORDER = [
  'normalize',
  'ingress',
  'provenance',
  'toolauth',
  'egress',
] as const

export const DECISION = {
  ALLOW: 'allow',
  SANITIZE: 'sanitize',
  BLOCK: 'block',
} as const

export const RULE_LAYER_DISABLED = 'layer-disabled'

export const COPY = {
  TITLE: 'not-sandboxed',
  TAGLINE: 'the model is not sandboxed, so the effects are',
  TICKET_LABEL: 'Submit a support ticket',
  TICKET_HINT: 'You control this text. It reaches the agent as untrusted DATA.',
  SUBMIT: 'Send ticket',
  SUBMITTING: 'Running…',
  AGENT_HEADING: 'What the agent produced',
  AGENT_EMPTY: 'The firewall blocked this before the agent replied.',
  VERDICT_HEADING: 'Verdict',
  NO_RULES: 'Nothing fired.',
  SECRET_ESCAPED: 'The secret escaped.',
  SECRET_CONTAINED: 'The secret stayed in.',
  DISABLED_NOTICE:
    'These layers are switched off at this level. Getting through ' +
    'here is not a bypass, it is a gift.',
  ACTIVE_LAYERS: 'Active layers',
  NO_ACTIVE_LAYERS: 'none — this level has no firewall at all',
  BOUNTY_NOTE: 'Every layer is on. A bypass here is a real finding.',
  ERRORS: {
    [HTTP_STATUS.PAYLOAD_TOO_LARGE]: 'That ticket is too long.',
    [HTTP_STATUS.TOO_MANY_REQUESTS]: 'Too many attempts. Wait a moment.',
    [HTTP_STATUS.NOT_FOUND]: 'Session expired. Reloading.',
    DEFAULT: 'Something broke on our side.',
  },
} as const

export type Route = typeof ROUTES
export type LayerName = (typeof LAYER_ORDER)[number]
