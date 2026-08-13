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

export const TOAST = {
  POSITION: 'top-right',
  DURATION: 2000,
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

export const SEVERITY_WEIGHT = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
} as const

export const SEVERITY_MAX_WEIGHT = 4

export const SEVERITY_SCALE_OFFSET = 1

export const NUMERAL_PAD = 2

export const SESSION_ID_HEAD = 8

export const CODEPOINT_CLASSES = {
  TAG: { LOW: 0xe0000, HIGH: 0xe007f },
  BIDI: [
    { LOW: 0x202a, HIGH: 0x202e },
    { LOW: 0x2066, HIGH: 0x2069 },
    { LOW: 0x200e, HIGH: 0x200f },
  ],
  ZERO_WIDTH: [
    { LOW: 0x200b, HIGH: 0x200d },
    { LOW: 0xfeff, HIGH: 0xfeff },
  ],
  ASCII_HIGH: 0x7f,
} as const

export const CENSUS_MARKS = {
  TAG: 'TAG',
  BIDI: 'BIDI',
  ZERO_WIDTH: 'ZW',
} as const

export type CensusMark = (typeof CENSUS_MARKS)[keyof typeof CENSUS_MARKS]

export const COPY = {
  TITLE: 'not-sandboxed',
  TAGLINE: 'the model is not sandboxed, so the effects are',
  UNIT_ID: 'unit id / ns-06',
  UNIT_ROLE: 'prompt injection firewall',
  NODE: 'support desk agent',
  NODE_STATE: 'untrusted input accepted',
  ORIGIN: 'local instance',
  ORIGIN_DETAIL: 'no model keys, no network',
  FOOTER_SPEC: 'five layers / four hard invariants / one scored best-effort',
  FOOTER_BUILD: 'ingress is incomplete by design',
  FOOTER_MARK: 'angelamos — 2026',
  SESSION_LABEL: 'session',
  SESSION_PENDING: 'opening',
  SECRET_LABEL_SHORT: 'secret held',
  SECRET_UNIT: 'chars',
  CONFIG_LABEL: 'configurations',
  LEVEL_HEADING: 'Select firewall configuration',
  LEVEL_LEGEND: 'level',
  TEACHES_LABEL: 'what this level teaches',
  TICKET_LABEL: 'Submit a support ticket',
  TICKET_HINT: 'You control this text. It reaches the agent as untrusted DATA.',
  SPECIMEN_HEADING: 'Specimen',
  SPECIMEN_EMPTY: 'Nothing submitted yet. The field reads what you type.',
  REVEAL_ON: 'Reveal invisibles',
  REVEAL_OFF: 'Hide invisibles',
  CENSUS: {
    GLYPHS: 'glyphs',
    BYTES: 'utf-8 bytes',
    NON_ASCII: 'non-ascii',
    TAG: 'tag block',
    BIDI: 'bidi controls',
    ZERO_WIDTH: 'zero width',
  },
  CENSUS_CLEAN: 'Nothing hidden in this text.',
  CENSUS_DIRTY:
    'This text carries characters your eye cannot see. The tokenizer ' +
    'still reads every one of them.',
  SUBMIT: 'Send ticket',
  SUBMITTING: 'Running…',
  AGENT_HEADING: 'What the agent produced',
  AGENT_EMPTY: 'The firewall blocked this before the agent replied.',
  VERDICT_HEADING: 'Verdict',
  REQUEST_LABEL: 'request',
  EGRESS_LABEL: 'egress',
  EGRESS_UNREACHED: 'not reached',
  ATTEMPTS_LABEL: 'attempt',
  FINDINGS_HEADING: 'Rules fired',
  INVARIANT_MARK: 'invariant',
  NO_RULES: 'Nothing fired.',
  SECRET_ESCAPED: 'The secret escaped.',
  SECRET_CONTAINED: 'The secret stayed in.',
  SECRET_LABEL: 'containment',
  AWAITING: 'awaiting ticket',
  DISABLED_NOTICE:
    'These layers are switched off at this level. Getting through ' +
    'here is not a bypass, it is a gift.',
  ACTIVE_LAYERS: 'Active layers',
  NO_ACTIVE_LAYERS: 'none — this level has no firewall at all',
  BOUNTY_NOTE: 'Every layer is on. A bypass here is a real finding.',
  ERRORS: {
    [HTTP_STATUS.PAYLOAD_TOO_LARGE]: 'That ticket is too long.',
    [HTTP_STATUS.TOO_MANY_REQUESTS]: 'Too many attempts. Wait a moment.',
    [HTTP_STATUS.NOT_FOUND]:
      'That session is gone. A fresh one is open — send the ticket again.',
    DEFAULT: 'Something broke on our side.',
  },
} as const

export type Route = typeof ROUTES
export type LayerName = (typeof LAYER_ORDER)[number]
