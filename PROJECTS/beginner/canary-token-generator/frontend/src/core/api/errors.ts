// ===================
// ©AngelaMos | 2026
// errors.ts
// ===================

import type { AxiosError } from 'axios'

export const ApiErrorCode = {
  NETWORK_ERROR: 'NETWORK_ERROR',
  PARSE_ERROR: 'PARSE_ERROR',
  UNKNOWN_ERROR: 'UNKNOWN_ERROR',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  BAD_JSON: 'BAD_JSON',
  BAD_CURSOR: 'BAD_CURSOR',
  BAD_PARAM: 'BAD_PARAM',
  UNKNOWN_TYPE: 'UNKNOWN_TYPE',
  GENERATE_FAILED: 'GENERATE_FAILED',
  TURNSTILE_FAILED: 'TURNSTILE_FAILED',
  NOT_FOUND: 'NOT_FOUND',
  RATE_LIMITED: 'RATE_LIMITED',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
} as const

export type ApiErrorCode = (typeof ApiErrorCode)[keyof typeof ApiErrorCode]

const STATUS_FALLBACK_CODE: Record<number, ApiErrorCode> = {
  400: ApiErrorCode.VALIDATION_ERROR,
  404: ApiErrorCode.NOT_FOUND,
  410: ApiErrorCode.NOT_FOUND,
  429: ApiErrorCode.RATE_LIMITED,
  500: ApiErrorCode.INTERNAL_ERROR,
  502: ApiErrorCode.SERVICE_UNAVAILABLE,
  503: ApiErrorCode.SERVICE_UNAVAILABLE,
  504: ApiErrorCode.SERVICE_UNAVAILABLE,
}

const USER_FACING_COPY: Partial<Record<string, string>> = {
  [ApiErrorCode.NETWORK_ERROR]:
    'Unable to reach the server. Check your connection.',
  [ApiErrorCode.PARSE_ERROR]: 'Server response did not match expected shape.',
  [ApiErrorCode.UNKNOWN_ERROR]: 'An unexpected error occurred.',
  [ApiErrorCode.RATE_LIMITED]: 'Too many requests. Wait a moment, then retry.',
  [ApiErrorCode.SERVICE_UNAVAILABLE]:
    'Service is temporarily unavailable. Try again shortly.',
}

export class ApiError extends Error {
  readonly code: string
  readonly statusCode: number
  readonly fields?: Readonly<Record<string, string>>

  constructor(
    message: string,
    code: string,
    statusCode: number,
    fields?: Record<string, string>
  ) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.statusCode = statusCode
    this.fields = fields
  }

  getUserMessage(): string {
    if (this.message.length > 0) {
      return this.message
    }
    return USER_FACING_COPY[this.code] ?? 'An unexpected error occurred.'
  }
}

interface EnvelopeErrorShape {
  success?: unknown
  error?: {
    code?: unknown
    message?: unknown
    fields?: unknown
  }
}

function parseEnvelopeError(
  data: unknown
): { code: string; message: string; fields?: Record<string, string> } | null {
  if (data === null || typeof data !== 'object') {
    return null
  }
  const envelope = data as EnvelopeErrorShape
  if (envelope.success !== false || envelope.error == null) {
    return null
  }
  const { code, message, fields } = envelope.error
  if (typeof code !== 'string' || typeof message !== 'string') {
    return null
  }
  return {
    code,
    message,
    fields: parseFields(fields),
  }
}

function parseFields(raw: unknown): Record<string, string> | undefined {
  if (raw === null || typeof raw !== 'object') {
    return undefined
  }
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof v === 'string') {
      out[k] = v
    }
  }
  return Object.keys(out).length > 0 ? out : undefined
}

export function transformAxiosError(error: AxiosError<unknown>): ApiError {
  if (!error.response) {
    return new ApiError('Network error', ApiErrorCode.NETWORK_ERROR, 0)
  }
  const { status, data } = error.response

  const envelope = parseEnvelopeError(data)
  if (envelope) {
    return new ApiError(envelope.message, envelope.code, status, envelope.fields)
  }

  const fallbackCode = STATUS_FALLBACK_CODE[status] ?? ApiErrorCode.UNKNOWN_ERROR
  return new ApiError('Request failed', fallbackCode, status)
}

declare module '@tanstack/react-query' {
  interface Register {
    defaultError: ApiError
  }
}
