// ===================
// © AngelaMos | 2026
// errors.ts
//
// Typed API error handling with status code mapping and
// user-facing messages
//
// Defines ApiErrorCode literal union (NETWORK_ERROR,
// VALIDATION_ERROR, NOT_FOUND, CONFLICT, RATE_LIMITED,
// SERVER_ERROR, UNKNOWN_ERROR), ApiError class with code,
// statusCode, details, and getUserMessage() for toast
// display, and transformAxiosError which maps HTTP status
// codes to ApiErrorCode and extracts detail/message from
// FastAPI error responses. Registers ApiError as the
// TanStack React Query default error type
// ===================

import type { AxiosError } from 'axios'

export const ApiErrorCode = {
  NETWORK_ERROR: 'NETWORK_ERROR',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  RATE_LIMITED: 'RATE_LIMITED',
  SERVER_ERROR: 'SERVER_ERROR',
  UNKNOWN_ERROR: 'UNKNOWN_ERROR',
} as const

export type ApiErrorCode = (typeof ApiErrorCode)[keyof typeof ApiErrorCode]

export class ApiError extends Error {
  readonly code: ApiErrorCode
  readonly statusCode: number
  readonly details?: Record<string, string[]>

  constructor(
    message: string,
    code: ApiErrorCode,
    statusCode: number,
    details?: Record<string, string[]>
  ) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.statusCode = statusCode
    this.details = details
  }

  getUserMessage(): string {
    const messages: Record<ApiErrorCode, string> = {
      [ApiErrorCode.NETWORK_ERROR]:
        'Unable to connect to the server. Check your connection.',
      [ApiErrorCode.VALIDATION_ERROR]: 'Invalid request parameters.',
      [ApiErrorCode.NOT_FOUND]: 'The requested resource was not found.',
      [ApiErrorCode.CONFLICT]:
        'This operation conflicts with an existing resource.',
      [ApiErrorCode.RATE_LIMITED]:
        'Too many requests. Please wait a moment and try again.',
      [ApiErrorCode.SERVER_ERROR]:
        'Something went wrong on the server. Please try again later.',
      [ApiErrorCode.UNKNOWN_ERROR]:
        'An unexpected error occurred. Please try again.',
    }
    return messages[this.code]
  }
}

interface ApiErrorResponse {
  detail?: string | { msg: string; type: string }[]
  message?: string
}

export function transformAxiosError(error: AxiosError<unknown>): ApiError {
  if (!error.response) {
    return new ApiError('Network error', ApiErrorCode.NETWORK_ERROR, 0)
  }

  const { status } = error.response
  const data = error.response.data as ApiErrorResponse | undefined
  let message = 'An error occurred'
  const details: Record<string, string[]> | undefined = undefined

  if (data?.detail) {
    if (typeof data.detail === 'string') {
      message = data.detail
    }
  } else if (data?.message) {
    message = data.message
  }

  const codeMap: Record<number, ApiErrorCode> = {
    400: ApiErrorCode.VALIDATION_ERROR,
    404: ApiErrorCode.NOT_FOUND,
    409: ApiErrorCode.CONFLICT,
    429: ApiErrorCode.RATE_LIMITED,
    500: ApiErrorCode.SERVER_ERROR,
    502: ApiErrorCode.SERVER_ERROR,
    503: ApiErrorCode.SERVER_ERROR,
    504: ApiErrorCode.SERVER_ERROR,
  }

  const code = codeMap[status] || ApiErrorCode.UNKNOWN_ERROR

  return new ApiError(message, code, status, details)
}

declare module '@tanstack/react-query' {
  interface Register {
    defaultError: ApiError
  }
}
