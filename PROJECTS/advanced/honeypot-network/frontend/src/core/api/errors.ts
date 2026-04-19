// ===================
// ©AngelaMos | 2026
// errors.ts
// ===================

import type { AxiosError } from 'axios'

export const ApiErrorCode = {
  NETWORK_ERROR: 'NETWORK_ERROR',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  NOT_FOUND: 'NOT_FOUND',
  RATE_LIMITED: 'RATE_LIMITED',
  SERVER_ERROR: 'SERVER_ERROR',
  UNKNOWN_ERROR: 'UNKNOWN_ERROR',
} as const

export type ApiErrorCode = (typeof ApiErrorCode)[keyof typeof ApiErrorCode]

export class ApiError extends Error {
  readonly code: ApiErrorCode
  readonly statusCode: number

  constructor(message: string, code: ApiErrorCode, statusCode: number) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.statusCode = statusCode
  }

  getUserMessage(): string {
    const messages: Record<ApiErrorCode, string> = {
      [ApiErrorCode.NETWORK_ERROR]:
        'Unable to connect. Please check your connection.',
      [ApiErrorCode.VALIDATION_ERROR]: 'Please check your input and try again.',
      [ApiErrorCode.NOT_FOUND]: 'The requested resource was not found.',
      [ApiErrorCode.RATE_LIMITED]:
        'Too many requests. Please wait and try again.',
      [ApiErrorCode.SERVER_ERROR]:
        'Something went wrong. Please try again later.',
      [ApiErrorCode.UNKNOWN_ERROR]:
        'An unexpected error occurred. Please try again.',
    }
    return messages[this.code]
  }
}

interface ApiErrorResponse {
  error?: string
  message?: string
}

export function transformAxiosError(error: AxiosError<unknown>): ApiError {
  if (!error.response) {
    return new ApiError('Network error', ApiErrorCode.NETWORK_ERROR, 0)
  }

  const { status } = error.response
  const data = error.response.data as ApiErrorResponse | undefined
  const message = data?.error ?? data?.message ?? 'An error occurred'

  const codeMap: Record<number, ApiErrorCode> = {
    400: ApiErrorCode.VALIDATION_ERROR,
    404: ApiErrorCode.NOT_FOUND,
    429: ApiErrorCode.RATE_LIMITED,
    500: ApiErrorCode.SERVER_ERROR,
    502: ApiErrorCode.SERVER_ERROR,
    503: ApiErrorCode.SERVER_ERROR,
    504: ApiErrorCode.SERVER_ERROR,
  }

  const code = codeMap[status] || ApiErrorCode.UNKNOWN_ERROR

  return new ApiError(message, code, status)
}

declare module '@tanstack/react-query' {
  interface Register {
    defaultError: ApiError
  }
}
