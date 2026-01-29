// ===================
// © AngelaMos | 2025
// auth.types.ts
// ===================

import { z } from 'zod'
import { PASSWORD_CONSTRAINTS } from '@/config'

export const UserRole = {
  UNKNOWN: 'unknown',
  USER: 'user',
  ADMIN: 'admin',
} as const

export type UserRole = (typeof UserRole)[keyof typeof UserRole]

export const userResponseSchema = z.object({
  id: z.string().uuid(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime().nullable(),
  email: z.string().email(),
  full_name: z.string().nullable(),
  is_active: z.boolean(),
  is_verified: z.boolean(),
  role: z.nativeEnum(UserRole),
})

export const tokenResponseSchema = z.object({
  access_token: z.string(),
  token_type: z.string(),
})

export const tokenWithUserResponseSchema = tokenResponseSchema.extend({
  user: userResponseSchema,
})

export const loginRequestSchema = z.object({
  username: z.string().email(),
  password: z
    .string()
    .min(PASSWORD_CONSTRAINTS.MIN_LENGTH)
    .max(PASSWORD_CONSTRAINTS.MAX_LENGTH),
})

export const registerRequestSchema = z.object({
  email: z.string().email(),
  password: z
    .string()
    .min(PASSWORD_CONSTRAINTS.MIN_LENGTH)
    .max(PASSWORD_CONSTRAINTS.MAX_LENGTH),
  full_name: z.string().max(255).optional(),
})

export const passwordChangeRequestSchema = z.object({
  current_password: z.string(),
  new_password: z
    .string()
    .min(PASSWORD_CONSTRAINTS.MIN_LENGTH)
    .max(PASSWORD_CONSTRAINTS.MAX_LENGTH),
})

export const logoutAllResponseSchema = z.object({
  revoked_sessions: z.number(),
})

export type UserResponse = z.infer<typeof userResponseSchema>
export type TokenResponse = z.infer<typeof tokenResponseSchema>
export type TokenWithUserResponse = z.infer<typeof tokenWithUserResponseSchema>
export type LoginRequest = z.infer<typeof loginRequestSchema>
export type RegisterRequest = z.infer<typeof registerRequestSchema>
export type PasswordChangeRequest = z.infer<typeof passwordChangeRequestSchema>
export type LogoutAllResponse = z.infer<typeof logoutAllResponseSchema>

export const isValidUserResponse = (data: unknown): data is UserResponse => {
  if (data === null || data === undefined) return false
  if (typeof data !== 'object') return false

  const result = userResponseSchema.safeParse(data)
  return result.success
}

export const isValidTokenResponse = (data: unknown): data is TokenResponse => {
  if (data === null || data === undefined) return false
  if (typeof data !== 'object') return false

  const result = tokenResponseSchema.safeParse(data)
  return result.success
}

export const isValidTokenWithUserResponse = (
  data: unknown
): data is TokenWithUserResponse => {
  if (data === null || data === undefined) return false
  if (typeof data !== 'object') return false

  const result = tokenWithUserResponseSchema.safeParse(data)
  return result.success
}

export const isValidLogoutAllResponse = (
  data: unknown
): data is LogoutAllResponse => {
  if (data === null || data === undefined) return false
  if (typeof data !== 'object') return false

  const result = logoutAllResponseSchema.safeParse(data)
  return result.success
}

export class AuthResponseError extends Error {
  readonly endpoint?: string

  constructor(message: string, endpoint?: string) {
    super(message)
    this.name = 'AuthResponseError'
    this.endpoint = endpoint
    Object.setPrototypeOf(this, AuthResponseError.prototype)
  }
}

export const AUTH_ERROR_MESSAGES = {
  INVALID_USER_RESPONSE: 'Invalid user data from server',
  INVALID_LOGIN_RESPONSE: 'Invalid login response from server',
  INVALID_TOKEN_RESPONSE: 'Invalid token response from server',
  INVALID_LOGOUT_RESPONSE: 'Invalid logout response from server',
  NO_REFRESH_TOKEN: 'No refresh token available',
  SESSION_EXPIRED: 'Session expired',
} as const

export const AUTH_SUCCESS_MESSAGES = {
  WELCOME_BACK: (name: string | null) =>
    `Welcome back${name !== null ? `, ${name}` : ''}!`,
  LOGOUT_SUCCESS: 'Logged out successfully',
  PASSWORD_CHANGED: 'Password changed successfully',
  REGISTERED: 'Account created successfully!',
} as const

export type AuthErrorMessage =
  (typeof AUTH_ERROR_MESSAGES)[keyof typeof AUTH_ERROR_MESSAGES]
export type AuthSuccessMessage = typeof AUTH_SUCCESS_MESSAGES
