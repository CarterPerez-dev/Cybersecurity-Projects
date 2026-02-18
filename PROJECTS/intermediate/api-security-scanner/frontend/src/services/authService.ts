// ===========================
// authService.ts
// ©AngelaMos | 2025
// ===========================

import { AUTH_ENDPOINTS } from '@/config/constants'
import { api } from '@/lib/api'
import type {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
} from '@/types/auth.types'

export const authQueryKeys = {
  all: ['auth'] as const,
  user: () => [...authQueryKeys.all, 'user'] as const,
} as const

export const authMutations = {
  register: async (data: RegisterRequest): Promise<RegisterResponse> => {
    return api.post<RegisterResponse>(AUTH_ENDPOINTS.REGISTER, data)
  },

  login: async (data: LoginRequest): Promise<LoginResponse> => {
    return api.post<LoginResponse>(AUTH_ENDPOINTS.LOGIN, data)
  },
}
