// ===========================
// useAuth.ts
// ©AngelaMos | 2025
// ===========================

import { type UseMutationResult, useMutation } from '@tanstack/react-query'
import { type AxiosError, isAxiosError } from 'axios'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { AUTH_ERROR_CONTEXTS, AUTH_ERROR_MESSAGES } from '@/config/constants'
import { authMutations } from '@/services/authService'
import { useAuthStore } from '@/store/authStore'
import type {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
} from '@/types/auth.types'
import { isValidLoginResponse, isValidRegisterResponse } from '@/types/guards'

const createAuthErrorHandler = (context: string) => {
  return (error: unknown): void => {
    if (
      isAxiosError(error) &&
      error.response?.data !== null &&
      error.response?.data !== undefined
    ) {
      const errorData: unknown = error.response.data

      if (
        typeof errorData === 'object' &&
        errorData !== null &&
        'detail' in errorData
      ) {
        const apiError = errorData as { detail: unknown }
        if (typeof apiError.detail === 'string' && apiError.detail.length > 0) {
          toast.error(apiError.detail)
          return
        }
      }
    }

    const fallbackMessage =
      error instanceof Error ? error.message : `${context} failed`
    toast.error(fallbackMessage)
  }
}

export const useRegister = (): UseMutationResult<
  RegisterResponse,
  AxiosError,
  RegisterRequest
> => {
  const navigate = useNavigate()

  return useMutation<RegisterResponse, AxiosError, RegisterRequest>({
    mutationFn: async (data: RegisterRequest): Promise<RegisterResponse> => {
      const response = await authMutations.register(data)
      if (!isValidRegisterResponse(response)) {
        throw new Error(AUTH_ERROR_MESSAGES.INVALID_REGISTER_RESPONSE)
      }
      return response
    },
    onSuccess: (_data: RegisterResponse): void => {
      toast.success('Account created! Please login.')
      void navigate('/login')
    },
    onError: createAuthErrorHandler(AUTH_ERROR_CONTEXTS.REGISTER),
  })
}

export const useLogin = (): UseMutationResult<
  LoginResponse,
  AxiosError,
  LoginRequest
> => {
  const navigate = useNavigate()
  const { setAuth } = useAuthStore()

  return useMutation<LoginResponse, AxiosError, LoginRequest>({
    mutationFn: async (data: LoginRequest): Promise<LoginResponse> => {
      const response = await authMutations.login(data)
      if (!isValidLoginResponse(response)) {
        throw new Error(AUTH_ERROR_MESSAGES.INVALID_LOGIN_RESPONSE)
      }
      return response
    },
    onSuccess: (data: LoginResponse, variables: LoginRequest): void => {
      const user = {
        id: 0,
        email: variables.email,
        is_active: true,
        created_at: new Date().toISOString(),
      }

      setAuth(user, data.access_token)
      toast.success('Login successful!')
      void navigate('/')
    },
    onError: createAuthErrorHandler(AUTH_ERROR_CONTEXTS.LOGIN),
  })
}

export const useLogout = (): (() => void) => {
  const navigate = useNavigate()
  const { clearAuth } = useAuthStore()

  return (): void => {
    clearAuth()
    toast.success('Logged out successfully')
    void navigate('/login')
  }
}
