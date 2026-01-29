// ===================
// © AngelaMos | 2025
// api.config.ts
// ===================

import axios, {
  type AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from 'axios'
import { API_ENDPOINTS, HTTP_STATUS } from '@/config'
import { useAuthStore } from '@/core/lib'
import { ApiError, ApiErrorCode, transformAxiosError } from './errors'

interface RequestConfig extends InternalAxiosRequestConfig {
  _retry?: boolean
}

interface RefreshSubscriber {
  resolve: (token: string) => void
  reject: (error: Error) => void
}

const getBaseURL = (): string => {
  return import.meta.env.VITE_API_URL ?? '/api'
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: getBaseURL(),
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
})

let isRefreshing = false
let refreshSubscribers: RefreshSubscriber[] = []

const processRefreshQueue = (error: Error | null, token: string | null): void => {
  refreshSubscribers.forEach((subscriber) => {
    if (error !== null) {
      subscriber.reject(error)
    } else if (token !== null) {
      subscriber.resolve(token)
    }
  })
  refreshSubscribers = []
}

const addRefreshSubscriber = (
  resolve: (token: string) => void,
  reject: (error: Error) => void
): void => {
  refreshSubscribers.push({ resolve, reject })
}

const handleTokenRefresh = async (): Promise<string> => {
  const response = await apiClient.post<{ access_token: string }>(
    API_ENDPOINTS.AUTH.REFRESH
  )

  if (
    response.data === null ||
    response.data === undefined ||
    typeof response.data !== 'object'
  ) {
    throw new ApiError(
      'Invalid refresh response',
      ApiErrorCode.AUTHENTICATION_ERROR,
      HTTP_STATUS.UNAUTHORIZED
    )
  }

  const accessToken = response.data.access_token
  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    throw new ApiError(
      'Invalid access token',
      ApiErrorCode.AUTHENTICATION_ERROR,
      HTTP_STATUS.UNAUTHORIZED
    )
  }

  return accessToken
}

const handleAuthFailure = (): void => {
  useAuthStore.getState().logout()
  window.location.href = '/login'
}

apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig): InternalAxiosRequestConfig => {
    const token = useAuthStore.getState().accessToken
    if (token !== null && token.length > 0) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error: unknown): Promise<never> => {
    return Promise.reject(error)
  }
)

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError): Promise<unknown> => {
    const originalRequest = error.config as RequestConfig | undefined

    if (originalRequest === undefined) {
      return Promise.reject(transformAxiosError(error))
    }

    const isUnauthorized = error.response?.status === HTTP_STATUS.UNAUTHORIZED
    const isNotRetried = originalRequest._retry !== true
    const isNotRefreshEndpoint =
      originalRequest.url?.includes(API_ENDPOINTS.AUTH.REFRESH) !== true

    if (isUnauthorized && isNotRetried && isNotRefreshEndpoint) {
      if (isRefreshing) {
        return new Promise<unknown>((resolve, reject) => {
          addRefreshSubscriber(
            (newToken: string): void => {
              originalRequest.headers.Authorization = `Bearer ${newToken}`
              resolve(apiClient(originalRequest))
            },
            (refreshError: Error): void => {
              reject(refreshError)
            }
          )
        })
      }

      originalRequest._retry = true
      isRefreshing = true

      try {
        const newToken = await handleTokenRefresh()
        useAuthStore.getState().setAccessToken(newToken)
        processRefreshQueue(null, newToken)
        originalRequest.headers.Authorization = `Bearer ${newToken}`
        return await apiClient(originalRequest)
      } catch (refreshError: unknown) {
        const apiError =
          refreshError instanceof ApiError
            ? refreshError
            : new ApiError(
                'Session expired',
                ApiErrorCode.AUTHENTICATION_ERROR,
                HTTP_STATUS.UNAUTHORIZED
              )
        processRefreshQueue(apiError, null)
        handleAuthFailure()
        return Promise.reject(apiError)
      } finally {
        isRefreshing = false
      }
    }

    return Promise.reject(transformAxiosError(error))
  }
)
