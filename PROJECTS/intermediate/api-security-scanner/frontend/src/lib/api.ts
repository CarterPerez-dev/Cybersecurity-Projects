/**
 * ©AngelaMos | 2025
 * Axios instance with request/response interceptors
 */

import axios, { type AxiosError, type AxiosResponse } from 'axios'
import { API_BASE_URL, STORAGE_KEYS } from '@/config/constants'

/**
 * Axios Base Config
 */
const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 180000,
  headers: {
    'Content-Type': 'application/json',
  },
})

/**
 * Request interceptor
 */
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem(STORAGE_KEYS.AUTH_TOKEN)
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error: AxiosError) => {
    return Promise.reject(error)
  }
)

/**
 * Response interceptor
 */
axiosInstance.interceptors.response.use(
  (response: AxiosResponse) => {
    return response
  },
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      const requestUrl = error.config?.url ?? ''
      const isAuthEndpoint =
        requestUrl.includes('/auth/login') ||
        requestUrl.includes('/auth/register')

      if (!isAuthEndpoint) {
        localStorage.removeItem(STORAGE_KEYS.AUTH_TOKEN)
        localStorage.removeItem(STORAGE_KEYS.USER)
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

/**
 * API wrapper
 */
export const api = {
  get: async <T>(url: string): Promise<T> => {
    const response = await axiosInstance.get<T>(url)
    return response.data
  },

  post: async <T>(url: string, data?: unknown): Promise<T> => {
    const response = await axiosInstance.post<T>(url, data)
    return response.data
  },

  put: async <T>(url: string, data?: unknown): Promise<T> => {
    const response = await axiosInstance.put<T>(url, data)
    return response.data
  },

  delete: async <T>(url: string): Promise<T> => {
    const response = await axiosInstance.delete<T>(url)
    return response.data
  },
}
