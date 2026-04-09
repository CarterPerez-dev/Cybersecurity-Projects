// ===================
// © AngelaMos | 2026
// api.config.ts
//
// Axios HTTP client singleton with error interceptor
//
// Creates an axios instance with base URL from VITE_API_URL
// env var (defaulting to /api), 15-second timeout, and JSON
// content type. Response interceptor transforms AxiosError
// into typed ApiError via transformAxiosError for consistent
// error handling across all API hooks
// ===================

import axios, { type AxiosError, type AxiosInstance } from 'axios'
import { transformAxiosError } from './errors'

const getBaseURL = (): string => {
  return import.meta.env.VITE_API_URL ?? '/api'
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: getBaseURL(),
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError): Promise<never> => {
    return Promise.reject(transformAxiosError(error))
  }
)
