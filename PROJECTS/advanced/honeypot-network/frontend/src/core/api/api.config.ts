// ===================
// ©AngelaMos | 2026
// api.config.ts
// ===================

import axios, { type AxiosError, type AxiosInstance } from 'axios'
import { transformAxiosError } from './errors'

export const getBaseURL = (): string => {
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
