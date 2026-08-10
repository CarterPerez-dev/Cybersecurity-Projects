// ===================
// © AngelaMos | 2026
// api.config.ts
// ===================

import axios, { type AxiosInstance } from 'axios'

const getBaseURL = (): string => {
  return import.meta.env.VITE_API_URL ?? '/api'
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: getBaseURL(),
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
})
