// ===================
// © AngelaMos | 2026
// api.config.ts
//
// Axios HTTP client instance configured with base URL
// from VITE_API_URL (fallback /api), 15s timeout, JSON
// content type, and credentials enabled
//
// Connects to:
//   api/hooks - used for upload and analysis requests
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
