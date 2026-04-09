// ===================
// © AngelaMos | 2026
// index.ts
//
// TanStack React Query hooks for binary upload and
// analysis retrieval
//
// useUpload returns a mutation that POSTs a File as
// multipart/form-data to API_ENDPOINTS.UPLOAD with
// UPLOAD_TIMEOUT_MS (120s), Zod-validates the response
// through UploadResponseSchema, and transforms Axios
// errors via transformAxiosError. useAnalysis returns a
// query keyed by QUERY_KEYS.ANALYSIS.BY_SLUG(slug)
// that GETs the full analysis result, Zod-validates
// through AnalysisResponseSchema, and is configured
// with staleTime: Infinity and no window-focus refetch
// since analysis results are immutable once computed
//
// Connects to:
//   config.ts           - API_ENDPOINTS, QUERY_KEYS,
//                          UPLOAD_TIMEOUT_MS
//   core/api/api.config - apiClient instance
//   core/api/errors     - transformAxiosError
//   api/schemas         - parse() validation
//   api/types           - UploadResponse, ApiErrorBody
// ===================

import { useMutation, useQuery } from '@tanstack/react-query'
import type { AxiosError } from 'axios'
import { API_ENDPOINTS, QUERY_KEYS, UPLOAD_TIMEOUT_MS } from '@/config'
import { apiClient } from '@/core/api'
import { transformAxiosError } from '@/core/api/errors'
import { AnalysisResponseSchema, UploadResponseSchema } from '../schemas'
import type { ApiErrorBody, UploadResponse } from '../types'

export function useUpload() {
  return useMutation<
    UploadResponse,
    ReturnType<typeof transformAxiosError>,
    File
  >({
    mutationFn: async (file: File) => {
      const form = new FormData()
      form.append('file', file)

      const { data } = await apiClient.post(API_ENDPOINTS.UPLOAD, form, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: UPLOAD_TIMEOUT_MS,
      })

      return UploadResponseSchema.parse(data)
    },
    onError: (error) => {
      return transformAxiosError(error as unknown as AxiosError<ApiErrorBody>)
    },
  })
}

export function useAnalysis(slug: string) {
  return useQuery({
    queryKey: QUERY_KEYS.ANALYSIS.BY_SLUG(slug),
    queryFn: async () => {
      const { data } = await apiClient.get(API_ENDPOINTS.ANALYSIS(slug))
      return AnalysisResponseSchema.parse(data)
    },
    enabled: slug.length > 0,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  })
}
