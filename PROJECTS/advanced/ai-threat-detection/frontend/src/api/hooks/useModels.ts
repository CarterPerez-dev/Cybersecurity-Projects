// ===================
// © AngelaMos | 2026
// useModels.ts
//
// TanStack Query hooks for model status and retraining
//
// useModelStatus fetches API_ENDPOINTS.MODELS.STATUS and
// validates the response through ModelStatusSchema, using
// the standard query strategy. useRetrain posts to
// API_ENDPOINTS.MODELS.RETRAIN, validates through
// RetrainResponseSchema, shows a Sonner success toast, and
// invalidates all QUERY_KEYS.MODELS queries to refresh the
// status display. Connects to api/types/models.types,
// core/api, config, pages/models
// ===================

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import type { ModelStatus, RetrainResponse } from '@/api/types'
import { ModelStatusSchema, RetrainResponseSchema } from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export function useModelStatus() {
  return useQuery<ModelStatus>({
    queryKey: QUERY_KEYS.MODELS.STATUS(),
    queryFn: async () => {
      const { data } = await apiClient.get<unknown>(API_ENDPOINTS.MODELS.STATUS)
      return ModelStatusSchema.parse(data)
    },
    ...QUERY_STRATEGIES.standard,
  })
}

export function useRetrain() {
  const queryClient = useQueryClient()

  return useMutation<RetrainResponse>({
    mutationFn: async () => {
      const { data } = await apiClient.post<unknown>(API_ENDPOINTS.MODELS.RETRAIN)
      return RetrainResponseSchema.parse(data)
    },
    onSuccess: () => {
      toast.success('Retraining started')
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.MODELS.ALL })
    },
    onError: () => {
      toast.error('Failed to start retraining')
    },
  })
}
