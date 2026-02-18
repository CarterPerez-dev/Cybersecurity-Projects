// ===========================
// useScan.ts
// ©AngelaMos | 2025
// ===========================

import {
  type UseMutationResult,
  type UseQueryResult,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import type { AxiosError } from 'axios'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { SCAN_ERROR_CONTEXTS, SCAN_ERROR_MESSAGES } from '@/config/constants'
import { createApiErrorHandler } from '@/lib/errors'
import { scanMutations, scanQueries, scanQueryKeys } from '@/services/scanService'
import {
  isValidCreateScanResponse,
  isValidGetScanResponse,
  isValidGetScansResponse,
} from '@/types/guards'
import type {
  CreateScanRequest,
  CreateScanResponse,
  GetScanResponse,
  GetScansResponse,
} from '@/types/scan.types'

export const useGetScans = (): UseQueryResult<GetScansResponse, AxiosError> => {
  return useQuery<GetScansResponse, AxiosError>({
    queryKey: scanQueryKeys.list(),
    queryFn: async (): Promise<GetScansResponse> => {
      const response = await scanQueries.getScans()
      if (!isValidGetScansResponse(response)) {
        throw new Error(SCAN_ERROR_MESSAGES.INVALID_GET_SCANS_RESPONSE)
      }
      return response
    },
    staleTime: 1000 * 60 * 5,
    gcTime: 1000 * 60 * 10,
  })
}

export const useGetScan = (
  id: number
): UseQueryResult<GetScanResponse, AxiosError> => {
  return useQuery<GetScanResponse, AxiosError>({
    queryKey: scanQueryKeys.detail(id),
    queryFn: async (): Promise<GetScanResponse> => {
      const response = await scanQueries.getScan(id)
      if (!isValidGetScanResponse(response)) {
        throw new Error(SCAN_ERROR_MESSAGES.INVALID_GET_SCAN_RESPONSE)
      }
      return response
    },
    staleTime: 1000 * 60 * 5,
    gcTime: 1000 * 60 * 10,
  })
}

export const useCreateScan = (): UseMutationResult<
  CreateScanResponse,
  AxiosError,
  CreateScanRequest
> => {
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  return useMutation<CreateScanResponse, AxiosError, CreateScanRequest>({
    mutationFn: async (data: CreateScanRequest): Promise<CreateScanResponse> => {
      const response = await scanMutations.createScan(data)
      if (!isValidCreateScanResponse(response)) {
        throw new Error(SCAN_ERROR_MESSAGES.INVALID_CREATE_SCAN_RESPONSE)
      }
      return response
    },
    onSuccess: (data: CreateScanResponse): void => {
      void queryClient.invalidateQueries({
        queryKey: scanQueryKeys.lists(),
      })

      toast.success('Scan completed successfully!')
      void navigate(`/scans/${data.id.toString()}`)
    },
    onError: createApiErrorHandler(SCAN_ERROR_CONTEXTS.CREATE_SCAN),
  })
}

export const useDeleteScan = (): UseMutationResult<
  undefined,
  AxiosError,
  number
> => {
  const queryClient = useQueryClient()

  return useMutation<undefined, AxiosError, number>({
    mutationFn: async (id: number): Promise<undefined> => {
      await scanMutations.deleteScan(id)
      return undefined
    },
    onSuccess: (): void => {
      void queryClient.invalidateQueries({
        queryKey: scanQueryKeys.lists(),
      })

      toast.success('Scan deleted successfully!')
    },
    onError: createApiErrorHandler(SCAN_ERROR_CONTEXTS.DELETE_SCAN),
  })
}
