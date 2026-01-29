// ===================
// AngelaMos | 2025
// usePrograms.ts
// ===================

import {
  type UseMutationResult,
  type UseQueryResult,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { toast } from 'sonner'

import {
  type Asset,
  type AssetCreate,
  isValidProgramDetail,
  isValidProgramList,
  type Program,
  type ProgramCreate,
  type ProgramDetail,
  type ProgramList,
  type ProgramUpdate,
  type RewardTier,
  type RewardTierCreate,
} from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient } from '@/core/api'

export const programQueries = {
  all: () => QUERY_KEYS.PROGRAMS.ALL,
  list: (page: number, size: number) => QUERY_KEYS.PROGRAMS.LIST(page, size),
  mine: (page: number, size: number) => QUERY_KEYS.PROGRAMS.MINE(page, size),
  bySlug: (slug: string) => QUERY_KEYS.PROGRAMS.BY_SLUG(slug),
} as const

const fetchPrograms = async (
  page: number,
  size: number
): Promise<ProgramList> => {
  const response = await apiClient.get<unknown>(API_ENDPOINTS.PROGRAMS.LIST, {
    params: { page, size },
  })

  if (!isValidProgramList(response.data)) {
    throw new Error('Invalid program list response')
  }

  return response.data
}

export const usePrograms = (
  page: number = 1,
  size: number = 20
): UseQueryResult<ProgramList, Error> => {
  return useQuery({
    queryKey: programQueries.list(page, size),
    queryFn: () => fetchPrograms(page, size),
  })
}

const fetchMyPrograms = async (
  page: number,
  size: number
): Promise<ProgramList> => {
  const response = await apiClient.get<unknown>(API_ENDPOINTS.PROGRAMS.MINE, {
    params: { page, size },
  })

  if (!isValidProgramList(response.data)) {
    throw new Error('Invalid program list response')
  }

  return response.data
}

export const useMyPrograms = (
  page: number = 1,
  size: number = 20
): UseQueryResult<ProgramList, Error> => {
  return useQuery({
    queryKey: programQueries.mine(page, size),
    queryFn: () => fetchMyPrograms(page, size),
  })
}

const fetchProgramBySlug = async (slug: string): Promise<ProgramDetail> => {
  const response = await apiClient.get<unknown>(
    API_ENDPOINTS.PROGRAMS.BY_SLUG(slug)
  )

  if (!isValidProgramDetail(response.data)) {
    throw new Error('Invalid program detail response')
  }

  return response.data
}

export const useProgram = (
  slug: string
): UseQueryResult<ProgramDetail, Error> => {
  return useQuery({
    queryKey: programQueries.bySlug(slug),
    queryFn: () => fetchProgramBySlug(slug),
    enabled: !!slug,
  })
}

const createProgram = async (data: ProgramCreate): Promise<Program> => {
  const response = await apiClient.post<Program>(
    API_ENDPOINTS.PROGRAMS.CREATE,
    data
  )
  return response.data
}

export const useCreateProgram = (): UseMutationResult<
  Program,
  Error,
  ProgramCreate
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: createProgram,
    onSuccess: (newProgram) => {
      queryClient.invalidateQueries({ queryKey: programQueries.list(1, 20) })
      queryClient.invalidateQueries({ queryKey: programQueries.mine(1, 20) })

      toast.success(`Program "${newProgram.name}" created successfully`)
    },
    onError: () => {
      toast.error('Failed to create program')
    },
  })
}

const updateProgram = async ({
  id,
  data,
}: {
  id: string
  data: ProgramUpdate
}): Promise<Program> => {
  const response = await apiClient.patch<Program>(
    API_ENDPOINTS.PROGRAMS.BY_ID(id),
    data
  )
  return response.data
}

export const useUpdateProgram = (): UseMutationResult<
  Program,
  Error,
  { id: string; data: ProgramUpdate }
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: updateProgram,
    onSuccess: (updatedProgram) => {
      const queries = queryClient.getQueriesData<ProgramDetail>({
        queryKey: programQueries.all(),
      })

      for (const [key, data] of queries) {
        if (data && data.id === updatedProgram.id) {
          queryClient.setQueryData<ProgramDetail>(key, {
            ...data,
            ...updatedProgram,
          })
        }
      }

      queryClient.invalidateQueries({ queryKey: programQueries.list(1, 20) })
      queryClient.invalidateQueries({ queryKey: programQueries.mine(1, 20) })

      toast.success(`Program "${updatedProgram.name}" updated successfully`)
    },
    onError: () => {
      toast.error('Failed to update program')
    },
  })
}

const deleteProgram = async (id: string): Promise<void> => {
  await apiClient.delete(API_ENDPOINTS.PROGRAMS.BY_ID(id))
}

export const useDeleteProgram = (): UseMutationResult<void, Error, string> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: deleteProgram,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: programQueries.list(1, 20) })
      queryClient.invalidateQueries({ queryKey: programQueries.mine(1, 20) })

      toast.success('Program deleted successfully')
    },
    onError: () => {
      toast.error('Failed to delete program')
    },
  })
}

const addAsset = async ({
  programId,
  data,
}: {
  programId: string
  data: AssetCreate
}): Promise<Asset> => {
  const response = await apiClient.post<Asset>(
    API_ENDPOINTS.PROGRAMS.ASSETS(programId),
    data
  )
  return response.data
}

export const useAddAsset = (): UseMutationResult<
  Asset,
  Error,
  { programId: string; data: AssetCreate }
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: addAsset,
    onSuccess: (newAsset, variables) => {
      const queries = queryClient.getQueriesData<ProgramDetail>({
        queryKey: programQueries.all(),
      })

      for (const [key, data] of queries) {
        if (data && 'assets' in data && data.id === variables.programId) {
          queryClient.setQueryData<ProgramDetail>(key, {
            ...data,
            assets: [...data.assets, newAsset],
          })
        }
      }

      toast.success('Asset added successfully')
    },
    onError: () => {
      toast.error('Failed to add asset')
    },
  })
}

const deleteAsset = async ({
  programId,
  assetId,
}: {
  programId: string
  assetId: string
}): Promise<void> => {
  await apiClient.delete(API_ENDPOINTS.PROGRAMS.ASSET(programId, assetId))
}

export const useDeleteAsset = (): UseMutationResult<
  void,
  Error,
  { programId: string; assetId: string }
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: deleteAsset,
    onSuccess: (_, variables) => {
      const queries = queryClient.getQueriesData<ProgramDetail>({
        queryKey: programQueries.all(),
      })

      for (const [key, data] of queries) {
        if (data && 'assets' in data && data.id === variables.programId) {
          queryClient.setQueryData<ProgramDetail>(key, {
            ...data,
            assets: data.assets.filter((a) => a.id !== variables.assetId),
          })
        }
      }

      toast.success('Asset deleted successfully')
    },
    onError: () => {
      toast.error('Failed to delete asset')
    },
  })
}

const setRewardTiers = async ({
  programId,
  tiers,
}: {
  programId: string
  tiers: RewardTierCreate[]
}): Promise<RewardTier[]> => {
  const response = await apiClient.put<RewardTier[]>(
    API_ENDPOINTS.PROGRAMS.REWARDS(programId),
    tiers
  )
  return response.data
}

export const useSetRewardTiers = (): UseMutationResult<
  RewardTier[],
  Error,
  { programId: string; tiers: RewardTierCreate[] }
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: setRewardTiers,
    onSuccess: (updatedTiers, variables) => {
      const queries = queryClient.getQueriesData<ProgramDetail>({
        queryKey: programQueries.all(),
      })

      for (const [key, data] of queries) {
        if (data && 'reward_tiers' in data && data.id === variables.programId) {
          queryClient.setQueryData<ProgramDetail>(key, {
            ...data,
            reward_tiers: updatedTiers,
          })
        }
      }

      toast.success('Reward tiers updated successfully')
    },
    onError: () => {
      toast.error('Failed to update reward tiers')
    },
  })
}
