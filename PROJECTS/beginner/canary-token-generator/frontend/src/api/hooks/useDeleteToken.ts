// ===================
// ©AngelaMos | 2026
// useDeleteToken.ts
// ===================

import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiDelete } from '../client'

const MANAGE_PATH_PREFIX = '/m/'
const MANAGE_KEY_PREFIX = ['canary', 'manage'] as const

export function useDeleteToken() {
  const queryClient = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: (manageId) =>
      apiDelete(`${MANAGE_PATH_PREFIX}${encodeURIComponent(manageId)}`),
    onSuccess: (_data, manageId) => {
      queryClient.removeQueries({
        queryKey: [...MANAGE_KEY_PREFIX, manageId],
      })
    },
  })
}
