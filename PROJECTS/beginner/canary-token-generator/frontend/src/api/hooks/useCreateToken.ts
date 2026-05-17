// ===================
// ©AngelaMos | 2026
// useCreateToken.ts
// ===================

import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiPost } from '../client'
import {
  type CreateTokenInput,
  type CreateTokenResponse,
  createTokenResponseSchema,
} from '../types/token'

const CREATE_TOKEN_PATH = '/tokens'
const MANAGE_KEY_PREFIX = ['canary', 'manage'] as const

export function useCreateToken() {
  const queryClient = useQueryClient()
  return useMutation<CreateTokenResponse, Error, CreateTokenInput>({
    mutationFn: (body) =>
      apiPost(CREATE_TOKEN_PATH, body, createTokenResponseSchema),
    onSuccess: (data) => {
      queryClient.invalidateQueries({
        queryKey: [...MANAGE_KEY_PREFIX, data.token.manage_id],
      })
    },
  })
}
