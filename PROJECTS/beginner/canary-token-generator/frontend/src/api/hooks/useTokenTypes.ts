// ===================
// ©AngelaMos | 2026
// useTokenTypes.ts
// ===================

import { useQuery } from '@tanstack/react-query'
import { QUERY_STRATEGIES } from '@/core/api'
import { apiGet } from '../client'
import { typeDescriptorListSchema } from '../types/token'

const TOKEN_TYPES_PATH = '/tokens/types'
const TOKEN_TYPES_KEY = ['canary', 'token-types'] as const

export function useTokenTypes() {
  return useQuery({
    queryKey: TOKEN_TYPES_KEY,
    queryFn: () => apiGet(TOKEN_TYPES_PATH, typeDescriptorListSchema),
    ...QUERY_STRATEGIES.static,
  })
}
