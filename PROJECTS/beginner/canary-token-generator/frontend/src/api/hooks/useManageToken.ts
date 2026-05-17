// ===================
// ©AngelaMos | 2026
// useManageToken.ts
// ===================

import { useQuery } from '@tanstack/react-query'
import { QUERY_STRATEGIES } from '@/core/api'
import { apiGet } from '../client'
import { manageResponseSchema } from '../types/event'

const MANAGE_PATH_PREFIX = '/m/'
const MANAGE_KEY_PREFIX = ['canary', 'manage'] as const

export type UseManageTokenParams = {
  cursor?: string
  limit?: number
}

function buildSearch(params: UseManageTokenParams | undefined): string {
  if (!params) {
    return ''
  }
  const sp = new URLSearchParams()
  if (params.cursor !== undefined && params.cursor.length > 0) {
    sp.set('cursor', params.cursor)
  }
  if (params.limit !== undefined) {
    sp.set('limit', String(params.limit))
  }
  const query = sp.toString()
  return query.length > 0 ? `?${query}` : ''
}

export function useManageToken(manageId: string, params?: UseManageTokenParams) {
  const search = buildSearch(params)
  const path = `${MANAGE_PATH_PREFIX}${encodeURIComponent(manageId)}${search}`
  return useQuery({
    queryKey: [...MANAGE_KEY_PREFIX, manageId, params ?? null],
    queryFn: () => apiGet(path, manageResponseSchema),
    enabled: manageId.length > 0,
    ...QUERY_STRATEGIES.frequent,
  })
}
