// ===================
// © AngelaMos | 2025
// useAdmin.ts
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
  type AdminUserCreateRequest,
  type AdminUserUpdateRequest,
  isValidUserListResponse,
  isValidUserResponse,
  USER_ERROR_MESSAGES,
  USER_SUCCESS_MESSAGES,
  type UserListResponse,
  type UserResponse,
  UserResponseError,
} from '@/api/types'
import { API_ENDPOINTS, PAGINATION, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export const adminQueries = {
  all: () => QUERY_KEYS.ADMIN.ALL,
  users: {
    all: () => QUERY_KEYS.ADMIN.USERS.ALL(),
    list: (page: number, size: number) => QUERY_KEYS.ADMIN.USERS.LIST(page, size),
    byId: (id: string) => QUERY_KEYS.ADMIN.USERS.BY_ID(id),
  },
} as const

interface UseAdminUsersParams {
  page?: number
  size?: number
}

const fetchAdminUsers = async (
  page: number,
  size: number
): Promise<UserListResponse> => {
  const response = await apiClient.get<unknown>(API_ENDPOINTS.ADMIN.USERS.LIST, {
    params: { page, size },
  })
  const data: unknown = response.data

  if (!isValidUserListResponse(data)) {
    throw new UserResponseError(
      USER_ERROR_MESSAGES.INVALID_USER_LIST_RESPONSE,
      API_ENDPOINTS.ADMIN.USERS.LIST
    )
  }

  return data
}

export const useAdminUsers = (
  params: UseAdminUsersParams = {}
): UseQueryResult<UserListResponse, Error> => {
  const page = params.page ?? PAGINATION.DEFAULT_PAGE
  const size = params.size ?? PAGINATION.DEFAULT_SIZE

  return useQuery({
    queryKey: adminQueries.users.list(page, size),
    queryFn: () => fetchAdminUsers(page, size),
    ...QUERY_STRATEGIES.standard,
  })
}

const fetchAdminUserById = async (id: string): Promise<UserResponse> => {
  const response = await apiClient.get<unknown>(
    API_ENDPOINTS.ADMIN.USERS.BY_ID(id)
  )
  const data: unknown = response.data

  if (!isValidUserResponse(data)) {
    throw new UserResponseError(
      USER_ERROR_MESSAGES.INVALID_USER_RESPONSE,
      API_ENDPOINTS.ADMIN.USERS.BY_ID(id)
    )
  }

  return data
}

export const useAdminUser = (id: string): UseQueryResult<UserResponse, Error> => {
  return useQuery({
    queryKey: adminQueries.users.byId(id),
    queryFn: () => fetchAdminUserById(id),
    enabled: id.length > 0,
    ...QUERY_STRATEGIES.standard,
  })
}

const performAdminCreateUser = async (
  data: AdminUserCreateRequest
): Promise<UserResponse> => {
  const response = await apiClient.post<unknown>(
    API_ENDPOINTS.ADMIN.USERS.CREATE,
    data
  )
  const responseData: unknown = response.data

  if (!isValidUserResponse(responseData)) {
    throw new UserResponseError(
      USER_ERROR_MESSAGES.INVALID_USER_RESPONSE,
      API_ENDPOINTS.ADMIN.USERS.CREATE
    )
  }

  return responseData
}

export const useAdminCreateUser = (): UseMutationResult<
  UserResponse,
  Error,
  AdminUserCreateRequest
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: performAdminCreateUser,
    onSuccess: (): void => {
      void queryClient.invalidateQueries({ queryKey: adminQueries.users.all() })

      toast.success(USER_SUCCESS_MESSAGES.CREATED)
    },
    onError: (error: Error): void => {
      const message =
        error instanceof UserResponseError
          ? error.message
          : USER_ERROR_MESSAGES.FAILED_TO_CREATE
      toast.error(message)
    },
  })
}

interface AdminUpdateUserParams {
  id: string
  data: AdminUserUpdateRequest
}

const performAdminUpdateUser = async (
  params: AdminUpdateUserParams
): Promise<UserResponse> => {
  const response = await apiClient.patch<unknown>(
    API_ENDPOINTS.ADMIN.USERS.UPDATE(params.id),
    params.data
  )
  const responseData: unknown = response.data

  if (!isValidUserResponse(responseData)) {
    throw new UserResponseError(
      USER_ERROR_MESSAGES.INVALID_USER_RESPONSE,
      API_ENDPOINTS.ADMIN.USERS.UPDATE(params.id)
    )
  }

  return responseData
}

export const useAdminUpdateUser = (): UseMutationResult<
  UserResponse,
  Error,
  AdminUpdateUserParams
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: performAdminUpdateUser,
    onSuccess: (data: UserResponse, variables: AdminUpdateUserParams): void => {
      queryClient.setQueryData(adminQueries.users.byId(variables.id), data)

      void queryClient.invalidateQueries({ queryKey: adminQueries.users.all() })

      toast.success(USER_SUCCESS_MESSAGES.UPDATED)
    },
    onError: (error: Error): void => {
      const message =
        error instanceof UserResponseError
          ? error.message
          : USER_ERROR_MESSAGES.FAILED_TO_UPDATE
      toast.error(message)
    },
  })
}

const performAdminDeleteUser = async (id: string): Promise<void> => {
  await apiClient.delete(API_ENDPOINTS.ADMIN.USERS.DELETE(id))
}

export const useAdminDeleteUser = (): UseMutationResult<void, Error, string> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: performAdminDeleteUser,
    onSuccess: (_, id: string): void => {
      queryClient.removeQueries({ queryKey: adminQueries.users.byId(id) })

      void queryClient.invalidateQueries({ queryKey: adminQueries.users.all() })

      toast.success(USER_SUCCESS_MESSAGES.DELETED)
    },
    onError: (error: Error): void => {
      const message =
        error instanceof UserResponseError
          ? error.message
          : USER_ERROR_MESSAGES.FAILED_TO_DELETE
      toast.error(message)
    },
  })
}
