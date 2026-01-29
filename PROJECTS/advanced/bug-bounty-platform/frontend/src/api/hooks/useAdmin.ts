// ===================
// AngelaMos | 2026
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
  ADMIN_ERROR_MESSAGES,
  ADMIN_SUCCESS_MESSAGES,
  type AdminProgramListResponse,
  type AdminProgramResponse,
  type AdminProgramUpdate,
  type AdminReportListResponse,
  type AdminReportResponse,
  type AdminReportUpdate,
  AdminResponseError,
  type AdminUserCreateRequest,
  type AdminUserListResponse,
  type AdminUserUpdateRequest,
  isValidAdminProgramListResponse,
  isValidAdminProgramResponse,
  isValidAdminReportListResponse,
  isValidAdminReportResponse,
  isValidAdminUserListResponse,
  isValidPlatformStatsResponse,
  isValidUserListResponse,
  isValidUserResponse,
  type PlatformStatsResponse,
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
  stats: () => QUERY_KEYS.ADMIN.STATS(),
  users: {
    all: () => QUERY_KEYS.ADMIN.USERS.ALL(),
    list: (page: number, size: number, role?: string) =>
      QUERY_KEYS.ADMIN.USERS.LIST(page, size, role),
    byId: (id: string) => QUERY_KEYS.ADMIN.USERS.BY_ID(id),
  },
  programs: {
    all: () => QUERY_KEYS.ADMIN.PROGRAMS.ALL(),
    list: (page: number, size: number, status?: string) =>
      QUERY_KEYS.ADMIN.PROGRAMS.LIST(page, size, status),
  },
  reports: {
    all: () => QUERY_KEYS.ADMIN.REPORTS.ALL(),
    list: (page: number, size: number, status?: string, severity?: string) =>
      QUERY_KEYS.ADMIN.REPORTS.LIST(page, size, status, severity),
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
    onSuccess: (newUser: UserResponse): void => {
      queryClient.setQueriesData<UserListResponse>(
        { queryKey: adminQueries.users.all() },
        (oldData) => {
          if (!oldData) return oldData
          return {
            ...oldData,
            items: [newUser, ...oldData.items],
            total: oldData.total + 1,
          }
        }
      )
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
    onSuccess: (
      updatedUser: UserResponse,
      variables: AdminUpdateUserParams
    ): void => {
      queryClient.setQueryData(adminQueries.users.byId(variables.id), updatedUser)
      queryClient.setQueriesData<UserListResponse>(
        { queryKey: adminQueries.users.all() },
        (oldData) => {
          if (!oldData) return oldData
          return {
            ...oldData,
            items: oldData.items.map((user) =>
              user.id === updatedUser.id ? updatedUser : user
            ),
          }
        }
      )
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
    onSuccess: (_, deletedId: string): void => {
      queryClient.removeQueries({ queryKey: adminQueries.users.byId(deletedId) })
      queryClient.setQueriesData<UserListResponse>(
        { queryKey: adminQueries.users.all() },
        (oldData) => {
          if (!oldData) return oldData
          return {
            ...oldData,
            items: oldData.items.filter((user) => user.id !== deletedId),
            total: oldData.total - 1,
          }
        }
      )
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

const fetchPlatformStats = async (): Promise<PlatformStatsResponse> => {
  const response = await apiClient.get<unknown>(API_ENDPOINTS.ADMIN.STATS)
  const data: unknown = response.data

  if (!isValidPlatformStatsResponse(data)) {
    throw new AdminResponseError(
      ADMIN_ERROR_MESSAGES.INVALID_STATS_RESPONSE,
      API_ENDPOINTS.ADMIN.STATS
    )
  }

  return data
}

export const usePlatformStats = (): UseQueryResult<
  PlatformStatsResponse,
  Error
> => {
  return useQuery({
    queryKey: adminQueries.stats(),
    queryFn: fetchPlatformStats,
    ...QUERY_STRATEGIES.standard,
  })
}

interface UseAdminProgramsParams {
  page?: number
  size?: number
  status?: string
}

const fetchAdminPrograms = async (
  page: number,
  size: number,
  status?: string
): Promise<AdminProgramListResponse> => {
  const params: Record<string, unknown> = { page, size }
  if (status) {
    params.status = status
  }

  const response = await apiClient.get<unknown>(
    API_ENDPOINTS.ADMIN.PROGRAMS.LIST,
    {
      params,
    }
  )
  const data: unknown = response.data

  if (!isValidAdminProgramListResponse(data)) {
    throw new AdminResponseError(
      ADMIN_ERROR_MESSAGES.INVALID_PROGRAM_LIST_RESPONSE,
      API_ENDPOINTS.ADMIN.PROGRAMS.LIST
    )
  }

  return data
}

export const useAdminPrograms = (
  params: UseAdminProgramsParams = {}
): UseQueryResult<AdminProgramListResponse, Error> => {
  const page = params.page ?? PAGINATION.DEFAULT_PAGE
  const size = params.size ?? PAGINATION.DEFAULT_SIZE

  return useQuery({
    queryKey: adminQueries.programs.list(page, size, params.status),
    queryFn: () => fetchAdminPrograms(page, size, params.status),
    ...QUERY_STRATEGIES.standard,
  })
}

interface AdminUpdateProgramParams {
  id: string
  data: AdminProgramUpdate
}

const performAdminUpdateProgram = async (
  params: AdminUpdateProgramParams
): Promise<AdminProgramResponse> => {
  const response = await apiClient.patch<unknown>(
    API_ENDPOINTS.ADMIN.PROGRAMS.UPDATE(params.id),
    params.data
  )
  const responseData: unknown = response.data

  if (!isValidAdminProgramResponse(responseData)) {
    throw new AdminResponseError(
      ADMIN_ERROR_MESSAGES.INVALID_PROGRAM_RESPONSE,
      API_ENDPOINTS.ADMIN.PROGRAMS.UPDATE(params.id)
    )
  }

  return responseData
}

export const useAdminUpdateProgram = (): UseMutationResult<
  AdminProgramResponse,
  Error,
  AdminUpdateProgramParams
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: performAdminUpdateProgram,
    onSuccess: (updatedProgram: AdminProgramResponse): void => {
      queryClient.setQueriesData<AdminProgramListResponse>(
        { queryKey: adminQueries.programs.all() },
        (oldData) => {
          if (!oldData) return oldData
          return {
            ...oldData,
            items: oldData.items.map((program) =>
              program.id === updatedProgram.id ? updatedProgram : program
            ),
          }
        }
      )
      toast.success(ADMIN_SUCCESS_MESSAGES.PROGRAM_UPDATED)
    },
    onError: (error: Error): void => {
      const message =
        error instanceof AdminResponseError
          ? error.message
          : ADMIN_ERROR_MESSAGES.FAILED_TO_UPDATE_PROGRAM
      toast.error(message)
    },
  })
}

const performAdminDeleteProgram = async (id: string): Promise<void> => {
  await apiClient.delete(API_ENDPOINTS.ADMIN.PROGRAMS.DELETE(id))
}

export const useAdminDeleteProgram = (): UseMutationResult<
  void,
  Error,
  string
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: performAdminDeleteProgram,
    onSuccess: (_, deletedId: string): void => {
      queryClient.setQueriesData<AdminProgramListResponse>(
        { queryKey: adminQueries.programs.all() },
        (oldData) => {
          if (!oldData) return oldData
          return {
            ...oldData,
            items: oldData.items.filter((program) => program.id !== deletedId),
            total: oldData.total - 1,
          }
        }
      )
      toast.success(ADMIN_SUCCESS_MESSAGES.PROGRAM_DELETED)
    },
    onError: (error: Error): void => {
      const message =
        error instanceof AdminResponseError
          ? error.message
          : ADMIN_ERROR_MESSAGES.FAILED_TO_DELETE_PROGRAM
      toast.error(message)
    },
  })
}

interface UseAdminReportsParams {
  page?: number
  size?: number
  status?: string
  severity?: string
}

const fetchAdminReports = async (
  page: number,
  size: number,
  status?: string,
  severity?: string
): Promise<AdminReportListResponse> => {
  const params: Record<string, unknown> = { page, size }
  if (status) {
    params.status = status
  }
  if (severity) {
    params.severity = severity
  }

  const response = await apiClient.get<unknown>(
    API_ENDPOINTS.ADMIN.REPORTS.LIST,
    {
      params,
    }
  )
  const data: unknown = response.data

  if (!isValidAdminReportListResponse(data)) {
    throw new AdminResponseError(
      ADMIN_ERROR_MESSAGES.INVALID_REPORT_LIST_RESPONSE,
      API_ENDPOINTS.ADMIN.REPORTS.LIST
    )
  }

  return data
}

export const useAdminReports = (
  params: UseAdminReportsParams = {}
): UseQueryResult<AdminReportListResponse, Error> => {
  const page = params.page ?? PAGINATION.DEFAULT_PAGE
  const size = params.size ?? PAGINATION.DEFAULT_SIZE

  return useQuery({
    queryKey: adminQueries.reports.list(
      page,
      size,
      params.status,
      params.severity
    ),
    queryFn: () => fetchAdminReports(page, size, params.status, params.severity),
    ...QUERY_STRATEGIES.standard,
  })
}

interface AdminUpdateReportParams {
  id: string
  data: AdminReportUpdate
}

const performAdminUpdateReport = async (
  params: AdminUpdateReportParams
): Promise<AdminReportResponse> => {
  const response = await apiClient.patch<unknown>(
    API_ENDPOINTS.ADMIN.REPORTS.UPDATE(params.id),
    params.data
  )
  const responseData: unknown = response.data

  if (!isValidAdminReportResponse(responseData)) {
    throw new AdminResponseError(
      ADMIN_ERROR_MESSAGES.INVALID_REPORT_RESPONSE,
      API_ENDPOINTS.ADMIN.REPORTS.UPDATE(params.id)
    )
  }

  return responseData
}

export const useAdminUpdateReport = (): UseMutationResult<
  AdminReportResponse,
  Error,
  AdminUpdateReportParams
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: performAdminUpdateReport,
    onSuccess: (updatedReport: AdminReportResponse): void => {
      queryClient.setQueriesData<AdminReportListResponse>(
        { queryKey: adminQueries.reports.all() },
        (oldData) => {
          if (!oldData) return oldData
          return {
            ...oldData,
            items: oldData.items.map((report) =>
              report.id === updatedReport.id ? updatedReport : report
            ),
          }
        }
      )
      toast.success(ADMIN_SUCCESS_MESSAGES.REPORT_UPDATED)
    },
    onError: (error: Error): void => {
      const message =
        error instanceof AdminResponseError
          ? error.message
          : ADMIN_ERROR_MESSAGES.FAILED_TO_UPDATE_REPORT
      toast.error(message)
    },
  })
}

interface UseAdminUsersWithStatsParams {
  page?: number
  size?: number
  role?: string
}

const fetchAdminUsersWithStats = async (
  page: number,
  size: number,
  role?: string
): Promise<AdminUserListResponse> => {
  const params: Record<string, unknown> = { page, size }
  if (role) {
    params.role = role
  }

  const response = await apiClient.get<unknown>(API_ENDPOINTS.ADMIN.USERS.LIST, {
    params,
  })
  const data: unknown = response.data

  if (!isValidAdminUserListResponse(data)) {
    throw new AdminResponseError(
      ADMIN_ERROR_MESSAGES.INVALID_USER_LIST_RESPONSE,
      API_ENDPOINTS.ADMIN.USERS.LIST
    )
  }

  return data
}

export const useAdminUsersWithStats = (
  params: UseAdminUsersWithStatsParams = {}
): UseQueryResult<AdminUserListResponse, Error> => {
  const page = params.page ?? PAGINATION.DEFAULT_PAGE
  const size = params.size ?? PAGINATION.DEFAULT_SIZE

  return useQuery({
    queryKey: adminQueries.users.list(page, size, params.role),
    queryFn: () => fetchAdminUsersWithStats(page, size, params.role),
    ...QUERY_STRATEGIES.standard,
  })
}
