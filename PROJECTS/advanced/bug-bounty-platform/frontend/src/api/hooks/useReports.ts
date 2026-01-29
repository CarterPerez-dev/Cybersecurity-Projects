// ===================
// AngelaMos | 2025
// useReports.ts
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
  type Comment,
  type CommentCreate,
  isValidReportDetail,
  isValidReportList,
  isValidReportStats,
  type Report,
  type ReportCreate,
  type ReportDetail,
  type ReportList,
  type ReportStats,
  type ReportTriage,
  type ReportUpdate,
} from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient } from '@/core/api'

export const reportQueries = {
  all: () => QUERY_KEYS.REPORTS.ALL,
  list: (page: number, size: number) => QUERY_KEYS.REPORTS.LIST(page, size),
  inbox: (page: number, size: number) => QUERY_KEYS.REPORTS.INBOX(page, size),
  stats: () => QUERY_KEYS.REPORTS.STATS(),
  byId: (id: string) => QUERY_KEYS.REPORTS.BY_ID(id),
  byProgram: (programId: string, page: number, size: number) =>
    QUERY_KEYS.REPORTS.BY_PROGRAM(programId, page, size),
} as const

const fetchMyReports = async (
  page: number,
  size: number
): Promise<ReportList> => {
  const response = await apiClient.get<unknown>(API_ENDPOINTS.REPORTS.LIST, {
    params: { page, size },
  })

  if (!isValidReportList(response.data)) {
    throw new Error('Invalid report list response')
  }

  return response.data
}

export const useMyReports = (
  page: number = 1,
  size: number = 20
): UseQueryResult<ReportList, Error> => {
  return useQuery({
    queryKey: reportQueries.list(page, size),
    queryFn: () => fetchMyReports(page, size),
  })
}

const fetchInbox = async (page: number, size: number): Promise<ReportList> => {
  const response = await apiClient.get<unknown>(API_ENDPOINTS.REPORTS.INBOX, {
    params: { page, size },
  })

  if (!isValidReportList(response.data)) {
    throw new Error('Invalid report list response')
  }

  return response.data
}

export const useInbox = (
  page: number = 1,
  size: number = 20
): UseQueryResult<ReportList, Error> => {
  return useQuery({
    queryKey: reportQueries.inbox(page, size),
    queryFn: () => fetchInbox(page, size),
  })
}

const fetchReportStats = async (): Promise<ReportStats> => {
  const response = await apiClient.get<unknown>(API_ENDPOINTS.REPORTS.STATS)

  if (!isValidReportStats(response.data)) {
    throw new Error('Invalid report stats response')
  }

  return response.data
}

export const useReportStats = (): UseQueryResult<ReportStats, Error> => {
  return useQuery({
    queryKey: reportQueries.stats(),
    queryFn: fetchReportStats,
  })
}

const fetchReport = async (id: string): Promise<ReportDetail> => {
  const response = await apiClient.get<unknown>(API_ENDPOINTS.REPORTS.BY_ID(id))

  if (!isValidReportDetail(response.data)) {
    throw new Error('Invalid report detail response')
  }

  return response.data
}

export const useReport = (id: string): UseQueryResult<ReportDetail, Error> => {
  return useQuery({
    queryKey: reportQueries.byId(id),
    queryFn: () => fetchReport(id),
    enabled: !!id,
  })
}

const fetchProgramReports = async (
  programId: string,
  page: number,
  size: number
): Promise<ReportList> => {
  const response = await apiClient.get<unknown>(
    API_ENDPOINTS.REPORTS.BY_PROGRAM(programId),
    {
      params: { page, size },
    }
  )

  if (!isValidReportList(response.data)) {
    throw new Error('Invalid report list response')
  }

  return response.data
}

export const useProgramReports = (
  programId: string,
  page: number = 1,
  size: number = 20
): UseQueryResult<ReportList, Error> => {
  return useQuery({
    queryKey: reportQueries.byProgram(programId, page, size),
    queryFn: () => fetchProgramReports(programId, page, size),
    enabled: !!programId,
  })
}

const submitReport = async (data: ReportCreate): Promise<Report> => {
  const response = await apiClient.post<Report>(
    API_ENDPOINTS.REPORTS.SUBMIT,
    data
  )
  return response.data
}

export const useSubmitReport = (): UseMutationResult<
  Report,
  Error,
  ReportCreate
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: submitReport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: reportQueries.list(1, 20) })
      queryClient.invalidateQueries({ queryKey: reportQueries.inbox(1, 20) })
      queryClient.invalidateQueries({ queryKey: reportQueries.stats() })

      toast.success('Report submitted successfully')
    },
    onError: () => {
      toast.error('Failed to submit report')
    },
  })
}

const updateReport = async ({
  id,
  data,
}: {
  id: string
  data: ReportUpdate
}): Promise<Report> => {
  const response = await apiClient.patch<Report>(
    API_ENDPOINTS.REPORTS.BY_ID(id),
    data
  )
  return response.data
}

export const useUpdateReport = (): UseMutationResult<
  Report,
  Error,
  { id: string; data: ReportUpdate }
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: updateReport,
    onSuccess: (updatedReport) => {
      const queries = queryClient.getQueriesData<ReportDetail>({
        queryKey: reportQueries.all(),
      })

      for (const [key, data] of queries) {
        if (data && 'comments' in data && data.id === updatedReport.id) {
          queryClient.setQueryData<ReportDetail>(key, {
            ...data,
            ...updatedReport,
          })
        }
      }

      queryClient.invalidateQueries({ queryKey: reportQueries.list(1, 20) })
      queryClient.invalidateQueries({ queryKey: reportQueries.inbox(1, 20) })

      toast.success('Report updated successfully')
    },
    onError: () => {
      toast.error('Failed to update report')
    },
  })
}

const triageReport = async ({
  id,
  data,
}: {
  id: string
  data: ReportTriage
}): Promise<Report> => {
  const response = await apiClient.patch<Report>(
    API_ENDPOINTS.REPORTS.TRIAGE(id),
    data
  )
  return response.data
}

export const useTriageReport = (): UseMutationResult<
  Report,
  Error,
  { id: string; data: ReportTriage }
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: triageReport,
    onSuccess: (updatedReport) => {
      const queries = queryClient.getQueriesData<ReportDetail>({
        queryKey: reportQueries.all(),
      })

      for (const [key, data] of queries) {
        if (data && 'comments' in data && data.id === updatedReport.id) {
          queryClient.setQueryData<ReportDetail>(key, {
            ...data,
            ...updatedReport,
          })
        }
      }

      queryClient.invalidateQueries({ queryKey: reportQueries.list(1, 20) })
      queryClient.invalidateQueries({ queryKey: reportQueries.inbox(1, 20) })
      queryClient.invalidateQueries({ queryKey: reportQueries.stats() })

      toast.success('Report triaged successfully')
    },
    onError: () => {
      toast.error('Failed to triage report')
    },
  })
}

const addComment = async ({
  reportId,
  data,
}: {
  reportId: string
  data: CommentCreate
}): Promise<Comment> => {
  const response = await apiClient.post<Comment>(
    API_ENDPOINTS.REPORTS.COMMENTS(reportId),
    data
  )
  return response.data
}

export const useAddComment = (): UseMutationResult<
  Comment,
  Error,
  { reportId: string; data: CommentCreate }
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: addComment,
    onSuccess: (newComment, variables) => {
      queryClient.setQueryData<ReportDetail>(
        reportQueries.byId(variables.reportId),
        (old) => {
          if (!old || !('comments' in old)) return old
          return {
            ...old,
            comments: [...old.comments, newComment],
          }
        }
      )

      toast.success('Comment added successfully')
    },
    onError: () => {
      toast.error('Failed to add comment')
    },
  })
}
