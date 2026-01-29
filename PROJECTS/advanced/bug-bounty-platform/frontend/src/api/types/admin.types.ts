// ===================
// AngelaMos | 2026
// admin.types.ts
// ===================

import { z } from 'zod'
import { UserRole } from './auth.types'
import { ProgramStatus, ProgramVisibility, Severity } from './program.types'
import { ReportStatus } from './report.types'

export const adminProgramResponseSchema = z.object({
  id: z.string().uuid(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime().nullable(),
  company_id: z.string().uuid(),
  company_email: z.string(),
  company_name: z.string().nullable(),
  name: z.string(),
  slug: z.string(),
  description: z.string().nullable(),
  status: z.nativeEnum(ProgramStatus),
  visibility: z.nativeEnum(ProgramVisibility),
  response_sla_hours: z.number(),
  report_count: z.number(),
})

export const adminProgramListResponseSchema = z.object({
  items: z.array(adminProgramResponseSchema),
  total: z.number(),
  page: z.number(),
  size: z.number(),
})

export const adminProgramUpdateSchema = z.object({
  name: z.string().optional(),
  status: z.nativeEnum(ProgramStatus).optional(),
  visibility: z.nativeEnum(ProgramVisibility).optional(),
  is_featured: z.boolean().optional(),
})

export const adminReportResponseSchema = z.object({
  id: z.string().uuid(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime().nullable(),
  program_id: z.string().uuid(),
  program_name: z.string(),
  program_slug: z.string(),
  researcher_id: z.string().uuid(),
  researcher_email: z.string(),
  researcher_name: z.string().nullable(),
  title: z.string(),
  severity_submitted: z.nativeEnum(Severity),
  severity_final: z.nativeEnum(Severity).nullable(),
  status: z.nativeEnum(ReportStatus),
  bounty_amount: z.number().nullable(),
  triaged_at: z.string().datetime().nullable(),
  resolved_at: z.string().datetime().nullable(),
})

export const adminReportListResponseSchema = z.object({
  items: z.array(adminReportResponseSchema),
  total: z.number(),
  page: z.number(),
  size: z.number(),
})

export const adminReportUpdateSchema = z.object({
  status: z.nativeEnum(ReportStatus).optional(),
  severity_final: z.nativeEnum(Severity).optional(),
  cvss_score: z.number().min(0).max(10).optional(),
  bounty_amount: z.number().min(0).optional(),
  admin_notes: z.string().optional(),
})

export const platformStatsResponseSchema = z.object({
  total_users: z.number(),
  total_researchers: z.number(),
  total_companies: z.number(),
  total_programs: z.number(),
  active_programs: z.number(),
  total_reports: z.number(),
  reports_by_status: z.record(z.string(), z.number()),
  total_bounties_paid: z.number(),
  reports_this_month: z.number(),
  new_users_this_month: z.number(),
})

export const adminUserResponseSchema = z.object({
  id: z.string().uuid(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime().nullable(),
  email: z.string(),
  full_name: z.string().nullable(),
  company_name: z.string().nullable(),
  is_active: z.boolean(),
  is_verified: z.boolean(),
  role: z.nativeEnum(UserRole),
  reputation_score: z.number(),
  program_count: z.number(),
  report_count: z.number(),
})

export const adminUserListResponseSchema = z.object({
  items: z.array(adminUserResponseSchema),
  total: z.number(),
  page: z.number(),
  size: z.number(),
})

export type AdminProgramResponse = z.infer<typeof adminProgramResponseSchema>
export type AdminProgramListResponse = z.infer<
  typeof adminProgramListResponseSchema
>
export type AdminProgramUpdate = z.infer<typeof adminProgramUpdateSchema>
export type AdminReportResponse = z.infer<typeof adminReportResponseSchema>
export type AdminReportListResponse = z.infer<
  typeof adminReportListResponseSchema
>
export type AdminReportUpdate = z.infer<typeof adminReportUpdateSchema>
export type PlatformStatsResponse = z.infer<typeof platformStatsResponseSchema>
export type AdminUserResponse = z.infer<typeof adminUserResponseSchema>
export type AdminUserListResponse = z.infer<typeof adminUserListResponseSchema>

export const isValidAdminProgramListResponse = (
  data: unknown
): data is AdminProgramListResponse => {
  return adminProgramListResponseSchema.safeParse(data).success
}

export const isValidAdminReportListResponse = (
  data: unknown
): data is AdminReportListResponse => {
  return adminReportListResponseSchema.safeParse(data).success
}

export const isValidPlatformStatsResponse = (
  data: unknown
): data is PlatformStatsResponse => {
  return platformStatsResponseSchema.safeParse(data).success
}

export const isValidAdminUserListResponse = (
  data: unknown
): data is AdminUserListResponse => {
  return adminUserListResponseSchema.safeParse(data).success
}

export const isValidAdminProgramResponse = (
  data: unknown
): data is AdminProgramResponse => {
  return adminProgramResponseSchema.safeParse(data).success
}

export const isValidAdminReportResponse = (
  data: unknown
): data is AdminReportResponse => {
  return adminReportResponseSchema.safeParse(data).success
}

export class AdminResponseError extends Error {
  readonly endpoint?: string

  constructor(message: string, endpoint?: string) {
    super(message)
    this.name = 'AdminResponseError'
    this.endpoint = endpoint
    Object.setPrototypeOf(this, AdminResponseError.prototype)
  }
}

export const ADMIN_ERROR_MESSAGES = {
  INVALID_PROGRAM_LIST_RESPONSE: 'Invalid admin program list from server',
  INVALID_PROGRAM_RESPONSE: 'Invalid admin program data from server',
  INVALID_REPORT_LIST_RESPONSE: 'Invalid admin report list from server',
  INVALID_REPORT_RESPONSE: 'Invalid admin report data from server',
  INVALID_STATS_RESPONSE: 'Invalid platform stats from server',
  INVALID_USER_LIST_RESPONSE: 'Invalid admin user list from server',
  FAILED_TO_UPDATE_PROGRAM: 'Failed to update program',
  FAILED_TO_DELETE_PROGRAM: 'Failed to delete program',
  FAILED_TO_UPDATE_REPORT: 'Failed to update report',
} as const

export const ADMIN_SUCCESS_MESSAGES = {
  PROGRAM_UPDATED: 'Program updated successfully',
  PROGRAM_DELETED: 'Program deleted successfully',
  REPORT_UPDATED: 'Report updated successfully',
} as const
