// ===================
// AngelaMos | 2025
// report.types.ts
// ===================

import { z } from 'zod'
import { Severity } from './program.types'

export const ReportStatus = {
  NEW: 'new',
  TRIAGING: 'triaging',
  NEEDS_MORE_INFO: 'needs_more_info',
  ACCEPTED: 'accepted',
  DUPLICATE: 'duplicate',
  INFORMATIVE: 'informative',
  NOT_APPLICABLE: 'not_applicable',
  RESOLVED: 'resolved',
  DISCLOSED: 'disclosed',
} as const

export type ReportStatus = (typeof ReportStatus)[keyof typeof ReportStatus]

export const commentSchema = z.object({
  id: z.string().uuid(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime().nullable(),
  report_id: z.string().uuid(),
  author_id: z.string().uuid(),
  content: z.string(),
  is_internal: z.boolean(),
})

export const attachmentSchema = z.object({
  id: z.string().uuid(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime().nullable(),
  report_id: z.string().uuid(),
  comment_id: z.string().uuid().nullable(),
  filename: z.string(),
  mime_type: z.string(),
  size_bytes: z.number(),
})

export const reportSchema = z.object({
  id: z.string().uuid(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime().nullable(),
  program_id: z.string().uuid(),
  researcher_id: z.string().uuid(),
  title: z.string(),
  description: z.string(),
  steps_to_reproduce: z.string().nullable(),
  impact: z.string().nullable(),
  severity_submitted: z.nativeEnum(Severity),
  severity_final: z.nativeEnum(Severity).nullable(),
  status: z.nativeEnum(ReportStatus),
  cvss_score: z.number().nullable(),
  cwe_id: z.string().nullable(),
  bounty_amount: z.number().nullable(),
  duplicate_of_id: z.string().uuid().nullable(),
  triaged_at: z.string().datetime().nullable(),
  resolved_at: z.string().datetime().nullable(),
  disclosed_at: z.string().datetime().nullable(),
})

export const reportDetailSchema = reportSchema.extend({
  comments: z.array(commentSchema),
  attachments: z.array(attachmentSchema),
})

export const reportListSchema = z.object({
  items: z.array(reportSchema),
  total: z.number(),
  page: z.number(),
  size: z.number(),
})

export const reportStatsSchema = z.object({
  total_reports: z.number(),
  accepted_reports: z.number(),
  total_earned: z.number(),
  reputation_score: z.number(),
})

export const reportCreateSchema = z.object({
  program_id: z.string().uuid(),
  title: z.string().min(1).max(500),
  description: z.string().min(1),
  steps_to_reproduce: z.string().optional(),
  impact: z.string().optional(),
  severity_submitted: z.nativeEnum(Severity).default(Severity.MEDIUM),
})

export const reportUpdateSchema = z.object({
  title: z.string().min(1).max(500).optional(),
  description: z.string().min(1).optional(),
  steps_to_reproduce: z.string().optional(),
  impact: z.string().optional(),
  severity_submitted: z.nativeEnum(Severity).optional(),
})

export const reportTriageSchema = z.object({
  status: z.nativeEnum(ReportStatus).optional(),
  severity_final: z.nativeEnum(Severity).optional(),
  cvss_score: z.number().min(0).max(10).optional(),
  cwe_id: z.string().max(20).optional(),
  bounty_amount: z.number().min(0).optional(),
  duplicate_of_id: z.string().uuid().optional(),
})

export const commentCreateSchema = z.object({
  content: z.string().min(1),
  is_internal: z.boolean().default(false),
})

export type Comment = z.infer<typeof commentSchema>
export type Attachment = z.infer<typeof attachmentSchema>
export type Report = z.infer<typeof reportSchema>
export type ReportDetail = z.infer<typeof reportDetailSchema>
export type ReportList = z.infer<typeof reportListSchema>
export type ReportStats = z.infer<typeof reportStatsSchema>
export type ReportCreate = z.infer<typeof reportCreateSchema>
export type ReportUpdate = z.infer<typeof reportUpdateSchema>
export type ReportTriage = z.infer<typeof reportTriageSchema>
export type CommentCreate = z.infer<typeof commentCreateSchema>

export const isValidReport = (data: unknown): data is Report => {
  return reportSchema.safeParse(data).success
}

export const isValidReportDetail = (data: unknown): data is ReportDetail => {
  return reportDetailSchema.safeParse(data).success
}

export const isValidReportList = (data: unknown): data is ReportList => {
  return reportListSchema.safeParse(data).success
}

export const isValidReportStats = (data: unknown): data is ReportStats => {
  return reportStatsSchema.safeParse(data).success
}

export const REPORT_STATUS_LABELS: Record<ReportStatus, string> = {
  new: 'New',
  triaging: 'Triaging',
  needs_more_info: 'Needs More Info',
  accepted: 'Accepted',
  duplicate: 'Duplicate',
  informative: 'Informative',
  not_applicable: 'N/A',
  resolved: 'Resolved',
  disclosed: 'Disclosed',
}

export const REPORT_STATUS_COLORS: Record<ReportStatus, string> = {
  new: '#3b82f6',
  triaging: '#f59e0b',
  needs_more_info: '#8b5cf6',
  accepted: '#22c55e',
  duplicate: '#6b7280',
  informative: '#06b6d4',
  not_applicable: '#6b7280',
  resolved: '#22c55e',
  disclosed: '#10b981',
}

export const isOpenStatus = (status: ReportStatus): boolean => {
  return ([
    ReportStatus.NEW,
    ReportStatus.TRIAGING,
    ReportStatus.NEEDS_MORE_INFO,
  ] as ReportStatus[]).includes(status)
}

export const isClosedStatus = (status: ReportStatus): boolean => {
  return !isOpenStatus(status)
}
