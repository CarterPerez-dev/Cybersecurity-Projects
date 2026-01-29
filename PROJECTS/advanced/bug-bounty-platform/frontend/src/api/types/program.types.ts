// ===================
// AngelaMos | 2025
// program.types.ts
// ===================

import { z } from 'zod'

export const ProgramStatus = {
  DRAFT: 'draft',
  ACTIVE: 'active',
  PAUSED: 'paused',
  CLOSED: 'closed',
} as const

export type ProgramStatus = (typeof ProgramStatus)[keyof typeof ProgramStatus]

export const ProgramVisibility = {
  PUBLIC: 'public',
  PRIVATE: 'private',
  INVITE_ONLY: 'invite_only',
} as const

export type ProgramVisibility =
  (typeof ProgramVisibility)[keyof typeof ProgramVisibility]

export const AssetType = {
  DOMAIN: 'domain',
  API: 'api',
  MOBILE_APP: 'mobile_app',
  SOURCE_CODE: 'source_code',
  HARDWARE: 'hardware',
  OTHER: 'other',
} as const

export type AssetType = (typeof AssetType)[keyof typeof AssetType]

export const Severity = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFORMATIONAL: 'informational',
} as const

export type Severity = (typeof Severity)[keyof typeof Severity]

export const rewardTierSchema = z.object({
  id: z.string().uuid(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime().nullable(),
  program_id: z.string().uuid(),
  severity: z.nativeEnum(Severity),
  min_bounty: z.number(),
  max_bounty: z.number(),
  currency: z.string(),
})

export const assetSchema = z.object({
  id: z.string().uuid(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime().nullable(),
  program_id: z.string().uuid(),
  asset_type: z.nativeEnum(AssetType),
  identifier: z.string(),
  in_scope: z.boolean(),
  description: z.string().nullable(),
})

export const programSchema = z.object({
  id: z.string().uuid(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime().nullable(),
  company_id: z.string().uuid(),
  name: z.string(),
  slug: z.string(),
  description: z.string().nullable(),
  rules: z.string().nullable(),
  response_sla_hours: z.number(),
  status: z.nativeEnum(ProgramStatus),
  visibility: z.nativeEnum(ProgramVisibility),
})

export const programDetailSchema = programSchema.extend({
  assets: z.array(assetSchema),
  reward_tiers: z.array(rewardTierSchema),
})

export const programListSchema = z.object({
  items: z.array(programSchema),
  total: z.number(),
  page: z.number(),
  size: z.number(),
})

export const programCreateSchema = z.object({
  name: z.string().min(1).max(255),
  slug: z
    .string()
    .min(1)
    .max(100)
    .regex(/^[a-z0-9-]+$/),
  description: z.string().max(10000).optional(),
  rules: z.string().max(50000).optional(),
  response_sla_hours: z.number().min(1).max(720).default(72),
  visibility: z.nativeEnum(ProgramVisibility).default(ProgramVisibility.PUBLIC),
})

export const programUpdateSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  description: z.string().max(10000).optional(),
  rules: z.string().max(50000).optional(),
  response_sla_hours: z.number().min(1).max(720).optional(),
  status: z.nativeEnum(ProgramStatus).optional(),
  visibility: z.nativeEnum(ProgramVisibility).optional(),
})

export const assetCreateSchema = z.object({
  asset_type: z.nativeEnum(AssetType).default(AssetType.DOMAIN),
  identifier: z.string().min(1).max(500),
  in_scope: z.boolean().default(true),
  description: z.string().max(2000).optional(),
})

export const rewardTierCreateSchema = z.object({
  severity: z.nativeEnum(Severity),
  min_bounty: z.number().min(0).default(0),
  max_bounty: z.number().min(0).default(0),
  currency: z.string().max(3).default('USD'),
})

export type RewardTier = z.infer<typeof rewardTierSchema>
export type Asset = z.infer<typeof assetSchema>
export type Program = z.infer<typeof programSchema>
export type ProgramDetail = z.infer<typeof programDetailSchema>
export type ProgramList = z.infer<typeof programListSchema>
export type ProgramCreate = z.infer<typeof programCreateSchema>
export type ProgramUpdate = z.infer<typeof programUpdateSchema>
export type AssetCreate = z.infer<typeof assetCreateSchema>
export type RewardTierCreate = z.infer<typeof rewardTierCreateSchema>

export const isValidProgram = (data: unknown): data is Program => {
  return programSchema.safeParse(data).success
}

export const isValidProgramDetail = (data: unknown): data is ProgramDetail => {
  return programDetailSchema.safeParse(data).success
}

export const isValidProgramList = (data: unknown): data is ProgramList => {
  return programListSchema.safeParse(data).success
}

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Informational',
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#2563eb',
  informational: '#6b7280',
}

export const STATUS_LABELS: Record<ProgramStatus, string> = {
  draft: 'Draft',
  active: 'Active',
  paused: 'Paused',
  closed: 'Closed',
}

export const ASSET_TYPE_LABELS: Record<AssetType, string> = {
  domain: 'Domain',
  api: 'API',
  mobile_app: 'Mobile App',
  source_code: 'Source Code',
  hardware: 'Hardware',
  other: 'Other',
}
