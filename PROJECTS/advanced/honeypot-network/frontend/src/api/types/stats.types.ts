// ===================
// ©AngelaMos | 2026
// stats.types.ts
// ===================

import { z } from 'zod'

export const overviewStatsSchema = z.object({
  total_events: z.number(),
  active_sessions: z.number(),
  events_by_service: z.record(z.string(), z.number()),
})

export type OverviewStats = z.infer<typeof overviewStatsSchema>

export const credentialEntrySchema = z.object({
  value: z.string(),
  count: z.number(),
})

export const credentialPairSchema = z.object({
  username: z.string(),
  password: z.string(),
  count: z.number(),
})

export const credentialStatsSchema = z.object({
  top_usernames: z.array(credentialEntrySchema),
  top_passwords: z.array(credentialEntrySchema),
  top_pairs: z.array(credentialPairSchema),
})

export type CredentialStats = z.infer<typeof credentialStatsSchema>

export const isValidOverviewStats = (data: unknown): data is OverviewStats => {
  return overviewStatsSchema.safeParse(data).success
}

export const isValidCredentialStats = (
  data: unknown
): data is CredentialStats => {
  return credentialStatsSchema.safeParse(data).success
}
