// ===================
// © AngelaMos | 2026
// stats.types.ts
//
// Zod schemas and types for dashboard statistics
//
// Defines SeverityBreakdownSchema with high/medium/low
// integer counts, IPStatEntrySchema and PathStatEntrySchema
// for ranked lists with source_ip or path plus count, and
// StatsResponseSchema combining time_range,
// threats_stored, threats_detected, severity_breakdown,
// top_source_ips, and top_attacked_paths. All types are
// inferred from their schemas via z.infer. Connects to
// api/hooks/useStats, pages/dashboard
// ===================

import { z } from 'zod'

export const SeverityBreakdownSchema = z.object({
  high: z.number().int(),
  medium: z.number().int(),
  low: z.number().int(),
})

export const IPStatEntrySchema = z.object({
  source_ip: z.string(),
  count: z.number().int(),
})

export const PathStatEntrySchema = z.object({
  path: z.string(),
  count: z.number().int(),
})

export const StatsResponseSchema = z.object({
  time_range: z.string(),
  threats_stored: z.number().int(),
  threats_detected: z.number().int(),
  severity_breakdown: SeverityBreakdownSchema,
  top_source_ips: z.array(IPStatEntrySchema),
  top_attacked_paths: z.array(PathStatEntrySchema),
})

export type SeverityBreakdown = z.infer<typeof SeverityBreakdownSchema>
export type IPStatEntry = z.infer<typeof IPStatEntrySchema>
export type PathStatEntry = z.infer<typeof PathStatEntrySchema>
export type StatsResponse = z.infer<typeof StatsResponseSchema>
