// ===================
// © AngelaMos | 2026
// threats.types.ts
// ===================

import { z } from 'zod'

export const GeoInfoSchema = z.object({
  country: z.string().nullable(),
  city: z.string().nullable(),
  lat: z.number().nullable(),
  lon: z.number().nullable(),
})

export const ThreatEventSchema = z.object({
  id: z.string().uuid(),
  created_at: z.string(),
  source_ip: z.string(),
  request_method: z.string(),
  request_path: z.string(),
  status_code: z.number().int(),
  response_size: z.number().int(),
  user_agent: z.string(),
  threat_score: z.number(),
  severity: z.literal(['HIGH', 'MEDIUM', 'LOW']),
  component_scores: z.record(z.string(), z.number()),
  geo: GeoInfoSchema,
  matched_rules: z.array(z.string()).nullable(),
  model_version: z.string().nullable(),
  reviewed: z.boolean(),
  review_label: z.string().nullable(),
})

export const ThreatListSchema = z.object({
  total: z.number().int(),
  limit: z.number().int(),
  offset: z.number().int(),
  items: z.array(ThreatEventSchema),
})

export type GeoInfo = z.infer<typeof GeoInfoSchema>
export type ThreatEvent = z.infer<typeof ThreatEventSchema>
export type ThreatList = z.infer<typeof ThreatListSchema>
