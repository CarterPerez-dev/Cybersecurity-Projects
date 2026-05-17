// ===================
// ©AngelaMos | 2026
// event.ts
// ===================

import { z } from 'zod'
import { manageTokenViewSchema } from './token'

export const notifyStatusSchema = z.enum(['pending', 'sent', 'failed', 'deduped'])

export type NotifyStatus = z.infer<typeof notifyStatusSchema>

export const geoViewSchema = z.object({
  country: z.string().nullable(),
  region: z.string().nullable(),
  city: z.string().nullable(),
  asn: z.number().int().nullable(),
  asn_org: z.string().nullable(),
})

export type GeoView = z.infer<typeof geoViewSchema>

export const eventResponseSchema = z.object({
  id: z.number().int().nonnegative(),
  triggered_at: z.iso.datetime(),
  source_ip: z.string(),
  user_agent: z.string().nullable(),
  referer: z.string().nullable(),
  geo: geoViewSchema,
  extra: z.unknown(),
  notify_status: notifyStatusSchema,
  notified_at: z.iso.datetime().nullable(),
})

export type EventResponse = z.infer<typeof eventResponseSchema>

export const managePageSchema = z.object({
  next_cursor: z.string(),
  has_more: z.boolean(),
})

export type ManagePage = z.infer<typeof managePageSchema>

export const manageResponseSchema = z.object({
  token: manageTokenViewSchema,
  events: z.array(eventResponseSchema),
  events_total: z.number().int().nonnegative(),
  events_silenced_active: z.number().int().nonnegative(),
  page: managePageSchema,
})

export type ManageResponse = z.infer<typeof manageResponseSchema>
