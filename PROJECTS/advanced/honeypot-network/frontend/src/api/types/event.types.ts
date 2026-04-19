// ===================
// ©AngelaMos | 2026
// event.types.ts
// ===================

import { z } from 'zod'
import { geoInfoSchema, SERVICE_TYPE_VALUES } from './common.types'

export const honeypotEventSchema = z.object({
  id: z.string(),
  session_id: z.string(),
  sensor_id: z.string(),
  timestamp: z.string(),
  received_at: z.string(),
  service_type: z.enum(SERVICE_TYPE_VALUES),
  event_type: z.string(),
  source_ip: z.string(),
  source_port: z.number(),
  dest_port: z.number(),
  protocol: z.string(),
  schema_version: z.number(),
  geo: geoInfoSchema.optional(),
  tags: z.array(z.string()).optional(),
  service_data: z.record(z.string(), z.unknown()).optional(),
})

export type HoneypotEvent = z.infer<typeof honeypotEventSchema>

export const isValidHoneypotEvent = (data: unknown): data is HoneypotEvent => {
  return honeypotEventSchema.safeParse(data).success
}
