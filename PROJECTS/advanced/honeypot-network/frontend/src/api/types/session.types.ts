// ===================
// ©AngelaMos | 2026
// session.types.ts
// ===================

import { z } from 'zod'
import { SERVICE_TYPE_VALUES } from './common.types'

export const sessionSchema = z.object({
  id: z.string(),
  sensor_id: z.string(),
  started_at: z.string(),
  ended_at: z.string().optional(),
  service_type: z.enum(SERVICE_TYPE_VALUES),
  source_ip: z.string(),
  source_port: z.number(),
  dest_port: z.number(),
  client_version: z.string().optional(),
  login_success: z.boolean(),
  username: z.string().optional(),
  command_count: z.number(),
  mitre_techniques: z.array(z.string()).optional(),
  threat_score: z.number(),
  tags: z.array(z.string()).optional(),
})

export type Session = z.infer<typeof sessionSchema>

export const isValidSession = (data: unknown): data is Session => {
  return sessionSchema.safeParse(data).success
}
