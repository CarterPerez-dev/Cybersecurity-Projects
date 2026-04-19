// ===================
// ©AngelaMos | 2026
// attacker.types.ts
// ===================

import { z } from 'zod'
import { geoInfoSchema } from './common.types'

export const attackerSchema = z.object({
  id: z.number(),
  ip: z.string(),
  first_seen: z.string(),
  last_seen: z.string(),
  total_events: z.number(),
  total_sessions: z.number(),
  geo: geoInfoSchema,
  threat_score: z.number(),
  tool_family: z.string().optional(),
  tags: z.array(z.string()).optional(),
})

export type Attacker = z.infer<typeof attackerSchema>

export const isValidAttacker = (data: unknown): data is Attacker => {
  return attackerSchema.safeParse(data).success
}
