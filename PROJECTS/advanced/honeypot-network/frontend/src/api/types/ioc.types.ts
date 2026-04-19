// ===================
// ©AngelaMos | 2026
// ioc.types.ts
// ===================

import { z } from 'zod'

export const iocSchema = z.object({
  id: z.number(),
  type: z.string(),
  value: z.string(),
  first_seen: z.string(),
  last_seen: z.string(),
  sight_count: z.number(),
  confidence: z.number(),
  source: z.string(),
  tags: z.array(z.string()).optional(),
})

export type IOC = z.infer<typeof iocSchema>

export const isValidIOC = (data: unknown): data is IOC => {
  return iocSchema.safeParse(data).success
}
