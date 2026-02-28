// ===================
// © AngelaMos | 2026
// websocket.types.ts
// ===================

import { z } from 'zod'

export const WebSocketAlertSchema = z.object({
  event: z.literal('threat'),
  timestamp: z.string(),
  source_ip: z.string(),
  request_path: z.string(),
  threat_score: z.number(),
  severity: z.string(),
  component_scores: z.record(z.string(), z.number()),
})

export type WebSocketAlert = z.infer<typeof WebSocketAlertSchema>
