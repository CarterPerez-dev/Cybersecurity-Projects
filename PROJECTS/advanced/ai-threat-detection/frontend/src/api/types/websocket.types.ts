// ===================
// © AngelaMos | 2026
// websocket.types.ts
//
// Zod schema and type for real-time WebSocket alert frames
//
// Defines WebSocketAlertSchema validating incoming JSON
// frames from the alert WebSocket: optional id (stamped
// client-side), literal 'threat' event discriminator,
// timestamp, source_ip, request_method (defaults to GET),
// request_path, threat_score, severity string, and
// per-model component_scores record. The WebSocketAlert
// type is inferred via z.infer. Connects to
// api/hooks/useAlerts, components/alert-feed
// ===================

import { z } from 'zod'

export const WebSocketAlertSchema = z.object({
  id: z.string().optional(),
  event: z.literal('threat'),
  timestamp: z.string(),
  source_ip: z.string(),
  request_method: z.string().default('GET'),
  request_path: z.string(),
  threat_score: z.number(),
  severity: z.string(),
  component_scores: z.record(z.string(), z.number()),
})

export type WebSocketAlert = z.infer<typeof WebSocketAlertSchema>
