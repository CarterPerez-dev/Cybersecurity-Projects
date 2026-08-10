// ===================
// © AngelaMos | 2026
// index.ts
// ===================

import { z } from 'zod'

export const findingSchema = z.object({
  layer: z.string(),
  rule: z.string(),
  severity: z.string(),
  invariant: z.boolean(),
})

export const levelSchema = z.object({
  number: z.number(),
  title: z.string(),
  teaches: z.string(),
  active_layers: z.array(z.string()),
})

export const levelsResponseSchema = z.object({
  levels: z.array(levelSchema),
})

export const sessionResponseSchema = z.object({
  session_id: z.string(),
  secret_length: z.number(),
})

export const attemptResponseSchema = z.object({
  level: levelSchema,
  request_decision: z.string(),
  egress_decision: z.string().nullable(),
  agent_text: z.string(),
  secret_escaped: z.boolean(),
  findings: z.array(findingSchema),
  attempts: z.number(),
})

export type Finding = z.infer<typeof findingSchema>
export type Level = z.infer<typeof levelSchema>
export type LevelsResponse = z.infer<typeof levelsResponseSchema>
export type SessionResponse = z.infer<typeof sessionResponseSchema>
export type AttemptResponse = z.infer<typeof attemptResponseSchema>

export interface AttemptRequest {
  session_id: string
  level: number
  ticket: string
}
