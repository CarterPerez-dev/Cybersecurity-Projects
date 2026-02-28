// ===================
// © AngelaMos | 2026
// models.types.ts
// ===================

import { z } from 'zod'

export const ActiveModelSchema = z.object({
  model_type: z.string(),
  version: z.string(),
  training_samples: z.number().int(),
  metrics: z.record(z.string(), z.number()),
  threshold: z.number().nullable(),
})

export const ModelStatusSchema = z.object({
  models_loaded: z.boolean(),
  detection_mode: z.string(),
  active_models: z.array(ActiveModelSchema),
})

export const RetrainResponseSchema = z.object({
  status: z.string(),
  job_id: z.string(),
})

export type ActiveModel = z.infer<typeof ActiveModelSchema>
export type ModelStatus = z.infer<typeof ModelStatusSchema>
export type RetrainResponse = z.infer<typeof RetrainResponseSchema>
