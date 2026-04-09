// ===================
// © AngelaMos | 2026
// models.types.ts
//
// Zod schemas and types for ML model status and retraining
//
// Defines ActiveModelSchema with model_type, version,
// training_samples, a flexible metrics record, and nullable
// threshold. ModelStatusSchema wraps models_loaded flag,
// detection_mode string, and an array of ActiveModel
// entries. RetrainResponseSchema captures the status and
// job_id returned when a retrain is triggered. All types
// are inferred from their schemas via z.infer. Connects to
// api/hooks/useModels, pages/models
// ===================

import { z } from 'zod'

export const ActiveModelSchema = z.object({
  model_type: z.string(),
  version: z.string(),
  training_samples: z.number().int(),
  metrics: z.record(z.string(), z.unknown()),
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
