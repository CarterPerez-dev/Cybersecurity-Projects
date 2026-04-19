// ===================
// ©AngelaMos | 2026
// mitre.types.ts
// ===================

import { z } from 'zod'

export const techniqueInfoSchema = z.object({
  id: z.string(),
  name: z.string(),
  tactic: z.string(),
})

export type TechniqueInfo = z.infer<typeof techniqueInfoSchema>

export const heatmapEntrySchema = z.object({
  technique_id: z.string(),
  name: z.string(),
  tactic: z.string(),
  count: z.number(),
})

export type HeatmapEntry = z.infer<typeof heatmapEntrySchema>

export const isValidTechniqueInfo = (data: unknown): data is TechniqueInfo => {
  return techniqueInfoSchema.safeParse(data).success
}

export const isValidHeatmapEntry = (data: unknown): data is HeatmapEntry => {
  return heatmapEntrySchema.safeParse(data).success
}
